'use strict';
// Server-authoritative adapter around the original Incident Guild v5 game engine.
// The original rule code runs on the server. The browser never sends state or scores.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const SCRIPTS=['data','telemetry','forensics','engine'].map(n=>{
  let source=fs.readFileSync(path.join(__dirname,'core',`${n}.js`),'utf8');
  if(n==='engine')source=source.replace('window.Guild=Guild;', `window.__ctf={state:()=>state,judge:()=>state?judge():null,scene:()=>state?scenario(state.scenarioId):null,locked:(a)=>locked(a),done:(a)=>actionDone(a),consoleAction:(a)=>isConsoleAction(a),odds:(a,role)=>checkOdds(a,role),crew:()=>CREW,notice:()=>consoleNotice,modal:()=>modal, questions:()=>state?INVESTIGATION_DATA[state.scenarioId].questions:[],records:()=>state?INVESTIGATION_DATA[state.scenarioId].rows:[],guide:()=>state?INVESTIGATION_DATA[state.scenarioId].guide:null};window.Guild=Guild;`);
  return {name:n+'.js',script:new vm.Script(source,{filename:n+'.js'})};
});
const STAGES=['midnight','lantern','valve'];
const deepcopy=x=>JSON.parse(JSON.stringify(x));
function makeRng(seed){let s=seed>>>0;return ()=>{s=(Math.imul(s,1664525)+1013904223)>>>0;return s/4294967296;};}
function element(id){return {value:'',innerHTML:'',style:{},addEventListener(){},remove(){},click(){},querySelector(){return null},querySelectorAll(){return []}};}
class Simulator{
  constructor(seed){
    this.seeds=typeof seed==='object'?seed:Object.fromEntries(STAGES.map(id=>[id,seed]));
    const mem=new Map([['incident-guild-dice-mode-v2','standard'],['competition-fixed-dice-mode','standard']]);
    const localStorage={getItem(k){return mem.get(k)||null},setItem(k,v){mem.set(k,String(v))},removeItem(k){mem.delete(k)}};
    this.fields=new Map();
    const fields=this.fields;
    const body=element('body');body.appendChild=()=>{};
    const document={body,addEventListener(){},getElementById(id){if(!fields.has(id))fields.set(id,element(id));return fields.get(id);},createElement(){return element('created')},querySelector(){return null},querySelectorAll(){return []}};
    const math=Object.create(Math);math.random=makeRng(this.seeds.midnight);
    const window={scrollTo(){},addEventListener(){},localStorage};
    const context={window,document,localStorage,Math:math,Date,JSON,console:{log(){},warn(){},error(){}},setTimeout(){},clearTimeout(){},Blob:class {},URL:{createObjectURL(){return 'blob:dummy'},revokeObjectURL(){}},FileReader:class {}};
    this.ctx=vm.createContext(context);
    for(const item of SCRIPTS)item.script.runInContext(this.ctx,{timeout:1200});
    this.api=this.ctx.window.Guild;this.bridge=this.ctx.window.__ctf;
  }
  state(){return this.bridge.state();}
  score(){return this.bridge.judge();}
  stage(){return this.state()?.scenarioId;}
  start(id){if(!STAGES.includes(id))throw Error('Unknown scenario');this.ctx.Math.random=makeRng(this.seeds[id]);this.api.start(id,true);}
  apply(cmd){
    const s=this.state();if(!s)throw Error('No active scenario');
    if(s.ended)throw Error('This scenario has ended. Advance to the next round.');
    if(!cmd||typeof cmd!=='object'||typeof cmd.type!=='string')throw Error('Invalid command');
    let result=null;
    if(cmd.type==='query'){
      if(!['Logs','Network','Endpoint'].includes(cmd.source))throw Error('Unknown evidence source');
      if(typeof cmd.query!=='string'||cmd.query.length>180||!cmd.query.trim())throw Error('Supply a nonempty investigation query');
      this.api.tab('telemetry');this.api.telemetry(cmd.source);const oldTime=s.clock;this.api.query(cmd.query);if(s.clock===oldTime)throw Error('Invalid query or no time advanced');
    }else if(cmd.type==='collect'){
      if(typeof cmd.id!=='string'||!s.console?.results?.includes(cmd.id))throw Error('Inspect a matching search result first');
      this.api.collect(cmd.id);result={record:cmd.id,exhibit:!!this.bridge.scene().evidence[this.bridge.records().find(r=>r.id===cmd.id)?.evidence]};
    }else if(cmd.type==='hypothesis'){
      const q=this.bridge.questions().find(q=>q.id===cmd.id);
      if(!q||!Number.isInteger(cmd.choice)||cmd.choice<0||cmd.choice>=q.options.length)throw Error('Invalid conclusion');
      if(s.hypotheses?.[cmd.id]?.correct)throw Error('Already substantiated');
      if(q.requires.some(e=>!s.evidence.includes(e)))throw Error('Find the required evidence first');
      this.fields.set('hypothesis-'+cmd.id,{...element('hypothesis-'+cmd.id),value:String(cmd.choice)});
      this.api.tab('hypotheses');this.api.hypothesis(cmd.id);
    }else if(cmd.type==='action'){
      const a=this.bridge.scene().actions.find(a=>a.id===cmd.id);
      if(!a||this.bridge.locked(a)||this.bridge.done(a)||this.bridge.consoleAction(a))throw Error('This action is not available');
      if(typeof cmd.role!=='string'||!this.bridge.crew().some(r=>r.id===cmd.role))throw Error('Choose a valid specialist');
      if(cmd.assist!==undefined&&cmd.assist!==''&&(!this.bridge.crew().some(r=>r.id===cmd.assist)||cmd.assist===cmd.role))throw Error('Invalid assisting specialist');
      this.api.preview(a.id);this.api.previewRole(cmd.role);
      this.fields.set('assistSelect',{...element('assistSelect'),value:cmd.assist||''});
      const before=s.actionsTaken.length;
      this.api.roll(a.id);
      if(s.actionsTaken.length===before)throw Error('Could not resolve this order');
      result=deepcopy(s.actionsTaken.at(-1));
      this.api.closeModal();
    }else{throw Error('Command not permitted in competition mode');}
    return {result};
  }
  snapshot(){
    const s=this.state(),sc=this.bridge.scene(),grade=this.score(),c=this.bridge.crew(),rows=this.bridge.records(),questions=this.bridge.questions(),guide=this.bridge.guide();
    const resultIds=new Set(s.console?.results||[]);
    return deepcopy({
      round:{id:s.scenarioId,title:sc.title,brief:sc.brief,opening:sc.opening,difficulty:sc.difficulty,clock:s.clock,health:s.health,exposure:s.exposure,pressure:s.pressure,ended:s.ended,endReason:s.endReason,score:grade.score,assessment:grade.assessment,scoreBreakdown:grade.fields,objectives:sc.objectives.map(([title,fn])=>({title,done:!!fn(s)})),business:[]},
      crew:c.map(r=>({id:r.id,name:r.name,title:r.title,icon:r.icon,skills:r.skills,fatigue:Math.min(1,Math.floor((s.used?.[r.id]||0)/6)),busy:false})),
      actions:sc.actions.map(a=>({id:a.id,title:a.title,desc:a.desc,cat:a.cat,source:a.source,tool:a.tool||null,time:a.time,dc:a.dc,skill:a.skill,done:this.bridge.done(a),locked:this.bridge.locked(a),consoleAction:this.bridge.consoleAction(a)})),
      evidence:s.evidence.map(id=>sc.evidence[id]).filter(Boolean).map(e=>({id:e.id,title:e.title,source:e.source,summary:e.summary,asset:e.asset,query:e.query,raw:e.raw})),
      console:{source:s.console.source,query:s.console.query,results:rows.filter(r=>resultIds.has(r.id)).map(r=>({id:r.id,source:r.source,time:r.time,host:r.host,fields:r.fields,detail:r.detail,packet:r.packet||null,endpoint:r.endpoint||null,reviewed:s.console.inspected.includes(r.id),hasExhibit:!!r.evidence})),searched:s.console.searched.slice(-12),notice:this.bridge.notice()},
      guide:{brief:guide?.brief||"",milestones:(guide?.milestones||[]).map(m=>({title:m.title,sources:m.sources,goal:m.goal,why:m.why,complete:m.evidence.every(id=>s.evidence.includes(id)),found:m.evidence.filter(id=>s.evidence.includes(id)).length,total:m.evidence.length})),pivotIdeas:guide?.ideas||{}},
      hypotheses:questions.map(q=>({id:q.id,question:q.question,options:q.options,requirements:q.requires.map(id=>({title:s.evidence.includes(id)?sc.evidence[id]?.title:'Uncollected '+(sc.evidence[id]?.source||'')+' exhibit',found:s.evidence.includes(id)})),solved:!!s.hypotheses?.[q.id]?.correct,reason:s.hypotheses?.[q.id]?.correct?q.reason:null})),
      
      feed:s.feed?.slice(0,12)||[],chronicle:s.history?.slice(-35)||[],attackerProfile:null
    });
  }
}
module.exports={Simulator,STAGES};
