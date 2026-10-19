'use strict';
// Server-authoritative adapter around the original Incident Guild v5 game engine.
// The original rule code runs on the server. The browser never sends state or scores.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto=require('node:crypto');
const SCRIPTS=['data','telemetry','forensics','engine'].map(n=>{
  let source=fs.readFileSync(path.join(__dirname,'core',`${n}.js`),'utf8');
  if(n==='engine')source=source.replace('window.Guild=Guild;', `window.__ctf={state:()=>state,judge:()=>state?judge():null,scene:()=>state?scenario(state.scenarioId):null,locked:(a)=>locked(a),done:(a)=>actionDone(a),consoleAction:(a)=>isConsoleAction(a),odds:(a,role)=>checkOdds(a,role),crew:()=>CREW,notice:()=>consoleNotice,modal:()=>modal, questions:()=>state?INVESTIGATION_DATA[state.scenarioId].questions:[],spend:(time,title,desc)=>spendInvestigationTime(time,title,desc),flags:()=>state?INVESTIGATION_DATA[state.scenarioId].ctfFlags:[],records:()=>state?INVESTIGATION_DATA[state.scenarioId].rows:[],guide:()=>state?INVESTIGATION_DATA[state.scenarioId].guide:null};window.Guild=Guild;`);
  return {name:n+'.js',script:new vm.Script(source,{filename:n+'.js'})};
});
const CONCLUSION_HINTS={"midnight": {"origin": "Look for the source workstation/IP in authentication records; separate the expected administration host from the observed source.", "movement": "Can you correlate east–west session destinations with command/process execution on the suspected source?", "exposure": "Check the session content from the configured TLS inspection point and corroborate the transferred archive against endpoint staging."}, "lantern": {"identity": "Compare credential validity with authorized hosts, timing and service-owner expectations.", "origin": "Match the token theft hypothesis against build-agent secret access and process ancestry.", "loss": "Distinguish successful API responses, distinct objects, and the HTTP export/receipt evidence."}, "valve": {"authorization": "Correlate the VPN/jump sequence with authorized maintenance records and operator confirmation.", "boundary": "Trace the network path across IT, jump host and supervisory zone and compare to normal baselines.", "safety": "Separate what a decoded packet shows from what control-room or controller validation proves."}, "webshell": {"path": "Compare HTTP request parameters and responses to a matching process tree.", "source": "Compare unexpected files in the web root with corresponding access logs.", "loss": "Tie the archive creation to the reconstructed upload request and response receipt."}};
const STAGES=['midnight','lantern','valve','webshell'];
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
  start(id){if(!STAGES.includes(id))throw Error('Unknown scenario');this.ctx.Math.random=makeRng(this.seeds[id]);this.api.start(id,true);this.applyTournamentVariants(id);}
  applyTournamentVariants(id){
    // Derive the evidence-bearing values from a per-tournament secret seed.
    // Public repository source alone cannot disclose the live answers.
    const flags=this.bridge.flags(),scene=this.bridge.scene(),rows=this.bridge.records();
    const variant=(name)=>parseInt(crypto.createHash('sha256').update(`${this.seeds[id]}|${id}|${name}`).digest('hex').slice(0,8),16)%900000+100000;
    const changes={midnight:{archive:`finance-${variant('archive')}.7z`},lantern:{token:`tok-${variant('token')}`,batch:`customers-${variant('batch')}`},valve:{register:'0x'+(0x20+variant('register')%0x50).toString(16).padStart(4,'0')},webshell:{receipt:`rcpt-${variant('receipt')}`}}[id]||{};
    for(const f of flags){const next=changes[f.id];if(!next)continue;const old=f.answer;
      function replaceTree(root){if(!root||typeof root!=='object')return;for(const key of Object.keys(root)){const val=root[key];if(typeof val==='string'){
        if(key==='hex'){
          const b=Buffer.from(val.replace(/\s/g,''),'hex'),before=Buffer.from(old,'utf8'),after=Buffer.from(next,'utf8');const i=b.indexOf(before);
          if(i>=0){const changed=Buffer.concat([b.subarray(0,i),after,b.subarray(i+before.length)]);root[key]=changed.toString('hex').toUpperCase().match(/.{2}/g).join(' ');}
        }else root[key]=val.replaceAll(old,next);
      }else if(val&&typeof val==='object')replaceTree(val);}}
      // Only the current scenario's corresponding evidence-bearing records are transformed.
      for(const row of rows)replaceTree(row);
      for(const ev of Object.values(scene.evidence))replaceTree(ev);
      f.answer=next;
      if(id==='valve'&&f.id==='register'){
       const rec=rows.find(row=>row.id==='v09');
       const reg=Number.parseInt(next.slice(2),16);
       for(const frame of rec.packet.frames){let data=Buffer.from(frame.hex.replace(/\s/g,''),'hex');if(data.length>=12){data.writeUInt16BE(reg,8);frame.hex=data.toString('hex').toUpperCase().match(/.{2}/g).join(' ');}}
      }
    }
  }
  apply(cmd,legacyReplay=false){
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
      this.api.tab('hypotheses');this.api.hypothesis(cmd.id);const hypothesisAccepted=!!s.hypotheses?.[cmd.id]?.correct;result={conclusion:cmd.id,correct:hypothesisAccepted,coaching:hypothesisAccepted?q.reason:'This interpretation is not supported by the inspected evidence. Compare the source fields, timeline and alternative explanations before reassessing. No answer is revealed.'};
    }else if(cmd.type==='flag'){
      const f=this.bridge.flags().find(f=>f.id===cmd.id);
      if(!f)throw Error('Unknown CTF flag');
      if(s.ctfFlags?.[f.id])throw Error('Flag already accepted');
      if(typeof cmd.value!=='string'||cmd.value.length>140||!cmd.value.trim())throw Error('Enter a nonempty flag value');
      const inspected=this.bridge.records().find(r=>r.id===f.record);
      if(!inspected||!s.console.inspected.includes(f.record))throw Error('Inspect the relevant forensic record before submitting its flag');
      s.ctfFlags??={};s.ctfAttempts??={};s.ctfAttempts[f.id]=(s.ctfAttempts[f.id]||0)+1;
      const correct=cmd.value.trim().toLowerCase()===f.answer.trim().toLowerCase();
      this.bridge.spend(correct?1:3,correct?'CTF flag validated':'CTF incorrect flag',correct?'Forensic artifact correctly identified.':'Artifact not matched. Re-examine the source record.');
      if(correct)s.ctfFlags[f.id]=true;
      if(this.bridge.flags().every(flag=>s.ctfFlags[flag.id]))s.flags.ctfValidated=true;
      result={flag:f.id,correct,attempt:s.ctfAttempts[f.id]};
    }else if(cmd.type==='action'){
      if(cmd.id==='verify'&&!legacyReplay&&(!s.flags.ctfValidated||!s.flags.assessmentReady))throw Error('Verified closure requires both CTF flags and at least two evidence-supported conclusions. Open Casebook to finish these mandatory steps.');
      const a=this.bridge.scene().actions.find(a=>a.id===cmd.id);
      if(!a||this.bridge.locked(a)||this.bridge.done(a)||this.bridge.consoleAction(a))throw Error('This action is not available');
      // Competition has a fixed response proficiency: no specialists or support staff.
      this.api.preview(a.id);this.api.previewRole('analyst');
      this.fields.set('assistSelect',{...element('assistSelect'),value:''});
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
      crew:[],
      actions:sc.actions.map(a=>({id:a.id,title:a.title,desc:a.desc,cat:a.cat,source:a.source,tool:a.tool||null,time:a.time,dc:a.dc,skill:a.skill,done:this.bridge.done(a),locked:this.bridge.locked(a)||(a.id==='verify'&&(!s.flags.ctfValidated||!s.flags.assessmentReady)),consoleAction:this.bridge.consoleAction(a)})),
      evidence:s.evidence.map(id=>sc.evidence[id]).filter(Boolean).map(e=>({id:e.id,title:e.title,source:e.source,summary:e.summary,asset:e.asset,query:e.query,raw:e.raw})),
      console:{source:s.console.source,query:s.console.query,results:rows.filter(r=>resultIds.has(r.id)).map(r=>({id:r.id,source:r.source,time:r.time,host:r.host,fields:r.fields,detail:r.detail,packet:r.packet||null,endpoint:r.endpoint||null,log:r.log||null,reviewed:s.console.inspected.includes(r.id),hasExhibit:!!r.evidence})),searched:s.console.searched.slice(-12),notice:this.bridge.notice()},
      flags:this.bridge.flags().map(f=>({id:f.id,title:f.title,prompt:f.prompt,source:f.source,hint:f.hint,solved:!!s.ctfFlags?.[f.id],attempts:s.ctfAttempts?.[f.id]||0})),
      guide:{brief:guide?.brief||"",milestones:(guide?.milestones||[]).map(m=>({title:m.title,sources:m.sources,goal:m.goal,why:m.why,complete:m.evidence.every(id=>s.evidence.includes(id)),found:m.evidence.filter(id=>s.evidence.includes(id)).length,total:m.evidence.length})),pivotIdeas:guide?.ideas||{}},
      hypotheses:questions.map(q=>({id:q.id,question:q.question,options:q.options,hint:CONCLUSION_HINTS[s.scenarioId]?.[q.id]||"Compare the collected source records and timeline before choosing.",requirements:q.requires.map(id=>({title:s.evidence.includes(id)?sc.evidence[id]?.title:'Uncollected '+(sc.evidence[id]?.source||'')+' exhibit',found:s.evidence.includes(id)})),solved:!!s.hypotheses?.[q.id]?.correct,reason:s.hypotheses?.[q.id]?.correct?q.reason:null})),
      
      feed:s.feed?.slice(0,12)||[],chronicle:s.history?.slice(-35)||[],attackerProfile:null
    });
  }
}
module.exports={Simulator,STAGES};
