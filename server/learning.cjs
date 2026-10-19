'use strict';
// Educational analysis derived from the simulation's actual decisions and state.
// Never award extra leaderboard points outside of the V5 scoring engine.
const PLAYBOOK={
 midnight:{
  focus:'Contain the compromised service identity and its lateral access while preserving process and network evidence.',
  practice:'Correlate identity, east–west traffic, process ancestry and decrypted upload evidence; then eradicate and verify.',
  pitfalls:'Revoking access without confirming dependent jobs, deleting artifacts before preservation, or using a broad outage as containment.',
  timeline:'The adversary may expand remote administrative access, stage data and attempt encryption if lateral paths remain open.'},
 lantern:{
  focus:'Revoke the abused API token and independently block unauthorized outbound transfers.',
  practice:'Correlate API object access logs, token issuance and build-agent process ancestry before defining exposure.',
  pitfalls:'Assuming authenticated activity is authorized, treating all requests as confirmed leaked records, or shutting off the customer API without coordination.',
  timeline:'Uncontrolled valid tokens drive enumeration and subsequent outbound uploads, increasing confirmed exposure and incident cost.'},
 valve:{
  focus:'Stop unapproved IT-to-OT access with plant approval, keeping safety and production availability primary.',
  practice:'Correlate VPN/jump logs, passive protocol content, engineering process context and operator verification before safe restoration.',
  pitfalls:'Directly modifying controllers from the SOC, cutting industrial visibility without plant approval, or equating one write packet with proven physical effect.',
  timeline:'Missed containment can extend OT access and trigger operational impacts with severe score caps.'},
 webshell:{
  focus:'Block the malicious webshell request path and isolate the execution foothold without needlessly disabling the application.',
  practice:'Reconstruct cleartext HTTP POST parameters and server responses; match web-process child commands and outbound archive transfer.',
  pitfalls:'Removing the webshell before preserving process/HTTP traces, overlooking the web root or overreacting with a total web outage.',
  timeline:'The actor can run additional commands, collect customer data and transfer staged archives if the exposed path stays open.'}
};
const lessonForOrder=note=>`${note} Best practice: establish the relevant authorization, dependency assessment and/or forensic preservation before executing this control, unless an immediate safety or containment emergency justifies a documented exception.`;
function actionLesson(result,scene,actions){
 if(!result||!result.id)return null;
 const action=scene.actions.find(a=>a.id===result.id);
 const bad=(actions||[]).find(a=>a.id===result.id&&a.title===result.title);
 const errors=[];
 if(result.hazardous)errors.push({kind:'unsafe',title:'Unsafe response choice',why:`${action?.title||result.title} is a disproportionately disruptive or unsafe measure. A high D20 roll does not make an unsafe choice appropriate.`,better:`Prefer proportionate response: ${PLAYBOOK[scene.id].focus} Avoid these pitfalls: ${PLAYBOOK[scene.id].pitfalls}`});
 for(const note of result.orderNotes||[])errors.push({kind:'sequence',title:'Action sequencing problem',why:note,better:lessonForOrder(note)});
 if(!errors.length&&result.verdict==='fail')return {kind:'execution',title:'Execution check failed, not necessarily a bad decision',why:'The action was reasonable to attempt but its D20 execution check failed. A dice result is separate from the quality of a response decision.',better:'Review prerequisites, use corroborating evidence and retry where the response remains appropriate.'};
 if(!errors.length&&result.verdict==='partial')return {kind:'execution',title:'Partial technical result',why:'The attempted action progressed with a complication. This does not by itself mean the response decision was wrong.',better:'Validate whether the control worked, document side effects and continue with a scoped response.'};
 if(!errors.length)return {kind:'good',title:'Response decision recorded',why:action?.success||'The planned response step was executed.',better:'Verify impact, correlate evidence and continue the incident lifecycle.'};
 return {kind:'error',title:'Best-practice coaching',why:errors.map(e=>e.why).join(' '),better:errors.map(e=>e.better).join(' '),issues:errors};
}
function makeReport(sim){
 const s=sim.state(),snapshot=sim.snapshot(),judge=sim.score(),scene=sim.bridge.scene(),plan=PLAYBOOK[s.scenarioId];
 const events=s.impactEvents||[],seq=s.orderEvents||[],unsafe=s.severeDecisions||[],done=new Set(s.done||[]);
 const flags=(snapshot.flags||[]).filter(f=>f.solved).length;
 const solved=snapshot.hypotheses.filter(h=>h.solved).length;
 const good=[],needs=[],recommendations=[];
 function add(isGood,title,detail){(isGood?good:needs).push({title,detail});}
 add(!!s.flags.coordinated,'Incident coordination',s.flags.coordinated?'Stakeholders and response owners were engaged.':'Establish incident command, system ownership, and authorization before disruptive changes.');
 add(!!s.flags.preserved,'Evidence preservation',s.flags.preserved?'Forensic artifacts were preserved for investigation and recovery.':'Preserve volatile traces, packets and logs before cleanup whenever practical.');
 add(!!s.flags.identity,'Compromised identity',s.flags.identity?'Access associated with the compromised account or token was revoked.':'Revoke suspect access and verify sessions or issued tokens cannot be reused.');
 add(events.length===0,'Attacker milestones',events.length===0?'No damaging attacker milestone was allowed to complete in the scenario.':`${events.length} attacker milestone(s) caused impact before effective defenses: ${events.map(e=>e.title).join(', ')}.`);
 add(seq.length===0,'Response sequencing',seq.length===0?'No recorded avoidable action-ordering consequences.':`${seq.length} avoidable ordering consequence(s) were recorded.`);
 add(unsafe.length===0,'Safety and proportionality',unsafe.length===0?'No catastrophic or disproportionate decision was recorded.':unsafe.map(e=>`${e.title}: ${e.why}`).join(' '));
 add(flags===2,'Forensic flags',`${flags}/2 mandatory artifacts correctly identified.`);
 add(solved>=2,'Evidence-backed conclusions',`${solved}/3 conclusions were substantiated using supporting exhibits.`);
 add(s.ended&&s.endReason==='closed','Verified recovery',s.endReason==='closed'?'Verified technical closure was reached.':'The incident ended without a fully verified recovery and closure.');
 const ct=judge.containmentMinute,goal=judge.targets?.contain;
 add(ct!==null&&ct<=goal,'Containment timing',ct===null?'Critical containment controls were not all completed.':`Critical containment at T+${ct} minutes. Target T+${goal} minutes.`);
 if(events.length)recommendations.push('Identify the exact attacker milestone that caused damage and move the relevant controls earlier in the response sequence.');
 for(const issue of seq)needs.push({title:'Ordering mistake: '+issue.action,detail:lessonForOrder(issue.note)});
 for(const issue of unsafe)needs.push({title:'Unsafe action: '+issue.title,detail:issue.why+' Best practice: '+plan.pitfalls});
 if((s.hypothesisMistakes||0)>0)needs.push({title:'Unsupported conclusions',detail:`${s.hypothesisMistakes} unsupported assessment(s) were submitted. Re-check source evidence and avoid inferring more than it proves.`});
 if((s.hypothesisMistakes||0)>0)recommendations.push('Practice formulating conclusions that explicitly cite supporting Logs, Network, and Endpoint exhibits.');
 if(seq.length)recommendations.push('Practice response order: establish authority and dependencies, preserve high-value evidence, then perform scoped containment and eradication.');
 if(unsafe.length)recommendations.push('Replace broad or unsafe intervention with minimum-impact controls approved by the relevant operational owner.');
 if(!s.flags.preserved)recommendations.push('Preserve NetWitness log/packet records and endpoint process context before destructive remediation.');
 if(solved<2)recommendations.push('Complete at least two source-supported conclusions before declaring incident closure.');
 if(flags<2)recommendations.push('Find both mandatory forensic flags in the corresponding inspected source records.');
 recommendations.push(plan.practice);
 return {focus:plan.focus,overall:`${judge.assessment.toUpperCase()} — ${judge.score}/100. ${s.endReason==='closed'?'Verified closure reached.':'The case did not reach verified closure.'} Business health ${s.health}%, exposure risk ${s.exposure}%.`,bestPractice:plan.practice,whatWentWell:good,needsImprovement:needs,recommendations:[...new Set(recommendations)],attacker:{overview:plan.timeline,containedAt:ct,target:goal,occurred:events.map(e=>({minute:e.at,title:e.title,points:e.points,cap:e.cap})),avoided:(s.history||[]).filter(x=>x.type==='prevented').map(x=>({time:x.time,title:x.title})),notes:events.length?'The score reductions and maximum score caps caused by these milestones remain even after later containment.':'Timely response prevented the documented damaging milestones.'},decisionErrors:{unsafe:unsafe.map(x=>({time:x.time,title:x.title,why:x.why})),sequencing:seq.map(x=>({time:x.time,note:x.note})),incorrectConclusions:s.hypothesisMistakes||0},metrics:{flagsSolved:flags,flagsRequired:2,conclusionsSolved:solved,containmentMinute:ct,containmentTarget:goal,impactCount:events.length,unsafeCount:unsafe.length,sequenceCount:seq.length}};
}
module.exports={makeReport,actionLesson,PLAYBOOK};
