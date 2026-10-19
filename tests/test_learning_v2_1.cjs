'use strict';
const assert=require('node:assert/strict');
const {Simulator,STAGES}=require('../server/simulator.cjs');
const {makeReport,actionLesson}=require('../server/learning.cjs');
for(const id of STAGES){
 const sim=new Simulator(512038);sim.start(id);
 const before=sim.snapshot();assert.equal(before.flags.length,2,id+' flags');
 assert.ok(before.hypotheses.every(q=>q.hint&&q.hint.length>30),id+' conclusion hints');
 assert.ok(before.actions.find(a=>a.id==='verify').locked,id+' verification initially locked');
 assert.throws(()=>sim.apply({type:'action',id:'verify'}),/both CTF flags/);
 console.log('Closure gate + hints:',id);
}
let sim=new Simulator(8790);sim.start('midnight');const x=sim.apply({type:'action',id:'panic'});
const lesson=actionLesson(x.result,sim.bridge.scene());assert.equal(lesson.kind,'error');assert.match(lesson.why,/unsafe/);assert.ok(lesson.better.length>80);
console.log('Unsafe action best-practice coaching:',lesson.title);
sim=new Simulator(7099);sim.start('lantern');sim.bridge.spend(105,'Delayed investigation','No effective controls');
const report=makeReport(sim);assert.ok(report.attacker.occurred.length>=2);assert.ok(sim.state().exposure>=50);
assert.ok(report.needsImprovement.some(x=>x.title==='Attacker milestones'));
console.log('Time-triggered escalation:',report.attacker.occurred.length,'events,',sim.state().exposure+'% exposure');
console.log('Education engine tests passed.');
