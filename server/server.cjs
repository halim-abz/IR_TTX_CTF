'use strict';
const http=require('node:http');const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const {Simulator,STAGES}=require('./simulator.cjs');
const PORT=Number(process.env.PORT||3000),HOST=process.env.HOST||'0.0.0.0';
const DATA_DIR=path.resolve(process.env.DATA_DIR||path.join(__dirname,'..','data'));
const DB_FILE=path.join(DATA_DIR,'competition.json');const PUBLIC=path.resolve(__dirname,'../public');
// A unique default administrator password is generated once per installation and
// stored in the persistent data volume. Never ship a public fixed password.
const ADMIN_PASSWORD_FILE=path.join(DATA_DIR,'admin-password.txt');
const GENERATED_ADMIN_PASSWORD=!process.env.ADMIN_PASSWORD;
let ADMIN_PASSWORD;
if(process.env.ADMIN_PASSWORD){ADMIN_PASSWORD=process.env.ADMIN_PASSWORD;}
else if(fs.existsSync(ADMIN_PASSWORD_FILE)){ADMIN_PASSWORD=fs.readFileSync(ADMIN_PASSWORD_FILE,'utf8').trim();}
else{
 fs.mkdirSync(DATA_DIR,{recursive:true,mode:0o700});
 ADMIN_PASSWORD=crypto.randomBytes(24).toString('base64url');
 fs.writeFileSync(ADMIN_PASSWORD_FILE,ADMIN_PASSWORD+'\n',{mode:0o600,flag:'wx'});
}
if(!ADMIN_PASSWORD||ADMIN_PASSWORD.length<12)throw Error('ADMIN_PASSWORD must contain at least 12 characters');
const COOKIE_SECURE=process.env.COOKIE_SECURE==='1';
const PROF='standard';

fs.mkdirSync(DATA_DIR,{recursive:true,mode:0o700});
function newDB(){return {epoch:crypto.randomUUID(),createdAt:new Date().toISOString(),seeds:Object.fromEntries(STAGES.map(id=>[id,crypto.randomInt(1,0x7fffffff)])),players:[]};}
let db;if(fs.existsSync(DB_FILE)){try{db=JSON.parse(fs.readFileSync(DB_FILE,'utf8'));if(!Array.isArray(db.players))throw Error('invalid player store');}catch(e){throw Error('Cannot parse competition database: '+e.message);}}else{db=newDB();persist();}
let instances=new Map(),clients=new Set(),lastAttempt=new Map(),resetFailures=new Map();
function persist(){const tmp=DB_FILE+'.tmp';fs.writeFileSync(tmp,JSON.stringify(db,null,2),{mode:0o600});fs.renameSync(tmp,DB_FILE);}
function keyForPlayer(p){return `${db.epoch}:${p.id}`;}
function reconstruct(player){let sim=instances.get(keyForPlayer(player));if(sim)return sim;
 sim=new Simulator(db.seeds); // deterministic, common tournament seed; reproducible playthrough after restart
 let current=-1;
 for(const item of player.events){
  if(item.type==='start'){current++;sim.start(item.scenario);}
  else sim.apply(item);
 }
 instances.set(keyForPlayer(player),sim);return sim;
}
function currentRound(p){return p.rounds.findIndex(r=>r.status==='active');}
function completedCount(p){return p.rounds.filter(r=>r.status==='complete').length;}
function total(p){return p.rounds.reduce((n,r)=>n+(r.status==='complete'?r.score:0),0);}
function leaderboard(){return db.players.map(p=>{const current=currentRound(p);const sim=current>=0?reconstruct(p):null;const provisional=sim&&sim.state()?.moves>0?sim.score().score:0;return {name:p.name,score:total(p)+provisional,finalizedTotal:total(p),provisional,completed:completedCount(p),rounds:p.rounds.map(r=>r.status==='complete'?r.score:null),current,finished:p.rounds.every(r=>r.status==='complete'),lastUpdate:p.updatedAt};}).sort((a,b)=>b.score-a.score||b.completed-a.completed||String(a.lastUpdate||'').localeCompare(String(b.lastUpdate||''))||a.name.localeCompare(b.name)).map((p,i)=>({rank:i+1,...p}));}
function board(){return {epoch:db.epoch,players:db.players.length,updatedAt:new Date().toISOString(),leaderboard:leaderboard(),stages:STAGES};}
function broadcast(type,payload){const text=`event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`;for(const c of clients){try{c.write(text);}catch(e){clients.delete(c);}}}
function getCookies(req){const c=Object.fromEntries((req.headers.cookie||'').split(';').map(s=>s.trim()).filter(Boolean).map(s=>{let i=s.indexOf('=');return [s.slice(0,i),s.slice(i+1)];}));return c;}
function playerFromReq(req){const cookie=getCookies(req).ig_ctf;if(!cookie||!cookie.includes('.'))return null;const [id,token]=cookie.split('.',2);if(!/^[a-f0-9-]{36}$/.test(id)||!token||token.length>150)return null;const p=db.players.find(x=>x.id===id);if(!p)return null;const hash=crypto.createHash('sha256').update(token).digest('hex');const a=Buffer.from(hash,'hex'),b=Buffer.from(p.tokenHash,'hex');return a.length===b.length&&crypto.timingSafeEqual(a,b)?p:null;}
function headerNoCache(res){res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");}
function json(res,status,data){headerNoCache(res);res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(data));}
function fail(res,status,message){return json(res,status,{error:message});}
async function parseBody(req){return new Promise((resolve,reject)=>{let total=0,data='';req.on('data',chunk=>{total+=chunk.length;if(total>8192){reject(Object.assign(Error('Body too large'),{status:413}));req.destroy();}else data+=chunk;});req.on('end',()=>{try{resolve(JSON.parse(data||'{}'));}catch(e){reject(Object.assign(Error('Invalid JSON'),{status:400}));}});req.on('error',reject);});}
function validOrigin(req){const origin=req.headers.origin;if(!origin)return true;try{const o=new URL(origin);const host=req.headers.host;return ['http:','https:'].includes(o.protocol)&&o.host===host;}catch(e){return false;}}
function perUserLimit(req,id){const t=Date.now(),k=id||req.socket.remoteAddress||'unknown';const last=lastAttempt.get(k)||[];const live=last.filter(x=>t-x<10_000);if(live.length>=25)return false;live.push(t);lastAttempt.set(k,live);return true;}
function submitRoundIfEnded(p,sim){const s=sim.state(),roundIdx=currentRound(p);if(roundIdx<0||!s.ended)return false;const round=p.rounds[roundIdx];round.status='complete';round.score=sim.score().score;round.assessment=sim.score().assessment;round.clock=s.clock;round.reason=s.endReason;round.finishedAt=new Date().toISOString();round.report={title:sim.snapshot().round.title,score:round.score,assessment:round.assessment,reason:round.reason,clock:s.clock,health:s.health,exposure:s.exposure,pressure:s.pressure,scoreBreakdown:sim.score().fields,caps:sim.score().caps,objectives:sim.snapshot().round.objectives,chronicle:s.history.slice(-90),evidence:s.evidence.map(id=>sim.snapshot().evidence.find(e=>e.id===id)).filter(Boolean)};return true;}
function publicPlayer(p){const i=currentRound(p),lb=leaderboard().find(x=>x.name===p.name);return {id:p.id,name:p.name,rounds:p.rounds.map((r,n)=>({scenario:STAGES[n],status:r.status,score:r.status==='complete'?r.score:null,assessment:r.status==='complete'?r.assessment:null})),total:total(p),provisionalScore:lb?.provisional||0,liveTotal:lb?.score||0,completed:completedCount(p),active:i,finished:completedCount(p)===STAGES.length,rank:lb?.rank||null};}
function stateResponse(p,last=null){const sim=reconstruct(p);return {player:publicPlayer(p),game:currentRound(p)>=0?sim.snapshot():null,reports:p.rounds.map(r=>r.status==='complete'?r.report||null:null),feedback:last};}
function serveStatic(req,res,pth){const name=pth==='/'?'index.html':pth.slice(1);const names={'index.html':'text/html; charset=utf-8','app.js':'application/javascript; charset=utf-8','style.css':'text/css; charset=utf-8','favicon.svg':'image/svg+xml'};if(!Object.hasOwn(names,name))return fail(res,404,'Not found');let f=path.join(PUBLIC,name);try{const d=fs.readFileSync(f);headerNoCache(res);res.statusCode=200;res.setHeader('Content-Type',names[name]);res.end(d);}catch(e){fail(res,404,'Not found');}}
async function handle(req,res){const url=new URL(req.url,'http://localhost');const pth=url.pathname;if(!pth.startsWith('/api/'))return serveStatic(req,res,pth);
 if(req.method==='GET'&&pth==='/api/board')return json(res,200,board());
 if(req.method==='GET'&&pth==='/api/events'){
  headerNoCache(res);res.writeHead(200,{'Content-Type':'text/event-stream; charset=utf-8','Connection':'keep-alive','X-Accel-Buffering':'no'});
  res.write(`event: board\ndata: ${JSON.stringify(board())}\n\n`);clients.add(res);const t=setInterval(()=>{try{res.write(': keepalive\n\n');}catch(e){clearInterval(t);clients.delete(res);}},20000);req.on('close',()=>{clearInterval(t);clients.delete(res);});return;
 }
 if(req.method==='GET'&&pth==='/api/me'){const p=playerFromReq(req);return p?json(res,200,stateResponse(p)):fail(res,401,'Choose a username to join');}
 if(req.method!=='POST')return fail(res,405,'Method not allowed');
 if(!validOrigin(req))return fail(res,403,'Cross-origin requests are not permitted');
 if(pth==='/api/join'){
  if(!perUserLimit(req))return fail(res,429,'Too many requests');
  const previous=playerFromReq(req);if(previous)return json(res,200,stateResponse(previous));
  const obj=await parseBody(req),name=String(obj.username||'').trim();if(!/^[a-zA-Z0-9][a-zA-Z0-9_-]{2,23}$/.test(name))return fail(res,400,'Username must be 3–24 characters using letters, numbers, hyphens or underscores');
  if(name.toLowerCase()==='admin'||name.toLowerCase()==='administrator')return fail(res,400,'Reserved username');
  if(db.players.some(p=>p.name.toLowerCase()===name.toLowerCase()))return fail(res,409,'Username already taken; return using the browser that joined with it');
  if(db.players.length>=250)return fail(res,403,'Tournament player limit reached');
  const secret=crypto.randomBytes(32).toString('base64url');const id=crypto.randomUUID();
  const p={id,name,tokenHash:crypto.createHash('sha256').update(secret).digest('hex'),joinedAt:new Date().toISOString(),updatedAt:new Date().toISOString(),rounds:STAGES.map((x,i)=>({status:i===0?'active':'pending',score:null})),events:[{type:'start',scenario:STAGES[0]}]};
  db.players.push(p);reconstruct(p);persist();
  res.setHeader('Set-Cookie',`ig_ctf=${id}.${secret}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${COOKIE_SECURE?'; Secure':''}`);
  broadcast('board',board());return json(res,201,stateResponse(p));
 }
 if(pth==='/api/action'){
  const p=playerFromReq(req);if(!p)return fail(res,401,'Session not found. Join again.');if(!perUserLimit(req,p.id))return fail(res,429,'Slow down before sending another move');
  if(currentRound(p)<0)return fail(res,409,'All three scenarios have already finished');
  const cmd=await parseBody(req);const allowed=['query','collect','hypothesis','action'];if(!allowed.includes(cmd.type))return fail(res,400,'Unsupported move');
  // Transaction: the in-memory engine is only considered authoritative after a validated move is committed.
  const sim=reconstruct(p),before=sim.state()?.clock;
  let response;try{response=sim.apply(cmd);}catch(e){ // discard a potentially partially mutated simulation
    instances.delete(keyForPlayer(p));return fail(res,400,e.message||'Invalid move');
  }
  const stored=JSON.parse(JSON.stringify(cmd));p.events.push(stored);p.updatedAt=new Date().toISOString();const finalized=submitRoundIfEnded(p,sim);persist();
  broadcast('board',board());
  return json(res,200,stateResponse(p,response.result));
 }
 if(pth==='/api/next'){
  const p=playerFromReq(req);if(!p)return fail(res,401,'Session not found');const index=completedCount(p);if(index>=STAGES.length)return fail(res,409,'Competition completed');if(currentRound(p)!==-1)return fail(res,409,'Finish the current scenario first');
  p.rounds[index].status='active';p.events.push({type:'start',scenario:STAGES[index]});p.updatedAt=new Date().toISOString();
  const sim=reconstruct(p);sim.start(STAGES[index]);persist();broadcast('board',board());return json(res,200,stateResponse(p));
 }
 if(pth==='/api/admin/reset'){
  const remote=req.socket.remoteAddress||'unknown',past=resetFailures.get(remote)||[];const now=Date.now(),tries=past.filter(t=>now-t<600000);
  if(tries.length>=5)return fail(res,429,'Too many invalid admin reset attempts');
  const input=await parseBody(req);if(input.confirm!=='RESET EVERYTHING')return fail(res,400,'Confirmation phrase required');
  const a=Buffer.from(crypto.createHash('sha256').update(String(input.password||'')).digest('hex'),'hex'),b=Buffer.from(crypto.createHash('sha256').update(ADMIN_PASSWORD).digest('hex'),'hex');
  if(!crypto.timingSafeEqual(a,b)){tries.push(now);resetFailures.set(remote,tries);return fail(res,403,'Invalid administrator password');}
  db=newDB();instances=new Map();lastAttempt=new Map();resetFailures=new Map();persist();
  broadcast('reset',{epoch:db.epoch,message:'The tournament was reset by its administrator'});broadcast('board',board());return json(res,200,{ok:true,epoch:db.epoch});
 }
 return fail(res,404,'Unknown API endpoint');
}
const server=http.createServer((req,res)=>{Promise.resolve(handle(req,res)).catch(e=>{if(!res.headersSent)fail(res,e.status||500,(e.status?e.message:'Server error'));console.error('Request error:',e.message);});});
if(require.main===module){server.listen(PORT,HOST,()=>{console.log(`Incident Guild CTF available at http://localhost:${PORT}`);console.log(`Data directory: ${DATA_DIR}`);console.log('Incident Guild v5 core, tournament difficulty: standard');if(GENERATED_ADMIN_PASSWORD){console.log('Auto-generated persistent administrator password (protect these logs): '+ADMIN_PASSWORD);console.log('Stored in '+ADMIN_PASSWORD_FILE+'; set ADMIN_PASSWORD in .env to override.');}else console.log('Admin password loaded from environment (not displayed).');console.log('For internet use, place the server behind HTTPS and set COOKIE_SECURE=1.');});}
module.exports={server};
