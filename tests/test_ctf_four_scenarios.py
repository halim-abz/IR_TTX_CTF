"""Run against an isolated server at localhost:8844; verify full four-scenario event and CTF flow."""
import requests,random,time,os
B=os.environ.get('CTF_TEST_BASE','http://127.0.0.1:8849')
s=requests.Session()
username='CTFTester'+str(random.randint(10000,99999))
r=s.post(B+'/api/join',json={'username':username});assert r.status_code==201,(r.status_code,r.text)
print('JOIN',username)
def move(body):
 for n in range(20):
  r=s.post(B+'/api/action',json=body)
  if r.status_code==429:time.sleep(.55);continue
  assert r.status_code==200,(body,r.status_code,r.text[:400])
  return r.json()
 raise AssertionError('rate limit')
def col(src,q,ids):
 x=move({'type':'query','source':src,'query':q})
 for rid in ids:
  for _ in range(8):
   matches={x['id'] for x in x['game']['console']['results']}
   if rid in matches:break
   x=move({'type':'query','source':src,'query':q})
  assert rid in matches,(src,q,rid,x['game']['round']['clock'],matches)
  x=move({'type':'collect','id':rid})
 return x

def record(x,id):return next(r for r in x["game"]["console"]["results"] if r["id"]==id)
def act(action):
 for _ in range(6):
  state=s.get(B+'/api/me').json()['game'];a=next(x for x in state['actions'] if x['id']==action)
  if a['done']:return state
  assert not a['locked'],('locked',action,[x['id'] for x in state['evidence']])
  x=move({'type':'action','id':action})
  if x['game'] is None:return x
 raise AssertionError('action max retries '+action)

def flag(id,value):
 x=move({'type':'flag','id':id,'value':value})
 assert next(f for f in x['game']['flags'] if f['id']==id)['solved'],(id,x['feedback'] if 'feedback' in x else None)
 return x

def hypo(id,choice):return move({'type':'hypothesis','id':id,'choice':choice})
def advance(expected):
 x=s.get(B+'/api/me').json();assert x['player']['completed']==expected,(expected,x['player']);print('DONE',expected,x['player']['rounds'][expected-1]['score'],'total',x['player']['total']);
 if expected<4:assert s.post(B+'/api/next',json={}).status_code==200
 return x
# midnight
act('brief')
col('Logs',"user.dst = 'svc_backup'",['m03','m05'])
col('Network',"ip.src = '10.14.8.42'",['m08'])
flag('file','budget-draft.xlsx')
col('Endpoint',"host = 'WS-042'",['m11','m12'])
act('owner');act('preserve');act('revoke');act('isolate');act('backup')
x=col('Network',"alias.host = 'store-updates.example'",['m15','m16'])
flag('archive',record(x,'m16')['packet']['frames'][0]['decoded']['archive'])
act('eradicate');act('restore')
hypo('origin',1);hypo('movement',1);act('verify');advance(1)
# lantern
x=col('Logs',"user.dst = 'svc_reports'",['l02','l03','l04','l05'])
flag('token',record(x,'l03')['fields']['token.id'])
x=col('Network',"alias.host = 'sync-metrics.example'",['l06','l07'])
flag('batch',record(x,'l07')['packet']['frames'][0]['decoded']['batch'])
col('Endpoint',"host = 'BUILD-02'",['l09','l10'])
act('brief');act('preserve');act('revoke');act('block');act('scope');act('cleanup');act('restore')
hypo('identity',1);hypo('loss',2);act('verify');advance(2)
# valve
col('Logs',"user.dst = 'ot_contractor'",['v02','v03'])
flag('account','ot_contractor')
act('brief');act('approval')
col('Network',"ip.src = '10.20.8.17'",['v05'])
x=col('Network',"ip.src = '10.90.10.15'",['v08','v09'])
flag('register',record(x,'v09')['packet']['frames'][0]['decoded']['registerAddress'])
col('Endpoint',"host = 'OT-JUMP-01'",['v11'])
act('plant');act('preserve');act('cut-vpn');act('seg-ot');act('plc');act('cleanup');act('restore')
hypo('authorization',2);hypo('boundary',0);act('verify');advance(3)
# webshell
col('Network',"alias.host = 'portal.internal.example'",['w01','w04'])
flag('path','/uploads/.cache.php')
col('Logs',"action = 'unexpected-php'",['w02'])
col('Logs',"action = 'webshell-request'",['w07'])
col('Endpoint',"parent = 'php-fpm'",['w03'])
col('Endpoint',"process = 'tar'",['w05'])
x=col('Network',"ip.dst = '203.0.113.92'",['w06'])
import re
response=bytes.fromhex(record(x,'w06')['packet']['frames'][1]['hex']).decode('utf-8')
flag('receipt',re.search(r'rcpt-\d+',response).group())
act('brief');act('owner');act('preserve');act('restrict');act('isolate');act('scope');act('cleanup');act('restore')
hypo('path',1);hypo('loss',2);act('verify');x=advance(4)
assert x['player']['finished'] and x['player']['total']<=400
board=requests.get(B+'/api/board').json();row=next(r for r in board['leaderboard'] if r['name']==username)
assert row['score']==x['player']['total'] and len(row['rounds'])==4
print('FOUR STAGES PASSED',row['rounds'],row['score'])
