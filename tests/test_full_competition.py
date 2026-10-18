import requests,random,time
BASE='http://127.0.0.1:8844'
s=requests.Session();name=f'FullRunner{random.randint(1000,9999)}'
r=s.post(BASE+'/api/join',json={'username':name});assert r.status_code==201,r.text
print('joined',name)

def move(body):
 
 for retry in range(20):
  r=s.post(BASE+'/api/action',json=body)
  if r.status_code==429:
   time.sleep(.65);continue
  assert r.status_code==200,(body,r.status_code,r.text[:250])
  return r.json()
 raise AssertionError('Rate limited too long')
def col(src,q,ids):
 x=move({'type':'query','source':src,'query':q})
 for rid in ids:
  if rid in [x['id'] for x in x['game']['console']['results']]:
   x=move({'type':'collect','id':rid})
  else:print('missing',rid,'at',x['game']['round']['clock'])
 return x

def act(id,role='commander'):
 x=None
 for n in range(7):
  r=s.get(BASE+'/api/me').json();a=next(a for a in r['game']['actions'] if a['id']==id)
  if a['done']:return r
  if a['locked']:raise AssertionError('Locked action '+id+': '+str(r['game']['evidence']))
  x=move({'type':'action','id':id,'role':role})
  if x['game'] is None:return x
  if next(a for a in x['game']['actions'] if a['id']==id)['done']:return x
 raise AssertionError('too many rolls for '+id)

def hypo(id,choice):return move({'type':'hypothesis','id':id,'choice':choice})

def report():
 x=s.get(BASE+'/api/me').json();print('  player',x['player']['name'],'stage',x['player']['active'],'total',x['player']['total'],'rounds',x['player']['rounds']);return x

act('brief')
col('Logs',"user.dst = 'svc_backup'",['m03','m05'])
act('owner');col('Network',"ip.src = '10.14.8.42'",['m08'])
col('Endpoint',"host = 'WS-042'",['m11','m12'])
act('preserve');act('revoke');act('isolate');act('backup');act('eradicate');act('restore')
hypo('origin',1);hypo('movement',1);act('verify')
x=report();assert x['player']['completed']==1
assert x['player']['rounds'][0]['score'] is not None
assert s.post(BASE+'/api/action',json={'type':'query','source':'Logs','query':'service = smb'}).status_code==409
r=s.post(BASE+'/api/next',json={});assert r.status_code==200,r.text[:240]
print('lantern begun')
col('Logs',"user.dst = 'svc_reports'",['l02','l03','l04','l05'])
col('Network',"alias.host = 'sync-metrics.example'",['l06'])
col('Endpoint',"host = 'BUILD-02'",['l09','l10'])
act('brief');col('Logs',"user.dst = 'svc_reports'",['l05']);act('preserve');act('revoke');act('block');act('scope','analyst');act('cleanup','forensic');act('restore','engineer')
hypo('identity',1);hypo('loss',2);act('verify','analyst')
x=report();assert x['player']['completed']==2
assert s.post(BASE+'/api/next',json={}).status_code==200
print('valve begun')
col('Logs',"user.dst = 'ot_contractor'",['v02','v03'])
act('brief');act('approval')
col('Network',"ip.src = '10.20.8.17'",['v05'])
col('Network',"ip.src = '10.90.10.15'",['v08'])
col('Endpoint',"host = 'OT-JUMP-01'",['v11'])
act('plant');act('preserve');act('cut-vpn');act('seg-ot');act('plc','engineer');act('cleanup','forensic');act('restore','engineer')
hypo('authorization',2);hypo('boundary',0);act('verify','hunter')
x=report();assert x['player']['finished'];assert x['player']['completed']==3
assert s.post(BASE+'/api/next',json={}).status_code==409
board=requests.get(BASE+'/api/board').json()
p=next(x for x in board['leaderboard'] if x['name']==name)
assert p['score']==x['player']['total'] and p['completed']==3
print('final',p['score'],p['rounds'],p['rank'])
print('FULL COMPETITION PASSED')
