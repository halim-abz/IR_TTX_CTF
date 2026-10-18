"""Self-contained check that live competition, scoring, and admin reset still work."""
from pathlib import Path
import subprocess,os,tempfile,atexit,time,requests,uuid
ROOT=Path(__file__).resolve().parents[1]
port='8863'
server=subprocess.Popen(['node',str(ROOT/'server/server.cjs')],env={**os.environ,'HOST':'127.0.0.1','PORT':port,'DATA_DIR':tempfile.mkdtemp(prefix='ig_v5_enhanced_'),'ADMIN_PASSWORD':'ctf-admin-test'},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
atexit.register(server.terminate);time.sleep(.5)
base='http://127.0.0.1:'+port
alice=requests.Session();bob=requests.Session()
for session,name in [(alice,'PlayerAlice'),(bob,'PlayerBob')]:
 r=session.post(base+'/api/join',json={'username':name});assert r.status_code==201,r.text
assert requests.get(base+'/api/board').json()['players']==2
q=alice.post(base+'/api/action',json={'type':'query','source':'Logs','query':"user.dst = 'svc_backup'"})
assert q.ok,q.text
assert 'guide' in q.json()['game']
assert alice.post(base+'/api/action',json={'type':'action','id':'verify','role':'commander'}).status_code==400
assert alice.post(base+'/api/next',json={}).status_code==409
assert alice.post(base+'/api/action',json={'type':'collect','id':'m03','score':300}).ok
board=requests.get(base+'/api/board').json()['leaderboard'];assert len(board)==2
assert max(x['score'] for x in board)<=300
assert requests.post(base+'/api/admin/reset',json={'password':'bad','confirm':'RESET EVERYTHING'}).status_code==403
assert requests.post(base+'/api/admin/reset',json={'password':'ctf-admin-test','confirm':'RESET EVERYTHING'}).ok
assert requests.get(base+'/api/board').json()['players']==0
assert alice.get(base+'/api/me').status_code==401
print('CTF COMPETITION AND ADMIN RESET REGRESSION PASS')
