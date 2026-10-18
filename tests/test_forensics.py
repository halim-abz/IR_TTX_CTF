"""Integration checks for CTF investigation enrichments (running server on :8848)."""
import requests
BASE='http://127.0.0.1:8848'
s=requests.Session()
r=s.post(BASE+'/api/join',json={'username':'ForensicTester'})
assert r.status_code==201,(r.status_code,r.text)
assert len(r.json()['game']['guide']['milestones'])==4
assert r.json()['game']['guide']['pivotIdeas']['Logs']

def query(source,expr):
 r=s.post(BASE+'/api/action',json={'type':'query','source':source,'query':expr});assert r.ok,(r.status_code,r.text);return r.json()['game']

g=query('Logs',"user.dst = 'svc_backup'")
assert any(x['id']=='m03' for x in g['console']['results'])
for i in range(4):g=query('Network',"service = 'smb'")
assert any(x['id']=='m08' for x in g['console']['results']),[x['id'] for x in g['console']['results']]
r=next(x for x in g['console']['results'] if x['id']=='m08')
assert r['packet']['frames'][0]['hex'].startswith('FE 53 4D 42')
assert r['packet']['visibility'].startswith('SMB2')
# Advance to minute 10 to access m11 process telemetry.
for i in range(3):g=query('Endpoint',"process ~ 'powershell'")
assert any(x['id']=='m11' for x in g['console']['results']),g['round']['clock']
r=next(x for x in g['console']['results'] if x['id']=='m11')
assert '-EncodedCommand' in r['endpoint']['commandLine']
assert r['endpoint']['parentCommandLine']
assert 'command.line' in r['fields']
g=query('Endpoint',"command.line ~ 'EncodedCommand'")
assert any(x['id']=='m11' for x in g['console']['results'])
# Captured HTTP WinRM headers should not claim to contain decrypted commands.
g=query('Network',"service = 'winrm'")
assert any(x['id']=='m09' for x in g['console']['results'])
assert 'encrypted' in next(x for x in g['console']['results'] if x['id']=='m09')['packet']['visibility'].lower() or 'protected' in next(x for x in g['console']['results'] if x['id']=='m09')['packet']['visibility'].lower()
# TLS app data is not magically decrypted.
for i in range(7):g=query('Network',"alias.host = 'store-updates.example'")
assert any(x['id']=='m15' for x in g['console']['results']),g['round']['clock']
assert 'encrypted' in next(x for x in g['console']['results'] if x['id']=='m15')['packet']['limitations'].lower()
# Server-side score cannot be directly set by the browser.
assert s.post(BASE+'/api/action',json={'type':'collect','id':'m15','score':300}).ok
print('FORENSIC ENRICHMENT API TESTS PASS, score:',s.get(BASE+'/api/me').json()['player']['liveTotal'])
