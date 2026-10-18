import requests,threading,time,random
from pathlib import Path
from playwright.sync_api import sync_playwright
BASE='http://127.0.0.1:8844'
latest=[]
started=threading.Event()
def listen():
  with requests.get(BASE+'/api/events',stream=True,timeout=(5,15)) as r:
    for line in r.iter_lines(decode_unicode=True):
      if line.startswith('data: '):
        latest.append(line[6:]);started.set()
        if len(latest)>=2:return
thread=threading.Thread(target=listen,daemon=True);thread.start();assert started.wait(5)
s=requests.Session();name='LiveUser'+str(random.randrange(10000,99999));r=s.post(BASE+'/api/join',json={'username':name});assert r.status_code==201
thread.join(5)
assert len(latest)>=2,len(latest)
assert name in latest[-1]
print('SSE update after join: OK')
# Browser admin controls with mocked API calls for this restricted test browser
SRC=Path('/mnt/data/incident_guild_ctf_v5/public')
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
 page=b.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 api=requests.Session()
 def bridge(source,req):
  r=api.request(req.get('method','GET'),BASE+req['url'],data=req.get('body'),headers={'content-type':'application/json'},timeout=10)
  return {'ok':r.ok,'status':r.status_code,'data':r.json()}
 page.expose_binding('pyFetch',bridge);page.set_content('<html><body><div id="app"></div></body></html>')
 page.evaluate('''() => {window.fetch=(url,opt={})=>pyFetch({url,method:opt.method||'GET',body:opt.body}).then(x=>({ok:x.ok,status:x.status,json:async()=>x.data}));window.EventSource=class{addEventListener(){}set onerror(f){}};}''')
 page.add_style_tag(content=(SRC/'style.css').read_text());page.add_script_tag(content=(SRC/'app.js').read_text());page.wait_for_timeout(200)
 page.locator('[data-act=admin]').click();page.wait_for_timeout(120)
 assert page.locator('#admin-password').count()==1
 page.locator('#admin-password').fill('wrong')
 page.locator('#reset-confirm').fill('RESET EVERYTHING')
 page.locator('#reset-form button').click();page.wait_for_timeout(300)
 assert page.locator('#admin-password').count()==1
 assert page.locator('.alert.error').count()>=1
 print('Admin incorrect password keeps form: OK')
 page.locator('#admin-password').fill('test-admin-789')
 page.locator('#reset-confirm').fill('RESET EVERYTHING')
 page.locator('#reset-form button').click();page.wait_for_timeout(300)
 assert page.locator('#join-form').count()==1
 assert requests.get(BASE+'/api/board').json()['players']==0
 assert s.get(BASE+'/api/me').status_code==401
 assert not errors,errors
 print('Admin reset clears players and sessions: OK')
 b.close()
