from playwright.sync_api import sync_playwright
import requests,uuid,subprocess,os,time,tempfile,atexit
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE='http://game.test'
REAL='http://127.0.0.1:8848'
test_dir=tempfile.mkdtemp(prefix='ctf_forensics_')
server=subprocess.Popen(['node',str(ROOT/'server/server.cjs')],env={**os.environ,'HOST':'127.0.0.1','PORT':'8848','ADMIN_PASSWORD':'test-admin','DATA_DIR':test_dir},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
atexit.register(server.terminate)
time.sleep(0.5)
with sync_playwright() as p:
 b=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
 page=b.new_page(viewport={'width':1480,'height':1050})
 errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 session=requests.Session()
 def fake_fetch(source,req):
  r=session.request(req.get('method','GET'),REAL+req['url'],data=req.get('body') or None,headers={'content-type':'application/json'},timeout=8)
  return {'ok':r.ok,'status':r.status_code,'body':r.json()}
 page.expose_binding('_pyfetch',fake_fetch)
 page.set_content('<div id="app"></div>')
 page.add_style_tag(content=(ROOT/'public/style.css').read_text())
 page.add_script_tag(content='window.EventSource=class {addEventListener(){} set onerror(x){} }; window.fetch=(url,opt={})=>window._pyfetch({url:String(url),method:opt.method||"GET",body:opt.body||null}).then(r=>({ok:r.ok,status:r.status,json:async()=>r.body}));')
 page.add_script_tag(content=(ROOT/'public/app.js').read_text())
 page.wait_for_selector('#join-form')
 page.fill('#username','Packet'+uuid.uuid4().hex[:8]);page.locator('#join-form button[type=submit]').click()
 page.wait_for_selector('[data-act="tab"][data-id="telemetry"]')
 page.locator('.nav[data-id="telemetry"]').first.click()
 page.wait_for_selector('#query')
 print('guide',page.locator('.guide-card').count(),'pivots',page.locator('.pivot-chip').count())
 assert page.locator('.guide-card').count()==4
 assert page.locator('.pivot-chip').count()>=3
 # User requested: click a pivot => fill the input, no query is sent until submission
 before=page.locator('.metric').first.inner_text()
 expected=page.locator('.pivot-chip').nth(1).get_attribute('data-query')
 page.locator('.pivot-chip').nth(1).click()
 assert page.locator('#query').input_value()==expected
 assert page.locator('.metric').first.inner_text()==before
 page.locator('[data-act="source"][data-id="Network"]').click()
 assert page.locator('.pivot-chip').count()>=3
 page.locator('.pivot-chip').filter(has_text="service = 'smb'").click()
 assert page.locator('#query').input_value()=="service = 'smb'"
 # Advance time for SMB record
 for _ in range(3):
  page.locator('#query-form button[type=submit]').click();page.wait_for_timeout(260)
 assert page.locator('details.inline-packet').count()>=1
 page.locator('details.inline-packet').first.locator('summary').click()
 assert 'FE 53 4D 42' in page.locator('.hexdump').first.inner_text()
 page.locator('button[data-act="inspect"]').first.click()
 assert page.locator('.forensic-dialog').count()==1
 assert page.locator('.forensic-dialog .packets').count()==1
 page.screenshot(path=str(ROOT/'forensics_network.png'),full_page=True)
 page.locator('.forensic-dialog [data-act="modal-close"]').first.click()
 page.locator('[data-act="source"][data-id="Endpoint"]').click()
 # Process wasn't present yet; query advances twice to 10 mins
 page.locator('.pivot-chip').filter(has_text="process ~ 'powershell'").click()
 for _ in range(3):page.locator('#query-form button[type=submit]').click();page.wait_for_timeout(260)
 assert page.locator('.record-command').count()>=1
 assert 'EncodedCommand' in page.locator('.record-command').first.inner_text()
 page.locator('button[data-act="inspect"]').first.click()
 assert 'PARENT COMMAND LINE' in page.locator('.forensic-dialog').inner_text().upper()
 assert 'WORKING DIRECTORY' in page.locator('.forensic-dialog').inner_text().upper()
 page.screenshot(path=str(ROOT/'forensics_endpoint.png'),full_page=True)
 assert not errors,errors
 print('DESKTOP BROWSER PASS')
 # Responsive tests for smaller viewports
 mobile=b.new_page(viewport={'width':390,'height':844},device_scale_factor=1)
 mobile.set_default_timeout(8000)
 errors2=[];mobile.on('pageerror',lambda e:errors2.append(str(e)))
 mobile_session=requests.Session()
 def mobile_fetch(source,req):
  r=mobile_session.request(req.get('method','GET'),REAL+req['url'],data=req.get('body') or None,headers={'content-type':'application/json'},timeout=8)
  return {'ok':r.ok,'status':r.status_code,'body':r.json()}
 mobile.expose_binding('_pyfetch',mobile_fetch)
 mobile.set_content('<div id="app"></div>')
 mobile.add_style_tag(content=(ROOT/'public/style.css').read_text())
 mobile.add_script_tag(content='window.EventSource=class {addEventListener(){} set onerror(x){} };window.fetch=(url,opt={})=>window._pyfetch({url:String(url),method:opt.method||"GET",body:opt.body||null}).then(r=>({ok:r.ok,status:r.status,json:async()=>r.body}));')
 mobile.add_script_tag(content=(ROOT/'public/app.js').read_text())
 mobile.wait_for_selector('#join-form')
 mobile.fill('#username','Mobile'+uuid.uuid4().hex[:8]);mobile.locator('#join-form button[type=submit]').click();mobile.wait_for_selector('.mobile-tabs [data-id="telemetry"]')
 mobile.locator('.mobile-tabs [data-id="telemetry"]').click()
 assert mobile.locator('.pivot-chip').count()>=1
 assert mobile.locator('.guide-card').count()==4
 mobile.screenshot(path=str(ROOT/'forensics_mobile.png'),full_page=True)
 print('mobile width',mobile.evaluate('document.documentElement.scrollWidth'))
 assert mobile.evaluate('document.documentElement.scrollWidth')<=390
 assert not errors2,errors2
 print('MOBILE BROWSER PASS')
 b.close()
