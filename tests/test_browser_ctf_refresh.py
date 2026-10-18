"""Browser smoke against isolated game API; builds screenshots in /mnt/data."""
import requests,random,os
from pathlib import Path
from playwright.sync_api import sync_playwright
BASE=os.environ.get('CTF_TEST_BASE','http://127.0.0.1:8847')
SRC=Path(__file__).resolve().parents[1]
OUT=Path('/mnt/data/incident_trace_ctf_previews');OUT.mkdir(exist_ok=True)
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
 def page(width,height):
  pg=b.new_page(viewport={'width':width,'height':height});session=requests.Session();errors=[]
  pg.on('pageerror',lambda e:errors.append(str(e)))
  def bridge(source,req):
   r=session.request(req.get('method','GET'),BASE+req['url'],data=req.get('body'),headers={'content-type':'application/json'},timeout=12)
   return {'ok':r.ok,'status':r.status_code,'data':r.json()}
  pg.expose_binding('pyFetch',bridge)
  pg.set_content('<html><head><meta charset="utf-8"></head><body><div id="app"></div></body></html>')
  pg.evaluate('''() => {window.fetch=(url,opts={})=>window.pyFetch({url:String(url),method:opts.method||'GET',body:opts.body}).then(r=>({ok:r.ok,status:r.status,json:async()=>r.data})); window.EventSource=class{constructor(){}addEventListener(){}set onerror(x){}};}''')
  pg.add_style_tag(content=(SRC/'public/style.css').read_text())
  pg.add_script_tag(content=(SRC/'public/app.js').read_text())
  pg.wait_for_timeout(200)
  return pg,errors
 desktop,errors=page(1440,900)
 assert desktop.locator('#join-form').count()==1,desktop.locator('body').inner_text()[:300]
 desktop.screenshot(path=str(OUT/'landing.png'),full_page=True)
 desktop.locator('#username').fill('UX_Check_'+str(random.randint(10000,99999)))
 desktop.locator('#join-form button[type=submit]').click();desktop.wait_for_timeout(350)
 assert desktop.locator('.nav-list button.nav').count()==4 # four main + admin
 assert 'The Midnight Ticket' in desktop.locator('body').inner_text()
 assert 'Initial incident alert' in desktop.locator('body').inner_text()
 assert len(desktop.locator('.full-mission-description').inner_text())>145
 assert desktop.locator('.mobile-tabs').count()==0
 desktop.screenshot(path=str(OUT/'mission.png'),full_page=True)
 desktop.locator('[data-act=tab][data-id=casebook]').first.click()
 assert desktop.locator('.flag-card').count()==2
 desktop.screenshot(path=str(OUT/'flags.png'),full_page=True)
 desktop.locator('[data-act=tab][data-id=telemetry]').first.click()
 desktop.locator('#query').fill("user.dst = 'svc_backup'")
 desktop.locator('#query-form button[type=submit]').click();desktop.wait_for_timeout(300)
 desktop.locator('[data-act=inspect][data-id=m03]').click();desktop.wait_for_timeout(150)
 assert desktop.locator('.dialog').count()==1
 assert 'Raw log event' in desktop.locator('.dialog').inner_text()
 assert 'event.id=' in desktop.locator('.dialog').inner_text()
 desktop.screenshot(path=str(OUT/'log.png'),full_page=True)
 desktop.locator('[data-act=modal-close]').first.click()
 desktop.locator('#query').fill("service = 'smb'")
 desktop.locator('[data-act=source][data-id=Network]').first.click()
 desktop.locator('#query').fill("service = 'smb'")
 desktop.locator('#query-form button[type=submit]').click();desktop.wait_for_timeout(250)
 desktop.locator('[data-act=inspect][data-id=m08]').click();desktop.wait_for_timeout(150)
 assert 'budget-draft.xlsx' in desktop.locator('.dialog').inner_text()
 assert 'Visibility limit:' not in desktop.locator('.dialog').inner_text()
 desktop.screenshot(path=str(OUT/'network.png'),full_page=True)
 mobile,me=page(390,844)
 mobile.locator('#username').fill('MobileCheck'+str(random.randint(10000,99999)))
 mobile.locator('#join-form button[type=submit]').click();mobile.wait_for_timeout(330)
 assert mobile.locator('.nav-list button.nav').count()==4
 assert mobile.locator('.mobile-tabs').count()==0
 assert 'Initial incident alert:' in mobile.locator('body').inner_text()
 mobile.screenshot(path=str(OUT/'mobile.png'),full_page=True)
 print('WIDTH',mobile.evaluate('document.documentElement.scrollWidth'),mobile.evaluate('window.innerWidth'))
 print('BROWSER ERRORS',errors,me)
 assert not errors and not me,(errors,me)
 b.close()
print('BROWSER SMOKE PASSED')
