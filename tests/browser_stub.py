import requests
from pathlib import Path
from playwright.sync_api import sync_playwright
BASE='http://127.0.0.1:8844'
SRC=Path('/mnt/data/incident_guild_ctf_v5/public')
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
 def make_page(width,height):
  pg=b.new_page(viewport={'width':width,'height':height})
  session=requests.Session()
  errors=[]
  pg.on('pageerror',lambda e:errors.append(str(e)))
  def bridge(source,req):
   url=BASE+req['url']
   headers={'content-type':'application/json'}
   r=session.request(req.get('method','GET'),url,data=req.get('body'),headers=headers,timeout=10)
   try:data=r.json()
   except:data={'error':'invalid server response'}
   return {'ok':r.ok,'status':r.status_code,'data':data}
  pg.expose_binding('pyFetch',bridge)
  pg.set_content('<html><head><meta charset="utf-8"></head><body><div id="app"></div></body></html>')
  pg.evaluate('''() => {window.fetch=(url,opts={})=>window.pyFetch({url:String(url),method:opts.method||'GET',body:opts.body}).then(r=>({ok:r.ok,status:r.status,json:async()=>r.data})); window.EventSource=class{constructor(){}addEventListener(){}set onerror(x){}};}''')
  pg.add_style_tag(content=(SRC/'style.css').read_text())
  pg.add_script_tag(content=(SRC/'app.js').read_text())
  return pg,errors
 page,errors=make_page(1366,900)
 page.wait_for_timeout(200)
 print('landing',page.locator('#join-form').count(),page.locator('body').inner_text()[:140],errors)
 page.screenshot(path='/mnt/data/incident_guild_ctf_v5/preview_landing.png',full_page=True)
 page.locator('#username').fill('CyberKnight'+str(__import__('random').randint(100,999)))
 page.locator('#join-form button[type=submit]').click();page.wait_for_timeout(200)
 print('joined',page.locator('body').inner_text()[:360],'error panels',page.locator('.alert.error').all_inner_texts(),errors)
 page.screenshot(path='/mnt/data/incident_guild_ctf_v5/preview_game.png',full_page=True)
 page.locator('[data-act=tab][data-id=telemetry]').first.click();page.wait_for_timeout(90)
 print('query',page.locator('#query').count())
 page.locator('#query').fill("user.dst = 'svc_backup'");page.locator('#query-form button[type=submit]').click();page.wait_for_timeout(150)
 print('results',page.locator('.event-table tbody tr').count(),errors)
 page.screenshot(path='/mnt/data/incident_guild_ctf_v5/preview_console.png',full_page=True)
 page.locator('[data-act=inspect]').first.click();page.wait_for_timeout(80)
 print('modal',page.locator('.dialog').count())
 page.locator('[data-act=collect]').first.click();page.wait_for_timeout(120)
 print('postcollect',page.locator('body').inner_text()[-190:],errors)
 page.locator('[data-act=tab][data-id=leaderboard]').first.click();page.wait_for_timeout(110)
 page.screenshot(path='/mnt/data/incident_guild_ctf_v5/preview_board.png',full_page=True)
 mobile,me=make_page(390,844)
 mobile.screenshot(path='/mnt/data/incident_guild_ctf_v5/preview_mobile.png',full_page=True)
 print('mobile width',mobile.evaluate('document.documentElement.scrollWidth'),'error',me)
 assert not errors,errors
 b.close()
print('BROWSER PASSED')
