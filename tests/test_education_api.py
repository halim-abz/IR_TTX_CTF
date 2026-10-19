"""Standalone HTTP integration test: starts isolated server and checks admin, escalation and reset."""
from pathlib import Path
import tempfile,subprocess,os,time,requests
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="warroom-edu-") as directory:
 env={**os.environ,"DATA_DIR":directory,"PORT":"8852","HOST":"127.0.0.1","ADMIN_PASSWORD":"local-test-password-890123"}
 with open(os.devnull,"wb") as log:
  server=subprocess.Popen(["node","server/server.cjs"],cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
  try:
   base="http://127.0.0.1:8852"
   for i in range(30):
    try:
     if requests.get(base+"/api/board",timeout=2).ok:break
    except requests.RequestException:pass
    time.sleep(.1)
   user=requests.Session()
   assert user.post(base+"/api/join",json={"username":"EducationTester"},timeout=5).status_code==201
   assert requests.post(base+"/api/admin/overview",json={"password":"bad"},timeout=5).status_code==403
   overview=requests.post(base+"/api/admin/overview",json={"password":env["ADMIN_PASSWORD"]},timeout=5)
   assert overview.ok and overview.json()["summary"]["registered"]==1
   # Ransomware bad step feedback returns educational note; not a dice-based judgement.
   result=user.post(base+"/api/action",json={"type":"action","id":"panic"},timeout=5)
   assert result.ok and result.json()["coaching"]["kind"]=="error"
   assert result.json()["coaching"]["better"]
   state=user.get(base+"/api/me",timeout=5).json()["game"]
   assert state["actions"][-1]["id"]=="panic"
   reset=requests.post(base+"/api/admin/reset",json={"password":env["ADMIN_PASSWORD"],"confirm":"RESET EVERYTHING"},timeout=5)
   assert reset.ok and requests.get(base+"/api/board",timeout=5).json()["players"]==0
   assert user.get(base+"/api/me",timeout=5).status_code==401
   print("Admin overview, unsafe coaching, reset, session invalidation: PASSED")
  finally:
   server.terminate()
   try:server.wait(timeout=3)
   except subprocess.TimeoutExpired:server.kill()
