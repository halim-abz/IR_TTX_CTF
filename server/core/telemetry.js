/* Incident Guild v5 | Standalone simulated investigation datasets.
   All records are fictional and deliberately include benign noise.
   Log field names shown in the query console are a GAME SUBSET, not a claim of universal NetWitness parser syntax. */
const T=(id,source,time,host,fields,evidence=null,detail='')=>({id,source,time,host,fields,evidence,detail});
const INVESTIGATION_DATA={
 midnight:{
  starter:"user.dst = 'svc_backup'",
  tips:["user.dst = 'svc_backup'","ip.src = '10.14.8.42'","service = 'smb'","host = 'WS-042'","alias.host = 'store-updates.example'"],
  rows:[
   T('m01','Logs','03:02:11','DC-01',{'user.dst':'svc_backup','ip.src':'10.14.1.10','ip.dst':'10.14.1.2','event.id':4624,action:'success',service:'kerberos'},null,'Known backup workload from ADM-01; network logon.'),
   T('m02','Logs','03:04:43','DC-01',{'user.dst':'svc_backup','ip.src':'10.14.1.10','ip.dst':'10.14.1.2','event.id':4769,service:'cifs/backup-01',action:'ticket'},null,'Expected nightly backup service ticket.'),
   T('m03','Logs','03:14:02','DC-01',{'user.dst':'svc_backup','ip.src':'10.14.8.42','ip.dst':'10.14.1.2','event.id':4624,action:'success',service:'ntlm', 'logon.type':3},'r1','Unexpected network logon from WS-042.'),
   T('m04','Logs','03:14:04','DC-01',{'user.dst':'svc_backup','ip.src':'10.14.8.42','ip.dst':'10.14.1.2','event.id':4672,action:'privileged-logon',service:'windows'},'r1','Special privileges were assigned for the same logon context.'),
   T('m05','Logs','03:15:10','DC-01',{'user.dst':'svc_backup','ip.src':'10.14.8.42','ip.dst':'10.14.1.2','event.id':4769,action:'ticket',service:'cifs/FS-01'},'r2','Ticket requested for a file server outside the backup job.'),
   T('m06','Logs','03:15:19','DC-01',{'user.dst':'svc_backup','ip.src':'10.14.8.42','ip.dst':'10.14.1.2','event.id':4769,action:'ticket',service:'host/APP-02'},'r2','Additional service ticket request.'),
   T('m07','Logs','03:16:04','ADM-01',{'user.dst':'it.helpdesk','ip.src':'10.14.1.10','event.id':4624,action:'success',service:'windows'},null,'Normal administrator activity.'),
   T('m08','Network','03:17:42','WS-042',{'ip.src':'10.14.8.42','ip.dst':'10.14.22.19',service:'smb','tcp.dstport':445,'bytes.out':236000000,action:'file-session'},'r6','Unexpected east–west SMB volume to FS-01.'),
   T('m09','Network','03:18:06','WS-042',{'ip.src':'10.14.8.42','ip.dst':'10.14.18.20',service:'winrm','tcp.dstport':5985,'bytes.out':98000,action:'remote-management'},'r6','WinRM session to APP-02.'),
   T('m10','Network','03:18:40','ADM-01',{'ip.src':'10.14.1.10','ip.dst':'10.14.22.19',service:'smb','tcp.dstport':445,'bytes.out':120000,action:'file-session'},null,'Expected administrative file share access.'),
   T('m11','Endpoint','03:21:14','WS-042',{'ip.src':'10.14.8.42',process:'powershell.exe',parent:'wsmprovhost.exe',user:'svc_backup',action:'process-start'},'r4','Encoded PowerShell launched by a remote-management service host.'),
   T('m12','Endpoint','03:23:10','WS-042',{'ip.src':'10.14.8.42',process:'schtasks.exe',parent:'powershell.exe',user:'svc_backup',action:'task-create'},'r5','SysCacheUpdate task registered; action references a script in ProgramData.'),
   T('m13','Endpoint','03:27:09','FS-01',{'ip.src':'10.14.22.19',process:'7z.exe',parent:'services.exe',user:'svc_backup',action:'archive-create'},'r9','Finance data staged in a compressed archive.'),
   T('m14','Endpoint','03:28:10','APP-02',{process:'svchost.exe',parent:'services.exe',user:'SYSTEM',action:'process-start'},null,'Routine service startup.'),
   T('m15','Network','03:31:08','APP-02',{'ip.src':'10.14.18.20','ip.dst':'198.51.100.77',service:'tls','tcp.dstport':443,'alias.host':'store-updates.example','bytes.out':346000000,action:'upload'},'r7','Large outbound TLS transfer to newly seen destination.'),
   T('m16','Network','03:31:20','APP-02',{'ip.src':'10.14.18.20','ip.dst':'198.51.100.77',service:'tls','tcp.dstport':443,'alias.host':'store-updates.example','bytes.out':346000000,action:'tls-reconstruction'},'r8','Session reconstruction: SNI and transfer direction available; decoded HTTP at TLS inspection point available.'),
   T('m17','Network','03:34:11','APP-02',{'ip.src':'10.14.18.20','ip.dst':'198.51.100.12',service:'https','tcp.dstport':443,'alias.host':'vendor-updates.example','bytes.out':44000,action:'request'},null,'Approved software catalog synchronization.')
  ],
  questions:[
   {id:'origin',question:'Which host originated the suspicious privileged authentication?',options:['ADM-01','WS-042','FS-01','Cannot be determined'],correct:1,requires:['r1'],reason:'4624/4672 correlate the source address 10.14.8.42 to WS-042.'},
   {id:'movement',question:'What evidence best establishes lateral movement?',options:['A large outbound TLS session alone','SMB/WinRM connections plus remote process activity','A routine backup logon','A firewall alert without a source'],correct:1,requires:['r6','r4'],reason:'The east–west sessions and wsmprovhost/PowerShell ancestry substantiate movement.'},
   {id:'exposure',question:'What can be concluded about the outbound TLS transfer?',options:['Every finance document definitely left','The configured TLS inspection point shows the HTTP archive and server receipt, corroborated by Endpoint','It is harmless because port 443 was used','TLS proves the attacker used stolen certificates'],correct:1,requires:['r7','r8'],reason:'The decoded HTTP application stream contains the archive identity and receipt, while Endpoint confirms staging.'}
  ]
 },
 lantern:{
  starter:"user.dst = 'svc_reports'",
  tips:["user.dst = 'svc_reports'","ip.src = '10.33.5.22'","service = 'https'","host = 'BUILD-02'","alias.host = 'sync-metrics.example'"],
  rows:[
   T('l01','Logs','09:50:12','API-03',{'user.dst':'svc_reports','ip.src':'10.33.2.21','event.id':200,action:'api-get',service:'api'},null,'Scheduled reports service reads expected records.'),
   T('l02','Logs','10:02:21','API-03',{'user.dst':'svc_reports','ip.src':'10.33.5.22','event.id':200,action:'api-enumerate',service:'api'},'l1','Unusual sustained customer lookup sequence.'),
   T('l03','Logs','10:04:01','IDP-01',{'user.dst':'svc_reports','ip.src':'10.33.5.22','token.id':'tok-4880',action:'token-valid',service:'oauth'},'l2','Valid token consumed from unexpected BUILD-02 source.'),
   T('l04','Logs','10:04:15','IDP-01',{'user.dst':'svc_reports','ip.src':'10.33.5.22',action:'token-scope',service:'oauth'},'l7','Scope customers.read; audience reports-api.'),
   T('l05','Logs','10:07:23','API-03',{'user.dst':'svc_reports','ip.src':'10.33.5.22','event.id':200,action:'bulk-object-read',service:'api','request.count':27440},'l5','26,911 successful requests within the collection window; this is not an exact leaked record count.'),
   T('l06','Network','10:09:04','PROXY-01',{'ip.src':'10.33.5.22','ip.dst':'203.0.113.75',service:'tls','tcp.dstport':443,'alias.host':'sync-metrics.example','bytes.out':520000000,action:'upload'},'l3','Large outbound transfer to unusual destination.'),
   T('l07','Network','10:09:48','PROXY-01',{'ip.src':'10.33.5.22','ip.dst':'203.0.113.75',service:'tls','tcp.dstport':443,'alias.host':'sync-metrics.example','bytes.out':520000000,action:'tls-reconstruction'},'l6','HTTP application payload and receipt available from configured TLS inspection point.'),
   T('l08','Network','10:10:12','PROXY-01',{'ip.src':'10.33.2.21','ip.dst':'198.51.100.15',service:'https','tcp.dstport':443,'alias.host':'reports-cdn.example','bytes.out':10000,action:'request'},null,'Normal reporting asset fetch.'),
   T('l09','Endpoint','09:58:42','BUILD-02',{'ip.src':'10.33.5.22',process:'python.exe',parent:'sh',user:'build',action:'secret-read'},'l4','Build worker process accessed reports service secret environment file.'),
   T('l10','Endpoint','09:57:51','BUILD-02',{'ip.src':'10.33.5.22',process:'curl',parent:'sh',user:'build',action:'download'},'l8','Unexpected script downloaded before credential access.'),
   T('l11','Endpoint','10:13:02','BUILD-02',{'ip.src':'10.33.5.22',process:'git',parent:'runner',user:'build',action:'checkout'},null,'Normal source checkout for scheduled pipeline.'),
   T('l12','Logs','10:17:10','API-03',{'user.dst':'svc_reports','ip.src':'10.33.5.22',action:'object-reconciliation',service:'api'},'l10','18,420 distinct existing customer objects observed in server audit; content exposure still under investigation.')
  ],
  questions:[
   {id:'identity',question:'Does successful token authentication prove these requests were authorized?',options:['Yes, every valid token action is authorized','No; origin, volume, and owner context can show abuse of valid credentials','Only if HTTPS is enabled','Only if the token is expired'],correct:1,requires:['l1','l2'],reason:'A valid credential can be misused from an unauthorized workload.'},
   {id:'origin',question:'What is the strongest evidence of the suspected origin?',options:['An unrelated CDN connection','Build agent secret access and suspicious process ancestry','API traffic volume alone','Customer complaints'],correct:1,requires:['l4','l8'],reason:'The build-agent process chain provides a plausible acquisition path for the token.'},
   {id:'loss',question:'What can you report as confirmed from these records?',options:['All 27,440 queried customers had their data stolen','520 MB definitively contains customer PII','Correlated API export events and decrypted HTTP batch receipt confirm the customer export activity','No exposure because the API returned 200'],correct:2,requires:['l5','l3'],reason:'API logs identify distinct records and decoded outbound HTTP confirms the exported batch was accepted.'}
  ]
 },
 valve:{
  starter:"user.dst = 'ot_contractor'",
  tips:["user.dst = 'ot_contractor'","ip.src = '10.20.8.17'","service = 'rdp'","host = 'OT-JUMP-01'","service = 'modbus'"],
  rows:[
   T('v01','Logs','20:51:01','VPN-GW',{'user.dst':'plant_engineer','ip.src':'203.0.113.10',action:'vpn-denied',service:'vpn'},null,'Routine failed remote login; no connection established.'),
   T('v02','Logs','21:07:11','VPN-GW',{'user.dst':'ot_contractor','ip.src':'203.0.113.44',action:'vpn-success',service:'vpn'},'v1','Successful contractor VPN outside approved maintenance window.'),
   T('v03','Logs','21:09:31','OT-JUMP-01',{'user.dst':'ot_contractor','ip.src':'10.20.8.17','ip.dst':'10.90.10.15',action:'rdp-success',service:'rdp','tcp.dstport':3389},'v1','Jump host authentication linked to originating IT-WS-17.'),
   T('v04','Logs','21:10:03','VPN-GW',{'user.dst':'plant_service','ip.src':'10.90.10.15',action:'heartbeat',service:'vpn'},null,'Normal OT gateway heartbeat.'),
   T('v05','Network','21:09:40','IT-WS-17',{'ip.src':'10.20.8.17','ip.dst':'10.90.10.15',service:'rdp','tcp.dstport':3389,'bytes.out':620000},'v2','Unexpected IT-to-OT jump-host session.'),
   T('v06','Network','21:10:12','OT-JUMP-01',{'ip.src':'10.90.10.15','ip.dst':'10.90.20.21',service:'modbus','tcp.dstport':502,'bytes.out':12640},'v2','New industrial supervisory-zone flow.'),
   T('v07','Network','21:11:20','HIST-01',{'ip.src':'10.90.20.31','ip.dst':'10.90.20.21',service:'modbus','tcp.dstport':502,'bytes.out':1200},null,'Expected read-only historian polling relationship.'),
   T('v08','Network','21:12:18','OT-JUMP-01',{'ip.src':'10.90.10.15','ip.dst':'10.90.20.21',service:'modbus','tcp.dstport':502,'bytes.out':3400,action:'baseline-anomaly'},'v5','This source-to-controller communication is absent from normal baseline.'),
   T('v09','Network','21:14:22','SCADA-01',{'ip.src':'10.90.10.15','ip.dst':'10.90.20.21',service:'modbus','tcp.dstport':502,action:'function-06'},'v7','Decoded Modbus function 06 request and accepted response; operator trend checks confirm stable physical conditions.'),
   T('v10','Endpoint','21:08:39','IT-WS-17',{'ip.src':'10.20.8.17',process:'mstsc.exe',parent:'remote-support.exe',user:'ot_contractor',action:'process-start'},'v3','Remote support launcher initiated RDP.'),
   T('v11','Endpoint','21:11:03','OT-JUMP-01',{'ip.src':'10.90.10.15',process:'engineering-client.exe',parent:'explorer.exe',user:'ot_contractor',action:'process-start'},'v4','Engineering software started outside approved change window.'),
   T('v12','Endpoint','21:12:10','OT-JUMP-01',{'ip.src':'10.90.10.15',process:'historian-reader.exe',parent:'services.exe',user:'SYSTEM',action:'process-start'},null,'Expected historian agent startup.')
  ],
  questions:[
   {id:'authorization',question:'What supports the conclusion that remote access was unauthorized?',options:['RDP is always malicious','The VPN log alone proves malicious intent','The access chain and independently verified absence of an approved work order','A single packet-size anomaly'],correct:2,requires:['v1','v6'],reason:'Identity activity needs maintenance and operator-context validation.'},
   {id:'boundary',question:'What indicates a possible IT-to-OT pivot?',options:['New RDP to the jump host followed by industrial-zone traffic','A normal historian polling relationship','A failed VPN login','A single endpoint antivirus event'],correct:0,requires:['v2','v5'],reason:'The correlated path crosses an industrial boundary and departs from baseline.'},
   {id:'safety',question:'Can the packet decoder alone prove a physical plant state change?',options:['Yes, Modbus function 06 always changes a valve','No, physical impact requires operational/controller verification','Yes, because the source is a jump host','No, because industrial protocols are always encrypted'],correct:1,requires:['v7','v8'],reason:'A decoded write-like request does not establish a committed process change.'}
  ]
 }
};


INVESTIGATION_DATA.webshell={
 starter:"service = 'http'",tips:["service = 'http'","alias.host = 'portal.internal.example'","parent = 'php-fpm'","host = 'WEB-01'","ip.dst = '203.0.113.92'"],
 rows:[
 T('w01','Network','14:10:12','WAF-01',{'ip.src':'198.51.100.81','ip.dst':'10.60.2.11',service:'http','tcp.dstport':8080,'alias.host':'portal.internal.example',action:'suspicious-post'},'w1','HTTP POST to hidden PHP endpoint; reconstructed response available.'),
 T('w02','Logs','14:09:52','WEB-01',{'ip.src':'10.60.2.11',service:'file-integrity',action:'unexpected-php'},'w2','File-integrity alert: new executable PHP in writable uploads directory.'),
 T('w03','Endpoint','14:10:18','WEB-01',{process:'sh',parent:'php-fpm',user:'www-data',action:'process-start'},'w3','php-fpm child shell with a short command line.'),
 T('w04','Network','14:11:20','WAF-01',{'ip.src':'198.51.100.81','ip.dst':'10.60.2.11',service:'http','tcp.dstport':8080,'alias.host':'portal.internal.example',action:'directory-list'},'w4','Second POST returns application export listing.'),
 T('w05','Endpoint','14:13:03','WEB-01',{process:'tar',parent:'sh',user:'www-data',action:'archive-create'},'w5','Archive created from application exports.'),
 T('w06','Network','14:14:42','WAF-01',{'ip.src':'10.60.2.11','ip.dst':'203.0.113.92',service:'http','tcp.dstport':8080,'bytes.out':14723000,action:'upload'},'w6','Outbound HTTP upload and server receipt reconstructed.'),
 T('w07','Logs','14:10:18','WEB-01',{'ip.src':'198.51.100.81',service:'http',action:'webshell-request','event.id':200},'w7','Access event for PHP path with HTTP status and request correlation.'),
 T('w08','Logs','14:01:00','WEB-01',{'ip.src':'198.51.100.12',service:'http',action:'normal-request','event.id':200},null,'Normal request to public application.'),
 T('w09','Endpoint','14:06:29','WEB-01',{process:'php-fpm',parent:'systemd',user:'www-data',action:'process-start'},null,'Expected web worker process.'),
 T('w10','Network','14:07:05','WAF-01',{'ip.src':'203.0.113.10','ip.dst':'10.60.2.11',service:'http','tcp.dstport':8080,'alias.host':'portal.internal.example',action:'normal-request'},null,'Normal health check traffic.')
 ],
 questions:[
  {id:'path',question:'Which artifact establishes remote command execution via HTTP?',options:['Normal web GET request','POST command parameter, returned output, and matching php-fpm child shell','Only a file hash','A firewall permit event'],correct:1,requires:['w1','w3'],reason:'The HTTP POST, its response, and matching process tree establish command execution.'},
  {id:'source',question:'What indicates webshell persistence in an upload directory?',options:['New PHP file under /uploads plus matching requests','Routine php-fpm startup','DNS TTL value','Backend database query volume'],correct:0,requires:['w2','w7'],reason:'File integrity and HTTP access corroborate the abnormal PHP upload.'},
  {id:'loss',question:'What evidence identifies the exported data and proves transfer?',options:['Any outbound port 8080 session','Only the HTTP User-Agent','Archive process and decoded HTTP upload with a server receipt','The web application uptime metric'],correct:2,requires:['w5','w6'],reason:'Archive creation and a successful reconstructed HTTP upload identify the file and confirmed receipt.'}
 ]
};
