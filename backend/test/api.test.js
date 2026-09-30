const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const os=require('os');
const path=require('path');\nconst crypto=require('crypto');
const bcrypt=require('bcryptjs');

let server;
test.before(async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-api-'));
  process.env.NODE_ENV='test';
  process.env.PORT='0';
  process.env.DATA_DIR=dir;
  process.env.JWT_SECRET='api-test-secret';
  process.env.INGEST_API_KEY='api-test-ingest-key';
  process.env.INGEST_RATE_LIMIT_PER_MINUTE='300';
  process.env.BULK_INGEST_RATE_LIMIT_PER_MINUTE='60';
  process.env.ADMIN_USER='admin';
  process.env.ADMIN_PASSWORD_HASH=bcrypt.hashSync('password',4);
  for(const key of ['../config','../storage','../security','../server']){try{delete require.cache[require.resolve(key)]}catch{}}
  const app=require('../server');
  server=app.startServer();
  await new Promise(resolve=>server.once('listening',resolve));
});
test.after(async()=>{if(server)await new Promise(resolve=>server.close(resolve));});

test('metrics expose operational counters',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const health=await fetch(base+'/health');
  assert.equal(health.status,200);
  const response=await fetch(base+'/metrics');
  assert.equal(response.status,200);
  const body=await response.text();
  assert.match(body,/sentinel_http_requests_total \d+/);
  assert.match(body,/sentinel_events_ingested_total \d+/);
});

test('responses include a unique request id',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const response=await fetch(base+'/health');
  assert.equal(response.status,200);
  assert.match(response.headers.get('x-request-id')||'',/^[0-9a-f-]{36}$/);
});

test('same-origin requests work while foreign origins are rejected',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const same=await fetch(base+'/health',{headers:{Origin:base}});
  assert.equal(same.status,200);
  assert.equal(same.headers.get('access-control-allow-origin'),base);
  const foreign=await fetch(base+'/health',{headers:{Origin:'https://evil.example'}});
  assert.equal(foreign.status,403);
  assert.equal((await foreign.json()).error,'Origin not allowed');
});

test('login returns a session cookie and authenticated API access works',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  assert.equal(login.status,200);
  const cookie=login.headers.get('set-cookie');
  assert.match(cookie,/sentinel_session=/);
  const me=await fetch(base+'/api/auth/me',{headers:{cookie}});
  assert.equal(me.status,200);
  assert.equal((await me.json()).user.username,'admin');
});

test('ingest endpoint accepts API key and event appears in filtered API results',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  const cookie=login.headers.get('set-cookie');
  const ingest=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':'api-test-ingest-key'},body:JSON.stringify({severity:'HIGH',category:'ssh',source_ip:'10.1.1.9',message:'failed authentication',hostname:'test-host'})});
  assert.equal(ingest.status,201);
  const events=await fetch(base+'/api/events?search=10.1.1.9&limit=10',{headers:{cookie}});
  assert.equal(events.status,200);
  const data=await events.json();
  assert.equal(data.total,1);
  assert.equal(data.events[0].source_ip,'10.1.1.9');
  const bad=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':'wrong'},body:'{}'});
  assert.equal(bad.status,401);
});

test('bulk ingest accepts up to 1000 events and returns created alerts',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const before=await fetch(base+'/metrics');
  const beforeBody=await before.text();
  const events=Array.from({length:5},(_,i)=>({
    severity:'HIGH',category:'ssh',source_ip:'10.1.1.10',message:'failed authentication',hostname:'bulk-host-'+i
  }));
  const bulk=await fetch(base+'/api/ingest/bulk',{method:'POST',headers:{'content-type':'application/json','x-api-key':'api-test-ingest-key'},body:JSON.stringify(events)});
  assert.equal(bulk.status,201);
  const result=await bulk.json();
  assert.equal(result.count,5);
  assert.equal(result.alerts,1);
  const after=await fetch(base+'/metrics');
  const afterBody=await after.text();
  const eventCount=(body)=>Number(body.match(/sentinel_events_ingested_total (\d+)/)?.[1]);
  const alertCount=(body)=>Number(body.match(/sentinel_alerts_created_total (\d+)/)?.[1]);
  assert.equal(eventCount(afterBody)-eventCount(beforeBody),5);
  assert.equal(alertCount(afterBody)-alertCount(beforeBody),1);
  const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  const cookie=login.headers.get('set-cookie');
  const alerts=await fetch(base+'/api/alerts',{headers:{cookie}});
  const data=await alerts.json();
  assert.equal(data.alerts.filter((a)=>a.source_ip==='10.1.1.10').length,1);

  const repeat=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':'api-test-ingest-key'},body:JSON.stringify({severity:'HIGH',category:'ssh',source_ip:'10.1.1.10',message:'failed authentication',hostname:'bulk-host'})});
  assert.equal(repeat.status,201);
  assert.equal((await repeat.json()).alert,null);
});

test('authenticated WebSocket receives subscribed live events',async()=>{
  const WebSocket=require('ws');
  const base='http://127.0.0.1:'+server.address().port;
  const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  const cookie=login.headers.get('set-cookie');
  const ws=new WebSocket(base.replace('http','ws')+'/ws',{headers:{Cookie:cookie}});
  await new Promise((resolve,reject)=>{ws.once('open',resolve);ws.once('error',reject)});
  ws.send(JSON.stringify({type:'subscribe',severity:'HIGH',search:'websocket-test'}));
  const received=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('WebSocket event timeout')),2000);
    ws.on('message',(raw)=>{
      const msg=JSON.parse(raw.toString());
      if(msg.type==='event'){clearTimeout(timer);resolve(msg.event)}
    });
  });
  const ingest=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':'api-test-ingest-key'},body:JSON.stringify({severity:'HIGH',category:'system',source_ip:'10.1.1.20',message:'websocket-test event',hostname:'ws-host'})});
  assert.equal(ingest.status,201);
  const event=await received;
  assert.equal(event.message,'websocket-test event');
  ws.close();
});

test('admin can create an analyst and manage rotatable ingest keys',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  const cookie=login.headers.get('set-cookie');
  const user=await fetch(base+'/api/admin/users',{method:'POST',headers:{'content-type':'application/json',cookie},body:JSON.stringify({username:'analyst1',password:'long-test-password-123',role:'analyst'})});
  assert.equal(user.status,201);
  const listed=await fetch(base+'/api/admin/users',{headers:{cookie}});
  assert.equal((await listed.json()).users.some(x=>x.username==='analyst1'&&x.role==='analyst'),true);
  const rotated=await fetch(base+'/api/admin/ingest-keys/rotate',{method:'POST',headers:{'content-type':'application/json',cookie},body:JSON.stringify({name:'ci-rotated'})});
  assert.equal(rotated.status,201);
  const key=(await rotated.json()).key;
  const ingest=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':key},body:JSON.stringify({severity:'INFO',category:'system',source_ip:'10.1.1.30',message:'rotated key works'})});
  assert.equal(ingest.status,201);
  const keys=await fetch(base+'/api/admin/ingest-keys',{headers:{cookie}});
  const record=(await keys.json()).keys.find(x=>x.name==='ci-rotated');
  assert.ok(record?.last_used_at);
});

test('admin can create and rotate one connector without disabling another',async()=>{const base='http://127.0.0.1:'+server.address().port;const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});const cookie=login.headers.get('set-cookie');const first=await fetch(base+'/api/admin/ingest-keys',{method:'POST',headers:{'content-type':'application/json',cookie},body:JSON.stringify({name:'connector-a'})});assert.equal(first.status,201);const firstData=await first.json();const second=await fetch(base+'/api/admin/ingest-keys',{method:'POST',headers:{'content-type':'application/json',cookie},body:JSON.stringify({name:'connector-b'})});assert.equal(second.status,201);const secondData=await second.json();const rotated=await fetch(base+'/api/admin/ingest-keys/'+firstData.record.id+'/rotate',{method:'POST',headers:{'content-type':'application/json',cookie},body:JSON.stringify({name:'connector-a'})});assert.equal(rotated.status,201);const keys=await fetch(base+'/api/admin/ingest-keys',{headers:{cookie}});const listed=(await keys.json()).keys;assert.equal(listed.find(x=>x.id===firstData.record.id)?.enabled,0);assert.equal(listed.find(x=>x.id===secondData.record.id)?.enabled,1);assert.equal(listed.filter(x=>x.name==='connector-a'&&x.enabled).length,1);});
test('analyst sessions cannot change alert status',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const adminLogin=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  const adminCookie=adminLogin.headers.get('set-cookie');
  await fetch(base+'/api/admin/users',{method:'POST',headers:{'content-type':'application/json',cookie:adminCookie},body:JSON.stringify({username:'analyst2',password:'long-test-password-456',role:'analyst'})});
  const analystLogin=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'analyst2',password:'long-test-password-456'})});
  const analystCookie=analystLogin.headers.get('set-cookie');
  const denied=await fetch(base+'/api/alerts/nonexistent',{method:'PATCH',headers:{'content-type':'application/json',cookie:analystCookie},body:JSON.stringify({status:'RESOLVED'})});
  assert.equal(denied.status,403);
});

test('admin can update a persistent detection rule',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  const cookie=login.headers.get('set-cookie');
  const update=await fetch(base+'/api/admin/detection-rules/auth-bruteforce-v1',{method:'PUT',headers:{'content-type':'application/json',cookie},body:JSON.stringify({name:'SSH authentication burst',description:'Configurable test rule',enabled:true,window_ms:300000,threshold:3,severities:['HIGH','CRITICAL'],categories:['ssh'],message_pattern:'/failed|invalid/i',alert_severity:'CRITICAL',title:'Authentication burst detected'})});
  assert.equal(update.status,200);
  const rules=await fetch(base+'/api/admin/detection-rules',{headers:{cookie}});
  const rule=(await rules.json()).rules.find(x=>x.rule_key==='auth-bruteforce-v1');
  assert.equal(rule.threshold,3);
  assert.equal(rule.enabled,true);
});

test('detection rule preserves regex flags for capitalized OpenSSH messages',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  const cookie=login.headers.get('set-cookie');
  const update=await fetch(base+'/api/admin/detection-rules/auth-bruteforce-v1',{method:'PUT',headers:{'content-type':'application/json',cookie},body:JSON.stringify({name:'SSH authentication burst',description:'Case-insensitive authentication failures',enabled:true,window_ms:300000,threshold:3,severities:['HIGH','CRITICAL'],categories:['ssh'],message_pattern:'/failed|invalid|denied/i',alert_severity:'CRITICAL',title:'Authentication burst detected'})});
  assert.equal(update.status,200);
  const rotated=await fetch(base+'/api/admin/ingest-keys/rotate',{method:'POST',headers:{'content-type':'application/json',cookie},body:JSON.stringify({name:'regex-test-key'})});
  assert.equal(rotated.status,201);
  const ingestKey=(await rotated.json()).key;
  for(let i=0;i<3;i++){
    const response=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':ingestKey},body:JSON.stringify({severity:'HIGH',category:'ssh',source_ip:'10.2.2.2',message:'Failed password for root',hostname:'openssh-test'})});
    assert.equal(response.status,201);
    if(i<2)assert.equal((await response.json()).alert,null);
    else assert.equal((await response.json()).alert?.severity,'CRITICAL');
  }
});
test('isolates events, alerts, rules, audit records, users, and ingest keys between organizations',async()=>{
  const store=require('../storage');
  const security=require('../security');
  const base='http://127.0.0.1:'+server.address().port;
  const suffix=Date.now().toString(36);
  const organizationA=await store.createOrganization({id:'org-a-'+suffix,name:'Company A',slug:'company-a-'+suffix});
  const organizationB=await store.createOrganization({id:'org-b-'+suffix,name:'Company B',slug:'company-b-'+suffix});
  const passwordHash=bcrypt.hashSync('long-test-password-123',4);
  const userAId=await store.addUser({username:'company-a-admin-'+suffix,password_hash:passwordHash,role:'admin',organization_id:organizationA.id});
  const userBId=await store.addUser({username:'company-b-admin-'+suffix,password_hash:passwordHash,role:'admin',organization_id:organizationB.id});
  const userA={id:userAId,username:'company-a-admin-'+suffix,role:'admin',organization_id:organizationA.id};
  const userB={id:userBId,username:'company-b-admin-'+suffix,role:'admin',organization_id:organizationB.id};
  const authA={authorization:'Bearer '+security.token(userA)};
  const authB={authorization:'Bearer '+security.token(userB)};
  const rawA=security.generateIngestKey();
  const rawB=security.generateIngestKey();
  const hash=(value)=>crypto.createHash('sha256').update(value).digest('hex');
  const keyA=await store.createIngestKey({id:'key-a-'+suffix,name:'Company A connector',raw:rawA,hash:hash(rawA),created_by:userA.username,organization_id:organizationA.id});
  const keyB=await store.createIngestKey({id:'key-b-'+suffix,name:'Company B connector',raw:rawB,hash:hash(rawB),created_by:userB.username,organization_id:organizationB.id});
  assert.equal(keyA.organization_id,organizationA.id);
  assert.equal(keyB.organization_id,organizationB.id);
  const ruleB=await store.upsertRule({
    rule_key:'company-b-rule',
    name:'Company B rule',
    description:'Tenant isolation test rule',
    enabled:true,
    window_ms:300000,
    threshold:99,
    severities:['HIGH'],
    categories:['ssh'],
    message_pattern:'/tenant-b/i',
    alert_severity:'HIGH',
    title:'Company B rule'
  },userB.username,organizationB.id);
  assert.equal(ruleB.organization_id,organizationB.id);
  const eventA=await fetch(base+'/api/ingest/event',{
    method:'POST',
    headers:{'content-type':'application/json','x-api-key':rawA},
    body:JSON.stringify({severity:'HIGH',category:'tenant-a',source_ip:'10.50.0.1',message:'tenant-a event',hostname:'company-a'})
  });
  const eventB=await fetch(base+'/api/ingest/event',{
    method:'POST',
    headers:{'content-type':'application/json','x-api-key':rawB},
    body:JSON.stringify({severity:'HIGH',category:'tenant-b',source_ip:'10.60.0.1',message:'tenant-b event',hostname:'company-b'})
  });
  assert.equal(eventA.status,201);
  assert.equal(eventB.status,201);

  const eventsA=await fetch(base+'/api/events?limit=100',{headers:authA});
  const eventsAData=await eventsA.json();
  const eventsB=await fetch(base+'/api/events?limit=100',{headers:authB});
  const eventsBData=await eventsB.json();
  assert.equal(eventsAData.events.some(e=>e.message==='tenant-a event'),true);
  assert.equal(eventsAData.events.some(e=>e.message==='tenant-b event'),false);
  assert.equal(eventsBData.events.some(e=>e.message==='tenant-b event'),true);
  assert.equal(eventsBData.events.some(e=>e.message==='tenant-a event'),false);

  const usersA=await fetch(base+'/api/admin/users',{headers:authA});
  const usersB=await fetch(base+'/api/admin/users',{headers:authB});
  assert.equal((await usersA.json()).users.some(u=>u.username===userB.username),false);
  assert.equal((await usersB.json()).users.some(u=>u.username===userA.username),false);

  const rulesA=await fetch(base+'/api/admin/detection-rules',{headers:authA});
  const rulesB=await fetch(base+'/api/admin/detection-rules',{headers:authB});
  assert.equal((await rulesA.json()).rules.some(r=>r.rule_key==='company-b-rule'),false);
  assert.equal((await rulesB.json()).rules.some(r=>r.rule_key==='company-b-rule'),true);

  const alertB={
    id:'alert-company-b-'+suffix,
    organization_id:organizationB.id,
    created_at:new Date().toISOString(),
    source_ip:'10.60.0.1',
    severity:'HIGH',
    status:'NEW',
    title:'Company B alert',
    description:'Tenant isolation test alert',
    count:1,
    updated_at:null,
    updated_by:null,
    rule_key:'company-b-rule'
  };
  await store.addAlert(alertB);
  const alertsA=await fetch(base+'/api/alerts',{headers:authA});
  const alertsAData=await alertsA.json();
  const alertsB=await fetch(base+'/api/alerts',{headers:authB});
  const alertsBData=await alertsB.json();
  assert.equal(alertsAData.alerts.some(a=>a.id===alertB.id),false);
  assert.equal(alertsBData.alerts.some(a=>a.id===alertB.id),true);
  const denied=await fetch(base+'/api/alerts/'+alertB.id,{
    method:'PATCH',
    headers:{...authA,'content-type':'application/json'},
    body:JSON.stringify({status:'RESOLVED'})
  });
  assert.equal(denied.status,404);
  const resolved=await fetch(base+'/api/alerts/'+alertB.id,{
    method:'PATCH',
    headers:{...authB,'content-type':'application/json'},
    body:JSON.stringify({status:'RESOLVED'})
  });
  assert.equal(resolved.status,200);

  const statsA=await fetch(base+'/api/stats/summary',{headers:authA});
  const statsB=await fetch(base+'/api/stats/summary',{headers:authB});
  assert.equal((await statsA.json()).totalEvents,1);
  assert.equal((await statsB.json()).totalEvents,1);

  const auditA=await fetch(base+'/api/audit',{headers:authA});
  const auditB=await fetch(base+'/api/audit',{headers:authB});
  assert.equal((await auditA.json()).audit.some(a=>a.actor===userB.username),false);
  assert.equal((await auditB.json()).audit.some(a=>a.actor===userA.username),false);

  const keysA=await fetch(base+'/api/admin/ingest-keys',{headers:authA});
  const keysB=await fetch(base+'/api/admin/ingest-keys',{headers:authB});
  assert.equal((await keysA.json()).keys.some(k=>k.id===keyB.id),false);
  assert.equal((await keysB.json()).keys.some(k=>k.id===keyA.id),false);
  const revokeCrossTenant=await fetch(base+'/api/admin/ingest-keys/'+keyB.id,{
    method:'DELETE',
    headers:authA
  });
  assert.equal(revokeCrossTenant.status,404);
});
