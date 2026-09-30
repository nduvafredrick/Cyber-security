const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const os=require('os');
const path=require('path');
const bcrypt=require('bcryptjs');

let server;
test.before(async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-api-'));
  process.env.NODE_ENV='test';
  process.env.PORT='0';
  process.env.DATA_DIR=dir;
  process.env.JWT_SECRET='api-test-secret';
  process.env.INGEST_API_KEY='api-test-ingest-key';
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
  const response=await fetch(base+'/metrics');
  assert.equal(response.status,200);
  const body=await response.text();
  assert.match(body,/sentinel_http_requests_total \\d+/);
  assert.match(body,/sentinel_events_ingested_total \\d+/);
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
  const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'password'})});
  const cookie=login.headers.get('set-cookie');
  const events=Array.from({length:5},(_,i)=>({
    severity:'HIGH',category:'ssh',source_ip:'10.1.1.10',message:'failed authentication',hostname:'bulk-host-'+i
  }));
  const bulk=await fetch(base+'/api/ingest/bulk',{method:'POST',headers:{'content-type':'application/json','x-api-key':'api-test-ingest-key'},body:JSON.stringify(events)});
  assert.equal(bulk.status,201);
  const result=await bulk.json();
  assert.equal(result.count,5);
  assert.equal(result.alerts,1);
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
});

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
