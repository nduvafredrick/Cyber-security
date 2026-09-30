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
