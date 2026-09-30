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