const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const os=require('os');
const path=require('path');
const bcrypt=require('bcryptjs');

function freshEnv(dir){
  process.env.NODE_ENV='test';
  process.env.DATA_DIR=dir;
  process.env.JWT_SECRET='test-secret';
  process.env.INGEST_API_KEY='test-ingest-key';
  process.env.ADMIN_USER='admin';
  process.env.ADMIN_PASSWORD_HASH=bcrypt.hashSync('password',4);
  delete process.env.DATABASE_URL;
  for(const key of ['../config','../storage','../security']){try{delete require.cache[require.resolve(key)]}catch{}}
}
function makeStore(){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-'));
  freshEnv(dir);
  return {store:require('../storage'),security:require('../security'),dir};
}

test('sqlite storage persists and queries events',()=>{
  const {store}=makeStore();
  const now=new Date().toISOString();
  store.addEvents([
    {id:'t1',timestamp:now,severity:'HIGH',category:'ssh',source_ip:'10.0.0.1',message:'failed login',hostname:'host-a'},
    {id:'t2',timestamp:now,severity:'INFO',category:'system',source_ip:'10.0.0.2',message:'boot',hostname:'host-b'}
  ]);
  assert.equal(store.getEvents({search:'failed',limit:10,offset:0}).total,1);
  assert.equal(store.getEvents({severity:'INFO',limit:10,offset:0}).events[0].id,'t2');
  assert.equal(store.getStats().totalEvents,2);
  store.db.close();
});

test('authentication accepts correct credentials and rejects incorrect ones',()=>{
  const {security,store}=makeStore();
  assert.deepEqual(security.login('admin','password'),{id:1,username:'admin',role:'admin'});
  assert.equal(security.login('admin','wrong'),null);
  assert.equal(security.login('other','password'),null);
  store.db.close();
});

test('session token verifies with the expected issuer',()=>{
  const {security,store}=makeStore();
  const user={id:1,username:'admin',role:'admin'};
  const jwt=security.token(user);
  assert.deepEqual(security.verifyToken(jwt).username,'admin');
  assert.throws(()=>security.verifyToken(jwt+'.tampered'));
  store.db.close();
});

test('production environment validation rejects weak secrets',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-'));
  process.env.NODE_ENV='production';
  process.env.DATA_DIR=dir;
  process.env.JWT_SECRET='short';
  process.env.INGEST_API_KEY='short';
  process.env.METRICS_API_KEY='valid-metrics-key-0123456789';
  process.env.ADMIN_PASSWORD_HASH=bcrypt.hashSync('password',4);
  process.env.DATABASE_URL='postgresql://validation@example.invalid/db';
  delete require.cache[require.resolve('../config')];
  assert.throws(()=>require('../config'),/at least 32 characters/);
  process.env.NODE_ENV='test';
});

test('production environment validation rejects missing or weak metrics key',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-'));
  process.env.NODE_ENV='production';
  process.env.DATA_DIR=dir;
  process.env.JWT_SECRET='this-is-a-valid-jwt-secret-0123456789';
  process.env.INGEST_API_KEY='valid-ingest-key-0123456789';
  process.env.ADMIN_PASSWORD_HASH=bcrypt.hashSync('password',4);
  process.env.DATABASE_URL='postgresql://validation@example.invalid/db';
  delete process.env.METRICS_API_KEY;
  delete require.cache[require.resolve('../config')];
  assert.throws(()=>require('../config'),/Missing required environment variable: METRICS_API_KEY/);
  process.env.METRICS_API_KEY='short';
  delete require.cache[require.resolve('../config')];
  assert.throws(()=>require('../config'),/METRICS_API_KEY must be at least 20 characters/);
  process.env.NODE_ENV='test';
});

test('detection creates an alert after repeated failed authentication events',()=>{
  const detection=require('../detection');
  const now=Date.now();
  const events=Array.from({length:5},(_,i)=>({
    id:'e'+i,timestamp:new Date(now-i*30000).toISOString(),severity:'HIGH',
    category:'ssh',source_ip:'10.0.0.9',message:'failed authentication',hostname:'host'
  }));
  const alert=detection.evaluate(events[0],events);
  assert.equal(alert.severity,'CRITICAL');
  assert.match(alert.title,/brute-force/i);
  assert.equal(alert.source_ip,'10.0.0.9');
});

test('detection ignores unrelated low-severity events',()=>{
  const detection=require('../detection');
  const event={id:'x',timestamp:new Date().toISOString(),severity:'LOW',category:'system',source_ip:'10.0.0.1',message:'failed authentication',hostname:'host'};
  assert.equal(detection.evaluate(event,[event]),null);
});