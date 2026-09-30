const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const os=require('os');
const path=require('path');

test('sqlite storage persists and queries events',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-'));
  const previous=process.env.DATA_DIR;process.env.DATA_DIR=dir;process.env.NODE_ENV='test';
  for(const key of ['backend/config','backend/storage'])delete require.cache[require.resolve('../../'+key)];
  const store=require('../storage');
  const events=[
    {id:'t1',timestamp:new Date().toISOString(),severity:'HIGH',category:'ssh',source_ip:'10.0.0.1',message:'failed login',hostname:'host-a'},
    {id:'t2',timestamp:new Date().toISOString(),severity:'INFO',category:'system',source_ip:'10.0.0.2',message:'boot',hostname:'host-b'}
  ];
  store.addEvents(events);
  assert.equal(store.getEvents({search:'failed',limit:10,offset:0}).total,1);
  assert.equal(store.getEvents({severity:'INFO',limit:10,offset:0}).events[0].id,'t2');
  assert.equal(store.getStats().totalEvents,2);
  store.db.close();
  if(previous===undefined)delete process.env.DATA_DIR;else process.env.DATA_DIR=previous;
});

test('environment validation rejects weak production secrets',()=>{
  const previous={NODE_ENV:process.env.NODE_ENV,JWT_SECRET:process.env.JWT_SECRET,INGEST_API_KEY:process.env.INGEST_API_KEY,ADMIN_PASSWORD_HASH:process.env.ADMIN_PASSWORD_HASH};
  process.env.NODE_ENV='production';process.env.JWT_SECRET='short';process.env.INGEST_API_KEY='short';process.env.ADMIN_PASSWORD_HASH='hash';
  delete require.cache[require.resolve('../config')];
  assert.throws(()=>require('../config'),/at least 32 characters/);
  Object.assign(process.env,previous);
  delete require.cache[require.resolve('../config')];
});