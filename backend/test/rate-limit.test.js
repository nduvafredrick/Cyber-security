const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const os=require('os');
const path=require('path');
const bcrypt=require('bcryptjs');

let server;
let dataDir;

async function startTestServer(){
  dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-rate-limit-'));
  process.env.NODE_ENV='test';
  process.env.PORT='0';
  process.env.DATA_DIR=dataDir;
  process.env.JWT_SECRET='rate-limit-test-secret';
  process.env.INGEST_API_KEY='rate-limit-test-ingest-key';
  process.env.ADMIN_USER='admin';
  process.env.ADMIN_PASSWORD_HASH=bcrypt.hashSync('password',4);
  process.env.INGEST_RATE_LIMIT_PER_MINUTE='2';
  process.env.BULK_INGEST_RATE_LIMIT_PER_MINUTE='2';
  for(const key of ['../config','../storage','../security','../server']){
    try{delete require.cache[require.resolve(key)]}catch{}
  }
  const app=require('../server');
  server=app.startServer();
  await new Promise(resolve=>server.once('listening',resolve));
}

test.beforeEach(async()=>{await startTestServer();});
test.afterEach(async()=>{if(server)await new Promise(resolve=>server.close(resolve));server=null;});

test('event ingestion returns 429 after the configured per-client limit',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const body=JSON.stringify({severity:'INFO',category:'system',source_ip:'10.9.9.1',message:'rate-limit-test'});
  for(let i=0;i<2;i++){
    const response=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':'rate-limit-test-ingest-key'},body});
    assert.equal(response.status,201);
  }
  const limited=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':'rate-limit-test-ingest-key'},body});
  assert.equal(limited.status,429);
  assert.match(limited.headers.get('retry-after')||'',/^\d+$/);
  assert.equal((await limited.json()).error,'Ingestion rate limit exceeded');
});

test('bulk ingestion has a separate per-client limit',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const body=JSON.stringify([{severity:'INFO',category:'system',source_ip:'10.9.9.2',message:'bulk-rate-limit-test'}]);
  for(let i=0;i<2;i++){
    const response=await fetch(base+'/api/ingest/bulk',{method:'POST',headers:{'content-type':'application/json','x-api-key':'rate-limit-test-ingest-key'},body});
    assert.equal(response.status,201);
  }
  const limited=await fetch(base+'/api/ingest/bulk',{method:'POST',headers:{'content-type':'application/json','x-api-key':'rate-limit-test-ingest-key'},body});
  assert.equal(limited.status,429);
  assert.match(limited.headers.get('retry-after')||'',/^\d+$/);
  assert.equal((await limited.json()).error,'Bulk ingestion rate limit exceeded');
});

test('failed authentication does not consume a valid client quota',async()=>{
  const base='http://127.0.0.1:'+server.address().port;
  const body=JSON.stringify({severity:'INFO',category:'system',source_ip:'10.9.9.3',message:'auth-first-test'});
  for(let i=0;i<5;i++){
    const bad=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':'wrong-key-'+i},body});
    assert.equal(bad.status,401);
  }
  const fresh=await fetch(base+'/api/ingest/event',{method:'POST',headers:{'content-type':'application/json','x-api-key':'rate-limit-test-ingest-key'},body});
  assert.equal(fresh.status,201);
});
