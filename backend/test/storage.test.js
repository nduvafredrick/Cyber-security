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
    {id:'t1',organization_id:store.DEFAULT_ORGANIZATION_ID,timestamp:now,severity:'HIGH',category:'ssh',source_ip:'10.0.0.1',message:'failed login',hostname:'host-a'},
    {id:'t2',organization_id:store.DEFAULT_ORGANIZATION_ID,timestamp:now,severity:'INFO',category:'system',source_ip:'10.0.0.2',message:'boot',hostname:'host-b'}
  ]);
  const organizationId=store.DEFAULT_ORGANIZATION_ID;
  assert.equal(store.getEvents({organization_id:organizationId,search:'failed',limit:10,offset:0}).total,1);
  assert.equal(store.getEvents({organization_id:organizationId,severity:'INFO',limit:10,offset:0}).events[0].id,'t2');
  assert.equal(store.getStats(organizationId).totalEvents,2);
  store.db.close();
});

test('authentication accepts correct credentials and rejects incorrect ones',()=>{
  const {security,store}=makeStore();
  assert.deepEqual(security.login('admin','password'),{id:1,organization_id:store.DEFAULT_ORGANIZATION_ID,username:'admin',email:null,role:'admin'});
  assert.equal(security.login('admin','wrong'),null);
  assert.equal(security.login('other','password'),null);
  store.db.close();
});

test('session token verifies with the expected issuer',()=>{
  const {security,store}=makeStore();
  const user={id:1,organization_id:store.DEFAULT_ORGANIZATION_ID,username:'admin',role:'admin'};
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
test('legacy SQLite data migrates into the default organization',()=>{
  const Database=require('better-sqlite3');
  const {DEFAULT_ORGANIZATION_ID,runSqliteMigrations}=require('../migrations');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sentinel-migration-'));
  const dbPath=path.join(dir,'sentinel.db');
  const db=new Database(dbPath);
  db.exec(`
    CREATE TABLE events (
      id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, severity TEXT NOT NULL,
      category TEXT NOT NULL, source_ip TEXT NOT NULL, message TEXT NOT NULL, hostname TEXT NOT NULL
    );
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','analyst')), enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE detection_rules (
      rule_key TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
      window_ms INTEGER NOT NULL, threshold INTEGER NOT NULL, severities TEXT NOT NULL, categories TEXT NOT NULL,
      message_pattern TEXT NOT NULL, alert_severity TEXT NOT NULL, title TEXT NOT NULL, updated_at TEXT NOT NULL,
      updated_by TEXT NOT NULL
    );
  `);
  db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?)').run('legacy-event','2026-01-01T00:00:00.000Z','INFO','system','10.0.0.1','legacy event','legacy-host');
  db.prepare('INSERT INTO users(username,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)').run('legacy-admin','hash','admin',1,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z');
  db.prepare('INSERT INTO detection_rules VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run('legacy-rule','Legacy rule','Migrated rule',1,300000,5,'["HIGH"]','["ssh"]','/failed/i','HIGH','Legacy rule','2026-01-01T00:00:00.000Z','system');
  runSqliteMigrations(db);
  assert.equal(db.prepare('SELECT name FROM organizations WHERE id=?').get(DEFAULT_ORGANIZATION_ID).name,'Default Organization');
  assert.equal(db.prepare('SELECT organization_id FROM events WHERE id=?').get('legacy-event').organization_id,DEFAULT_ORGANIZATION_ID);
  assert.equal(db.prepare('SELECT organization_id FROM users WHERE username=?').get('legacy-admin').organization_id,DEFAULT_ORGANIZATION_ID);
  assert.equal(db.prepare('SELECT organization_id FROM detection_rules WHERE rule_key=?').get('legacy-rule').organization_id,DEFAULT_ORGANIZATION_ID);
  assert.deepEqual(db.prepare('SELECT version FROM _schema_migrations ORDER BY version').all().map(x=>x.version),[1,2,3,4]);
  db.close();
});

test('SQLite organization provisioning creates the administrator and connector atomically',()=>{
  const {store}=makeStore();
  const passwordHash=bcrypt.hashSync('long-onboarding-password',4);
  const result=store.provisionOrganization({
    id:'org-provision-test',
    name:'Provisioned Company',
    slug:'provisioned-company',
    industry:'Technology',
    company_size:'11-50',
    email:'owner@provisioned.example',
    password_hash:passwordHash,
    connector_id:'connector-provision-test',
    connector_name:'Production API',
    environment:'Production',
    key_hash:'hash-provision-test',
    key_raw:'sk_provision-test'
  });
  assert.equal(result.organization.id,'org-provision-test');
  assert.equal(result.user.email,'owner@provisioned.example');
  assert.equal(result.connector.environment,'Production');
  assert.equal(store.getIngestKeys('org-provision-test')[0].organization_id,'org-provision-test');
  assert.equal(store.listRules('org-provision-test').length,1);
  assert.equal(store.getAudit('org-provision-test')[0].action,'ORGANIZATION_CREATED');
  store.db.close();
});

test('SQLite integration provisioning binds the connector to one organization',()=>{
  const {store}=makeStore();
  const result=store.createIntegrationWithKey({
    id:'integration-test',
    organization_id:store.DEFAULT_ORGANIZATION_ID,
    name:'Test Sentinel Agent',
    type:'agent',
    environment:'Production',
    key_id:'integration-key-test',
    key_raw:'sk_integration-test',
    created_by:'admin'
  });
  assert.equal(result.integration.organization_id,store.DEFAULT_ORGANIZATION_ID);
  assert.equal(result.integration.type,'agent');
  assert.equal(result.key.key_id,'integration-key-test');
  assert.equal(store.listIntegrations(store.DEFAULT_ORGANIZATION_ID).length,1);
  assert.equal(store.getIntegration('integration-test',store.DEFAULT_ORGANIZATION_ID).name,'Test Sentinel Agent');
  store.db.close();
});
