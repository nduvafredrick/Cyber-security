const {databaseUrl}=require('./config');
if(databaseUrl)module.exports=require('./storage-pg');
else {
const fs=require('fs');
const path=require('path');
const Database=require('better-sqlite3');
const crypto=require('crypto');
const {dataDir,retentionDays,adminUser,adminPasswordHash,ingestKey,dbBusyTimeoutMs}=require('./config');
const {
  DEFAULT_ORGANIZATION_ID,
  runSqliteMigrations
}=require('./migrations');

fs.mkdirSync(dataDir,{recursive:true});
const db=new Database(path.join(dataDir,'sentinel.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = '+dbBusyTimeoutMs);
runSqliteMigrations(db);

const now=()=>new Date().toISOString();

function readLegacy(name){
  try{return JSON.parse(fs.readFileSync(path.join(dataDir,name),'utf8'))}catch{return []}
}
function migrateLegacy(){
  if(db.prepare('SELECT COUNT(*) count FROM events').get().count===0){
    const legacy=readLegacy('events.json');
    const stmt=db.prepare("INSERT OR IGNORE INTO events(id,organization_id,timestamp,severity,category,event_type,source_ip,message,hostname,metadata,agent_id) VALUES (@id,@organization_id,@timestamp,@severity,@category,@event_type,@source_ip,@message,@hostname,@metadata,@agent_id)");
    const tx=db.transaction(items=>items.slice(-10000).forEach(e=>stmt.run({...e,organization_id:DEFAULT_ORGANIZATION_ID})));
    tx(legacy.map(e=>({...e,event_type:e.event_type||'generic',metadata:e.metadata||'{}'})));
  }
  if(db.prepare('SELECT COUNT(*) count FROM alerts').get().count===0){
    const stmt=db.prepare('INSERT OR IGNORE INTO alerts(id,organization_id,created_at,source_ip,severity,status,title,description,count,updated_at,updated_by,rule_key) VALUES (@id,@organization_id,@created_at,@source_ip,@severity,@status,@title,@description,@count,@updated_at,@updated_by,@rule_key)');
    const tx=db.transaction(items=>items.slice(-5000).forEach(a=>stmt.run({...a,organization_id:DEFAULT_ORGANIZATION_ID,updated_at:a.updated_at||null,updated_by:a.updated_by||null,rule_key:a.rule_key||null})));
    tx(readLegacy('alerts.json'));
  }
  if(db.prepare('SELECT COUNT(*) count FROM audit').get().count===0){
    const stmt=db.prepare('INSERT OR IGNORE INTO audit(id,organization_id,timestamp,action,actor,target,status) VALUES (@id,@organization_id,@timestamp,@action,@actor,@target,@status)');
    const tx=db.transaction(items=>items.slice(-5000).forEach(a=>stmt.run({...a,organization_id:DEFAULT_ORGANIZATION_ID,target:a.target||null,status:a.status||null})));
    tx(readLegacy('audit.json'));
  }
}
migrateLegacy();

if(db.prepare('SELECT COUNT(*) count FROM users').get().count===0 && adminPasswordHash){
  db.prepare('INSERT INTO users(organization_id,username,email,password_hash,role,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)').run(DEFAULT_ORGANIZATION_ID,adminUser,null,adminPasswordHash,'admin',1,now(),now());
}
if(db.prepare('SELECT COUNT(*) count FROM ingest_keys').get().count===0 && ingestKey){
  const hash=crypto.createHash('sha256').update(ingestKey).digest('hex');
  db.prepare('INSERT INTO ingest_keys(id,organization_id,name,key_hash,key_prefix,environment,enabled,created_at,last_used_at,created_by) VALUES (?,?,?,?,?,?,1,?,?,?)').run(crypto.randomUUID(),DEFAULT_ORGANIZATION_ID,'bootstrap',hash,ingestKey.slice(0,8),'Production',now(),null,adminUser);
}
function seedDefaultRule(organizationId){
  db.prepare('INSERT INTO detection_rules(organization_id,rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,rule_key) DO NOTHING').run(
    organizationId,'auth-bruteforce-v1','Authentication brute force','Repeated failed authentication attempts from one source.',1,300000,5,
    JSON.stringify(['HIGH','CRITICAL']),JSON.stringify(['ssh','login','authentication']),'/failed|invalid|denied/i','CRITICAL',
    'Possible brute-force authentication attack',now(),'system'
  );
}
if(db.prepare('SELECT COUNT(*) count FROM detection_rules WHERE organization_id=?').get(DEFAULT_ORGANIZATION_ID).count===0){
  seedDefaultRule(DEFAULT_ORGANIZATION_ID);
}

const insertEvent=db.prepare("INSERT OR REPLACE INTO events(id,organization_id,timestamp,severity,category,event_type,source_ip,message,hostname,metadata,agent_id) VALUES (@id,@organization_id,@timestamp,@severity,@category,@event_type,@source_ip,@message,@hostname,@metadata,@agent_id)");
const insertMany=db.transaction(items=>{for(const e of items)insertEvent.run({...e,event_type:e.event_type||'generic',metadata:typeof e.metadata==='string'?e.metadata:JSON.stringify(e.metadata||{}),agent_id:e.agent_id||null})});

function prune(){
  const cutoff=new Date(Date.now()-retentionDays*86400000).toISOString();
  db.prepare('DELETE FROM events WHERE timestamp < ?').run(cutoff);
  db.prepare('DELETE FROM alerts WHERE rowid NOT IN (SELECT rowid FROM alerts ORDER BY created_at DESC LIMIT 5000)').run();
  db.prepare('DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY timestamp DESC LIMIT 5000)').run();
}
function requireOrganization(organizationId){
  if(!organizationId)throw new Error('Organization context is required');
}
function getEvents(options={}){
  const {organization_id,search='',severity='',category='',source_ip='',since='',limit,offset=0}=options;
  requireOrganization(organization_id);
  const where=['organization_id=@organization_id'],params={organization_id};
  if(search){where.push('(lower(message) LIKE @search OR lower(category) LIKE @search OR lower(source_ip) LIKE @search OR lower(hostname) LIKE @search)');params.search='%'+search.toLowerCase()+'%'}
  if(severity){where.push('severity=@severity');params.severity=severity}
  if(category){where.push('category=@category');params.category=category}
  if(source_ip){where.push('source_ip=@source_ip');params.source_ip=source_ip}
  if(since){where.push('timestamp>=@since');params.since=since}
  const clause='WHERE '+where.join(' AND ');
  const total=db.prepare('SELECT COUNT(*) count FROM events '+clause).get(params).count;
  const events=limit===undefined
    ?db.prepare('SELECT * FROM events '+clause+' ORDER BY timestamp DESC').all(params)
    :db.prepare('SELECT * FROM events '+clause+' ORDER BY timestamp DESC LIMIT @limit OFFSET @offset').all({...params,limit,offset});
  return {events,total};
}
function getRecentEvents(organizationId,sourceIp,since){
  requireOrganization(organizationId);
  return db.prepare('SELECT * FROM events WHERE organization_id=? AND source_ip=? AND timestamp>=? ORDER BY timestamp DESC').all(organizationId,sourceIp,since);
}
function getAlerts(organizationId,status){
  requireOrganization(organizationId);
  return status
    ?db.prepare('SELECT * FROM alerts WHERE organization_id=? AND status=? ORDER BY created_at DESC').all(organizationId,status)
    :db.prepare('SELECT * FROM alerts WHERE organization_id=? ORDER BY created_at DESC').all(organizationId);
}
function getActiveAlert(organizationId,ruleKey,sourceIp){
  requireOrganization(organizationId);
  return db.prepare("SELECT * FROM alerts WHERE organization_id=? AND rule_key=? AND source_ip=? AND status IN ('NEW','ACKNOWLEDGED') ORDER BY created_at DESC LIMIT 1").get(organizationId,ruleKey,sourceIp)||null;
}
function getAudit(organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT * FROM audit WHERE organization_id=? ORDER BY timestamp DESC LIMIT 100').all(organizationId);
}
function getUser(identifier){
  return db.prepare('SELECT id,organization_id,username,email,password_hash,role,enabled,created_at,updated_at FROM users WHERE (username=? OR email=?) AND enabled=1 ORDER BY id LIMIT 1').get(identifier,identifier)||null;
}
function listUsers(organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT id,organization_id,username,email,role,enabled,created_at,updated_at FROM users WHERE organization_id=? ORDER BY username').all(organizationId);
}
function addUser(user){
  requireOrganization(user.organization_id);
  const t=now();
  return db.prepare('INSERT INTO users(organization_id,username,email,password_hash,role,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)').run(user.organization_id,user.username,user.email||null,user.password_hash,user.role,1,t,t).lastInsertRowid;
}
function setUserEnabled(id,enabled,organizationId){
  requireOrganization(organizationId);
  db.prepare('UPDATE users SET enabled=?,updated_at=? WHERE id=? AND organization_id=?').run(enabled?1:0,now(),id,organizationId);
  return db.prepare('SELECT id,organization_id,username,email,role,enabled,created_at,updated_at FROM users WHERE id=? AND organization_id=?').get(id,organizationId)||null;
}
function getIngestKeys(organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT id,organization_id,name,key_prefix,environment,enabled,created_at,rotated_at,revoked_at,last_used_at,created_by FROM ingest_keys WHERE organization_id=? ORDER BY created_at DESC').all(organizationId);
}
function verifyIngestKey(value){
  const hash=crypto.createHash('sha256').update(String(value||'')).digest('hex');
  const key=db.prepare("SELECT k.id,k.organization_id,k.name,k.key_prefix FROM ingest_keys k LEFT JOIN integrations i ON i.ingest_key_id=k.id WHERE k.key_hash=? AND k.enabled=1 AND k.revoked_at IS NULL AND (i.id IS NULL OR i.status='ACTIVE')").get(hash)||null;
  if(key){db.prepare('UPDATE ingest_keys SET last_used_at=? WHERE id=?').run(now(),key.id);touchIntegrationByKey(key.id)}
  return key;
}
function createIngestKey(key){
  requireOrganization(key.organization_id);
  const t=now();
  db.prepare('INSERT INTO ingest_keys(id,organization_id,name,key_hash,key_prefix,environment,enabled,created_at,last_used_at,created_by) VALUES (?,?,?,?,?,?,1,?,?,?)').run(key.id,key.organization_id,key.name,key.hash,key.raw.slice(0,8),key.environment||'Production',t,null,key.created_by);
  return {id:key.id,organization_id:key.organization_id,name:key.name,key_prefix:key.raw.slice(0,8),created_at:t};
}
function revokeIngestKey(id,organizationId){
  requireOrganization(organizationId);
  const t=now();
  db.prepare('UPDATE ingest_keys SET enabled=0,revoked_at=?,rotated_at=? WHERE id=? AND organization_id=?').run(t,t,id,organizationId);
  return db.prepare('SELECT id,organization_id,name,key_prefix,environment,enabled,created_at,rotated_at,revoked_at,last_used_at,created_by FROM ingest_keys WHERE id=? AND organization_id=?').get(id,organizationId)||null;
}
function listRules(organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT * FROM detection_rules WHERE organization_id=? ORDER BY rule_key').all(organizationId).map(deserializeRule);
}
function deserializeRule(r){return {...r,enabled:Boolean(r.enabled),severities:JSON.parse(r.severities),categories:JSON.parse(r.categories)}}
function getRules(organizationId){return listRules(organizationId).filter(r=>r.enabled)}
function upsertRule(rule,user,organizationId){
  requireOrganization(organizationId);
  const t=now();
  db.prepare('INSERT INTO detection_rules(organization_id,rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,rule_key) DO UPDATE SET name=excluded.name,description=excluded.description,enabled=excluded.enabled,window_ms=excluded.window_ms,threshold=excluded.threshold,severities=excluded.severities,categories=excluded.categories,message_pattern=excluded.message_pattern,alert_severity=excluded.alert_severity,title=excluded.title,updated_at=excluded.updated_at,updated_by=excluded.updated_by').run(
    organizationId,rule.rule_key,rule.name,rule.description,rule.enabled?1:0,rule.window_ms,rule.threshold,JSON.stringify(rule.severities),JSON.stringify(rule.categories),rule.message_pattern,rule.alert_severity,rule.title,t,user
  );
  return db.prepare('SELECT * FROM detection_rules WHERE organization_id=? AND rule_key=?').get(organizationId,rule.rule_key);
}
function getStats(organizationId){
  requireOrganization(organizationId);
  return db.prepare([
    'SELECT',
    " (SELECT COUNT(*) FROM events WHERE organization_id=@organization_id) totalEvents,",
    " (SELECT COUNT(*) FROM events WHERE organization_id=@organization_id AND severity='CRITICAL') criticalEvents,",
    " (SELECT COUNT(*) FROM events WHERE organization_id=@organization_id AND severity='HIGH') highEvents,",
    " (SELECT COUNT(DISTINCT source_ip) FROM events WHERE organization_id=@organization_id) sources,",
    " (SELECT COUNT(*) FROM alerts WHERE organization_id=@organization_id AND status='NEW') openAlerts"
  ].join('\n')).get({organization_id:organizationId});
}
function addEvents(items){insertMany(items)}
function addAlert(a){
  requireOrganization(a.organization_id);
  db.prepare('INSERT OR REPLACE INTO alerts(id,organization_id,created_at,source_ip,severity,status,title,description,count,updated_at,updated_by,rule_key) VALUES (@id,@organization_id,@created_at,@source_ip,@severity,@status,@title,@description,@count,@updated_at,@updated_by,@rule_key)').run({...a,updated_at:a.updated_at||null,updated_by:a.updated_by||null,rule_key:a.rule_key||null});
}
function updateAlert(id,status,user,organizationId){
  requireOrganization(organizationId);
  const a=db.prepare('SELECT * FROM alerts WHERE id=? AND organization_id=?').get(id,organizationId);
  if(!a)return null;
  db.prepare('UPDATE alerts SET status=?,updated_at=?,updated_by=? WHERE id=? AND organization_id=?').run(status,now(),user,id,organizationId);
  return db.prepare('SELECT * FROM alerts WHERE id=? AND organization_id=?').get(id,organizationId);
}
function addAudit(a){
  requireOrganization(a.organization_id);
  db.prepare('INSERT OR REPLACE INTO audit(id,organization_id,timestamp,action,actor,target,status) VALUES (@id,@organization_id,@timestamp,@action,@actor,@target,@status)').run({...a,target:a.target||null,status:a.status||null});
}
function createOrganization(organization){
  const t=now();
  db.prepare('INSERT INTO organizations(id,name,slug,industry,company_size,created_at,updated_at) VALUES (?,?,?,?,?,?,?)').run(
    organization.id,organization.name,organization.slug,organization.industry||'Other',organization.company_size||'Unknown',t,t
  );
  return db.prepare('SELECT * FROM organizations WHERE id=?').get(organization.id);
}
function listIntegrations(organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at FROM integrations WHERE organization_id=? ORDER BY created_at DESC').all(organizationId);
}
function getIntegrationByIngestKey(keyId){
  return db.prepare('SELECT id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at FROM integrations WHERE ingest_key_id=?').get(keyId)||null;
}
function getIntegration(id,organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at FROM integrations WHERE id=? AND organization_id=?').get(id,organizationId)||null;
}
function createIntegrationWithKey(input){
  requireOrganization(input.organization_id);
  const t=now();
  return db.transaction(()=>{
    db.prepare('INSERT INTO ingest_keys(id,organization_id,name,key_hash,key_prefix,environment,enabled,created_at,last_used_at,created_by) VALUES (?,?,?,?,?,?,1,?,?,?)').run(
      input.key_id,input.organization_id,input.name,input.key_hash||crypto.createHash('sha256').update(input.key_raw).digest('hex'),input.key_raw.slice(0,8),input.environment,t,null,input.created_by
    );
    db.prepare('INSERT INTO integrations(id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?,NULL)').run(
      input.id,input.organization_id,input.name,input.type,input.environment,'ACTIVE',input.key_id,t,t
    );
    return {
      integration:getIntegration(input.id,input.organization_id),
      key:{key_id:input.key_id,raw:input.key_raw}
    };
  })();
}
function setIntegrationStatus(id,status,organizationId){
  requireOrganization(organizationId);
  const tx=db.transaction(()=>{db.prepare('UPDATE integrations SET status=?,updated_at=? WHERE id=? AND organization_id=?').run(status,now(),id,organizationId);const integration=db.prepare('SELECT ingest_key_id FROM integrations WHERE id=? AND organization_id=?').get(id,organizationId);if(integration?.ingest_key_id){const active=status==='ACTIVE';db.prepare('UPDATE ingest_keys SET enabled=?,revoked_at=? WHERE id=?').run(active?1:0,active?null:now(),integration.ingest_key_id);}});tx();
  return getIntegration(id,organizationId);
}
function touchIntegrationByKey(keyId){
  db.prepare('UPDATE integrations SET last_seen_at=?,updated_at=? WHERE ingest_key_id=? AND status=\'ACTIVE\'').run(now(),now(),keyId);
}
function getOrganization(organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT * FROM organizations WHERE id=?').get(organizationId)||null;
}
function provisionOrganization(input){
  const t=now();
  return db.transaction(()=>{
    db.prepare('INSERT INTO organizations(id,name,slug,industry,company_size,created_at,updated_at) VALUES (?,?,?,?,?,?,?)').run(
      input.id,input.name,input.slug,input.industry,input.company_size,t,t
    );
    const userId=db.prepare('INSERT INTO users(organization_id,username,email,password_hash,role,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)').run(
      input.id,input.email,input.email,input.password_hash,'admin',1,t,t
    ).lastInsertRowid;
    db.prepare('INSERT INTO ingest_keys(id,organization_id,name,key_hash,key_prefix,environment,enabled,created_at,last_used_at,created_by) VALUES (?,?,?,?,?,?,1,?,?,?)').run(
      input.connector_id,input.id,input.connector_name,input.key_hash,input.key_raw.slice(0,8),input.environment,t,null,input.email
    );
    seedDefaultRule(input.id);
    db.prepare('INSERT INTO audit(id,organization_id,timestamp,action,actor,target,status) VALUES (?,?,?,?,?,?,?)').run(
      crypto.randomUUID(),input.id,t,'ORGANIZATION_CREATED',input.email,input.id,'ACTIVE'
    );
    return {
      organization:db.prepare('SELECT * FROM organizations WHERE id=?').get(input.id),
      user:db.prepare('SELECT id,organization_id,username,email,role,enabled,created_at,updated_at FROM users WHERE id=?').get(userId),
      connector:{id:input.connector_id,name:input.connector_name,environment:input.environment,created_at:t}
    };
  })();
}
function health(){db.prepare('SELECT 1').get();return true}
function createAgent(input){
  requireOrganization(input.organization_id);
  const t=now();
  db.prepare('INSERT INTO agents(id,organization_id,integration_id,name,status,created_by,created_at) VALUES (?,?,?,?,?,?,?)').run(input.id,input.organization_id,input.integration_id||null,input.name,'pending',input.created_by||null,t);
  return getAgent(input.id,input.organization_id);
}
function getAgent(id,organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT * FROM agents WHERE id=? AND organization_id=?').get(id,organizationId)||null;
}
function listAgents(organizationId){
  requireOrganization(organizationId);
  return db.prepare('SELECT * FROM agents WHERE organization_id=? ORDER BY created_at DESC').all(organizationId);
}
function createEnrollmentToken(agentId,organizationId,tokenHash,expiresAt){
  requireOrganization(organizationId);
  const agent=getAgent(agentId,organizationId); if(!agent)throw new Error('Agent not found');
  const t=now();
  db.prepare('INSERT INTO agent_enrollment_tokens(agent_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)').run(agentId,tokenHash,expiresAt,t);
  return {agent_id:agentId,expires_at:expiresAt};
}
function getEnrollmentToken(tokenHash){return db.prepare('SELECT agent_id,expires_at,used_at FROM agent_enrollment_tokens WHERE token_hash=?').get(tokenHash)||null}
function enrollAgent(tokenHash,input){
  const t=now();
  return db.transaction(()=>{
    const row=db.prepare('SELECT t.id,t.agent_id,t.expires_at,t.used_at,a.organization_id,a.integration_id,a.status FROM agent_enrollment_tokens t JOIN agents a ON a.id=t.agent_id WHERE t.token_hash=?').get(tokenHash);
    if(!row||row.used_at||row.expires_at<=t)return null;
    const claimed=db.prepare('UPDATE agent_enrollment_tokens SET used_at=? WHERE id=? AND used_at IS NULL').run(t,row.id);
    if(claimed.changes!==1)return null;
    db.prepare("UPDATE agents SET credential_hash=?,credential_prefix=?,status='active',version=?,hostname=?,os=?,enrolled_at=?,disabled_at=NULL WHERE id=?").run(input.credential_hash,input.credential_prefix,input.version||null,input.hostname||null,input.os||null,t,row.agent_id);
    return getAgent(row.agent_id,row.organization_id);
  })();
}
function getAgentByCredential(agentId,credentialHash){
  return db.prepare("SELECT * FROM agents WHERE id=? AND credential_hash=? AND status='active'").get(agentId,credentialHash)||null;
}
function updateAgentHeartbeat(agentId,input){
  const t=now();
  db.prepare('UPDATE agents SET last_seen_at=?,last_heartbeat=?,version=COALESCE(?,version),hostname=COALESCE(?,hostname) WHERE id=? AND status=\'active\'').run(t,JSON.stringify(input),input.agent_version||null,input.hostname||null,agentId);
  return db.prepare('SELECT * FROM agents WHERE id=?').get(agentId)||null;
}
function setAgentStatus(id,status,organizationId){
  requireOrganization(organizationId);
  const disabledAt=status==='disabled'?now():null;
  db.prepare('UPDATE agents SET status=?,disabled_at=? WHERE id=? AND organization_id=?').run(status,disabledAt,id,organizationId);
  return getAgent(id,organizationId);
}
function rotateAgent(id,organizationId){
  requireOrganization(organizationId);
  const t=now();
  db.prepare("UPDATE agents SET credential_hash=NULL,credential_prefix=NULL,status='pending',disabled_at=NULL WHERE id=? AND organization_id=?").run(id,organizationId);
  db.prepare('DELETE FROM agent_enrollment_tokens WHERE agent_id=?').run(id);
  return getAgent(id,organizationId);
}
function touchIntegration(id,organizationId){requireOrganization(organizationId);db.prepare("UPDATE integrations SET last_seen_at=?,updated_at=? WHERE id=? AND organization_id=? AND status='ACTIVE'").run(now(),now(),id,organizationId)}
function deleteAgent(id,organizationId){
  requireOrganization(organizationId);
  return db.prepare('DELETE FROM agents WHERE id=? AND organization_id=?').run(id,organizationId).changes>0;
}
function claimIngestBatch(agentId,batchId,accepted){
  const t=now();
  const result=db.prepare('INSERT OR IGNORE INTO ingest_batches(agent_id,batch_id,received_at,accepted) VALUES(?,?,?,?)').run(agentId,batchId,t,accepted);
  if(result.changes===1)return {duplicate:false,accepted};
  return {duplicate:true,accepted:db.prepare('SELECT accepted FROM ingest_batches WHERE agent_id=? AND batch_id=?').get(agentId,batchId).accepted};
}
function incrementAgentEvents(agentId,count){db.prepare('UPDATE agents SET events_received=events_received+? WHERE id=?').run(count,agentId)}
function close(){db.close()}
module.exports={
  db,
  DEFAULT_ORGANIZATION_ID,
  createOrganization,
  createOrganizationWithAdmin:provisionOrganization,
  provisionOrganization,
  getOrganization,
  listIntegrations,
  getIntegration,
  getIntegrationByIngestKey,
  createIntegrationWithKey,
  setIntegrationStatus,
  getEvents,
  getRecentEvents,
  getAlerts,
  getActiveAlert,
  getAudit,
  getStats,
  addEvents,
  addAlert,
  updateAlert,
  addAudit,
  prune,
  health,
  getUser,
  listUsers,
  addUser,
  setUserEnabled,
  getIngestKeys,
  verifyIngestKey,
  createIngestKey,
  revokeIngestKey,
  createAgent,
  getAgent,
  listAgents,
  createEnrollmentToken,
  getEnrollmentToken,
  enrollAgent,
  getAgentByCredential,
  updateAgentHeartbeat,
  setAgentStatus,
  rotateAgent,
  deleteAgent,
  touchIntegration,
  claimIngestBatch,
  incrementAgentEvents,
  listRules,
  getRules,
  upsertRule,
  close
};
}
