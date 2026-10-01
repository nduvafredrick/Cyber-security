const postgres=require('postgres');
const crypto=require('crypto');
const {databaseUrl,retentionDays,adminUser,adminPasswordHash,ingestKey}=require('./config');
const {DEFAULT_ORGANIZATION_ID,runPostgresMigrations}=require('./migrations');

if(!databaseUrl)throw new Error('DATABASE_URL is required for PostgreSQL storage');

const sql=postgres(databaseUrl,{max:5,connect_timeout:10,idle_timeout:20,prepare:false});
const q=(text,values=[])=>sql.unsafe(text,values);

const ready=(async()=>{
  await runPostgresMigrations(q);
  if(adminPasswordHash){
    await q('INSERT INTO users(organization_id,username,email,password_hash,role,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,TRUE,NOW(),NOW()) ON CONFLICT(username) DO NOTHING',[DEFAULT_ORGANIZATION_ID,adminUser,null,adminPasswordHash,'admin']);
  }
  if(ingestKey){
    const h=crypto.createHash('sha256').update(ingestKey).digest('hex');
    await q('INSERT INTO ingest_keys(id,organization_id,name,key_hash,key_prefix,environment,enabled,created_at,created_by) SELECT $1,$2,$3,$4,$5,$6,TRUE,NOW(),$7 WHERE NOT EXISTS(SELECT 1 FROM ingest_keys)',[crypto.randomUUID(),DEFAULT_ORGANIZATION_ID,'bootstrap',h,ingestKey.slice(0,8),'Production',adminUser]);
  }
  await q('INSERT INTO detection_rules(organization_id,rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by) VALUES($1,$2,$3,$4,TRUE,$5,$6,$7::jsonb,$8::jsonb,$9,$10,$11,NOW(),$12) ON CONFLICT(organization_id,rule_key) DO NOTHING',[DEFAULT_ORGANIZATION_ID,'auth-bruteforce-v1','Authentication brute force','Repeated failed authentication attempts from one source.',300000,5,'["HIGH","CRITICAL"]','["ssh","login","authentication"]','/failed|invalid|denied/i','CRITICAL','Possible brute-force authentication attack','system']);
})();
const ensure=()=>ready;
function requireOrganization(organizationId){
  if(!organizationId)throw new Error('Organization context is required');
}
async function createOrganization(organization){
  const t=new Date().toISOString();
  await ensure();
  const rows=await q('INSERT INTO organizations(id,name,slug,industry,company_size,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$6) RETURNING *',[organization.id,organization.name,organization.slug,organization.industry||'Other',organization.company_size||'Unknown',t]);
  return rows[0];
}
async function listIntegrations(organizationId){
  await ensure();requireOrganization(organizationId);
  return q('SELECT id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at FROM integrations WHERE organization_id=$1 ORDER BY created_at DESC',[organizationId]);
}
async function getIntegration(id,organizationId){
  await ensure();requireOrganization(organizationId);
  const rows=await q('SELECT id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at FROM integrations WHERE id=$1 AND organization_id=$2',[id,organizationId]);
  return rows[0]||null;
}
async function createIntegrationWithKey(input){
  await ensure();requireOrganization(input.organization_id);
  const t=new Date().toISOString();
  return sql.begin(async tx=>{
    const keyHash=input.key_hash||crypto.createHash('sha256').update(input.key_raw).digest('hex');
    await tx`INSERT INTO ingest_keys(id,organization_id,name,key_hash,key_prefix,environment,enabled,created_at,last_used_at,created_by)
      VALUES(${input.key_id},${input.organization_id},${input.name},${keyHash},${input.key_raw.slice(0,8)},${input.environment},TRUE,${t},NULL,${input.created_by})`;
    const rows=await tx`INSERT INTO integrations(id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at)
      VALUES(${input.id},${input.organization_id},${input.name},${input.type},${input.environment},'ACTIVE',${input.key_id},${t},${t},NULL)
      RETURNING id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at`;
    return {integration:rows[0],key:{key_id:input.key_id,raw:input.key_raw}};
  });
}
async function setIntegrationStatus(id,status,organizationId){
  await ensure();requireOrganization(organizationId);
  const rows=await q('UPDATE integrations SET status=$1,updated_at=NOW() WHERE id=$2 AND organization_id=$3 RETURNING id,organization_id,name,type,environment,status,ingest_key_id,created_at,updated_at,last_seen_at',[status,id,organizationId]);
  return rows[0]||null;
}
async function touchIntegrationByKey(keyId){
  await ensure();
  await q("UPDATE integrations SET last_seen_at=NOW(),updated_at=NOW() WHERE ingest_key_id=$1 AND status='ACTIVE'",[keyId]);
}
async function getOrganization(organizationId){
  await ensure();requireOrganization(organizationId);
  const rows=await q('SELECT * FROM organizations WHERE id=$1',[organizationId]);
  return rows[0]||null;
}
async function getEvents(o={}){
  await ensure();
  const {organization_id,search='',severity='',category='',source_ip='',since='',limit,offset=0}=o;
  requireOrganization(organization_id);
  const clauses=['organization_id=$1'],values=[organization_id];
  const add=(value,sqlText)=>{values.push(value);clauses.push(sqlText.replace('?', '$'+values.length));};
  if(search){values.push('%'+search.toLowerCase()+'%');const n=values.length;clauses.push('(lower(message) LIKE $'+n+' OR lower(category) LIKE $'+n+' OR lower(source_ip) LIKE $'+n+' OR lower(hostname) LIKE $'+n+')');}
  if(severity)add(severity,'severity=?');
  if(category)add(category,'category=?');
  if(source_ip)add(source_ip,'source_ip=?');
  if(since)add(since,'timestamp>=?');
  const where=' WHERE '+clauses.join(' AND ');
  const total=Number((await q('SELECT COUNT(*) count FROM events'+where,values))[0].count);
  const rows=limit===undefined
    ?await q('SELECT * FROM events'+where+' ORDER BY timestamp DESC',values)
    :await q('SELECT * FROM events'+where+' ORDER BY timestamp DESC LIMIT $'+(values.length+1)+' OFFSET $'+(values.length+2),[...values,limit,offset]);
  return {events:rows,total};
}
async function getRecentEvents(organizationId,sourceIp,since){
  await ensure();requireOrganization(organizationId);
  return q('SELECT * FROM events WHERE organization_id=$1 AND source_ip=$2 AND timestamp>=$3 ORDER BY timestamp DESC',[organizationId,sourceIp,since]);
}
async function getAlerts(organizationId,status){
  await ensure();requireOrganization(organizationId);
  return status
    ?q('SELECT * FROM alerts WHERE organization_id=$1 AND status=$2 ORDER BY created_at DESC',[organizationId,status])
    :q('SELECT * FROM alerts WHERE organization_id=$1 ORDER BY created_at DESC',[organizationId]);
}
async function getActiveAlert(organizationId,ruleKey,sourceIp){
  await ensure();requireOrganization(organizationId);
  const rows=await q("SELECT * FROM alerts WHERE organization_id=$1 AND rule_key=$2 AND source_ip=$3 AND status IN('NEW','ACKNOWLEDGED') ORDER BY created_at DESC LIMIT 1",[organizationId,ruleKey,sourceIp]);
  return rows[0]||null;
}
async function getAudit(organizationId){
  await ensure();requireOrganization(organizationId);
  return q('SELECT * FROM audit WHERE organization_id=$1 ORDER BY timestamp DESC LIMIT 100',[organizationId]);
}
async function getUser(username){
  await ensure();
  const rows=await q('SELECT id,organization_id,username,email,password_hash,role,enabled,created_at,updated_at FROM users WHERE (username=$1 OR email=$1) AND enabled=TRUE ORDER BY id LIMIT 1',[username]);
  return rows[0]||null;
}
async function listUsers(organizationId){
  await ensure();requireOrganization(organizationId);
  return q('SELECT id,organization_id,username,email,role,enabled,created_at,updated_at FROM users WHERE organization_id=$1 ORDER BY username',[organizationId]);
}
async function addUser(user){
  await ensure();requireOrganization(user.organization_id);
  const rows=await q('INSERT INTO users(organization_id,username,email,password_hash,role,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,TRUE,NOW(),NOW()) RETURNING id',[user.organization_id,user.username,user.email||null,user.password_hash,user.role]);
  return rows[0].id;
}
async function setUserEnabled(id,enabled,organizationId){
  await ensure();requireOrganization(organizationId);
  const rows=await q('UPDATE users SET enabled=$1,updated_at=NOW() WHERE id=$2 AND organization_id=$3 RETURNING id,organization_id,username,role,enabled,created_at,updated_at',[Boolean(enabled),id,organizationId]);
  return rows[0]||null;
}
async function getIngestKeys(organizationId){
  await ensure();requireOrganization(organizationId);
  return q('SELECT id,organization_id,name,key_prefix,environment,enabled,created_at,rotated_at,revoked_at,last_used_at,created_by FROM ingest_keys WHERE organization_id=$1 ORDER BY created_at DESC',[organizationId]);
}
async function verifyIngestKey(raw){
  await ensure();
  const h=crypto.createHash('sha256').update(String(raw||'')).digest('hex');
  const rows=await q('SELECT id,organization_id,name,key_prefix FROM ingest_keys WHERE key_hash=$1 AND enabled=TRUE AND revoked_at IS NULL',[h]);
  if(!rows[0])return null;
  await q('UPDATE ingest_keys SET last_used_at=NOW() WHERE id=$1',[rows[0].id]);
  await touchIntegrationByKey(rows[0].id);
  return rows[0];
}
async function createIngestKey(key){
  await ensure();requireOrganization(key.organization_id);
  const t=new Date().toISOString();
  await q('INSERT INTO ingest_keys(id,organization_id,name,key_hash,key_prefix,environment,enabled,created_at,last_used_at,created_by) VALUES($1,$2,$3,$4,$5,$6,TRUE,$7,NULL,$8)',[key.id,key.organization_id,key.name,key.hash,key.raw.slice(0,8),key.environment||'Production',t,key.created_by]);
  return {id:key.id,organization_id:key.organization_id,name:key.name,key_prefix:key.raw.slice(0,8),created_at:t};
}
async function revokeIngestKey(id,organizationId){
  await ensure();requireOrganization(organizationId);
  const t=new Date().toISOString();
  const rows=await q('UPDATE ingest_keys SET enabled=FALSE,revoked_at=$1,rotated_at=$1 WHERE id=$2 AND organization_id=$3 RETURNING id,organization_id,name,key_prefix,environment,enabled,created_at,rotated_at,revoked_at,last_used_at,created_by',[t,id,organizationId]);
  return rows[0]||null;
}
async function listRules(organizationId){
  await ensure();requireOrganization(organizationId);
  return (await q('SELECT * FROM detection_rules WHERE organization_id=$1 ORDER BY rule_key',[organizationId])).map(r=>({...r,enabled:Boolean(r.enabled),severities:r.severities,categories:r.categories}));
}
async function getRules(organizationId){return (await listRules(organizationId)).filter(r=>r.enabled)}
async function upsertRule(r,user,organizationId){
  await ensure();requireOrganization(organizationId);
  const t=new Date().toISOString();
  const rows=await q('INSERT INTO detection_rules(organization_id,rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14) ON CONFLICT(organization_id,rule_key) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,enabled=EXCLUDED.enabled,window_ms=EXCLUDED.window_ms,threshold=EXCLUDED.threshold,severities=EXCLUDED.severities,categories=EXCLUDED.categories,message_pattern=EXCLUDED.message_pattern,alert_severity=EXCLUDED.alert_severity,title=EXCLUDED.title,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by RETURNING *',[organizationId,r.rule_key,r.name,r.description,Boolean(r.enabled),r.window_ms,r.threshold,JSON.stringify(r.severities),JSON.stringify(r.categories),r.message_pattern,r.alert_severity,r.title,t,user]);
  return rows[0];
}
async function getStats(organizationId){
  await ensure();requireOrganization(organizationId);
  return (await q("SELECT (SELECT COUNT(*)::int FROM events WHERE organization_id=$1) \"totalEvents\",(SELECT COUNT(*)::int FROM events WHERE organization_id=$1 AND severity='CRITICAL') \"criticalEvents\",(SELECT COUNT(*)::int FROM events WHERE organization_id=$1 AND severity='HIGH') \"highEvents\",(SELECT COUNT(DISTINCT source_ip)::int FROM events WHERE organization_id=$1) sources,(SELECT COUNT(*)::int FROM alerts WHERE organization_id=$1 AND status='NEW') \"openAlerts\"",[organizationId]))[0];
}
async function addEvents(items){
  await ensure();
  for(const e of items){
    requireOrganization(e.organization_id);
    await q('INSERT INTO events(id,organization_id,timestamp,severity,category,source_ip,message,hostname) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET organization_id=EXCLUDED.organization_id,timestamp=EXCLUDED.timestamp,severity=EXCLUDED.severity,category=EXCLUDED.category,source_ip=EXCLUDED.source_ip,message=EXCLUDED.message,hostname=EXCLUDED.hostname',[e.id,e.organization_id,e.timestamp,e.severity,e.category,e.source_ip,e.message,e.hostname]);
  }
}
async function addAlert(a){
  await ensure();requireOrganization(a.organization_id);
  await q('INSERT INTO alerts(id,organization_id,created_at,source_ip,severity,status,title,description,count,updated_at,updated_by,rule_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(id) DO UPDATE SET organization_id=EXCLUDED.organization_id,status=EXCLUDED.status,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by',[a.id,a.organization_id,a.created_at,a.source_ip,a.severity,a.status,a.title,a.description,a.count,a.updated_at||null,a.updated_by||null,a.rule_key||null]);
}
async function updateAlert(id,status,user,organizationId){
  await ensure();requireOrganization(organizationId);
  const rows=await q('UPDATE alerts SET status=$1,updated_at=NOW(),updated_by=$2 WHERE id=$3 AND organization_id=$4 RETURNING *',[status,user,id,organizationId]);
  return rows[0]||null;
}
async function addAudit(a){
  await ensure();requireOrganization(a.organization_id);
  await q('INSERT INTO audit(id,organization_id,timestamp,action,actor,target,status) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET organization_id=EXCLUDED.organization_id,status=EXCLUDED.status',[a.id,a.organization_id,a.timestamp,a.action,a.actor,a.target||null,a.status||null]);
}
async function provisionOrganization(input){
  await ensure();
  const t=new Date().toISOString();
  const result=await sql.begin(async tx=>{
    const orgs=await tx`INSERT INTO organizations(id,name,slug,industry,company_size,created_at,updated_at)
      VALUES(${input.id},${input.name},${input.slug},${input.industry},${input.company_size},${t},${t})
      RETURNING *`;
    const users=await tx`INSERT INTO users(organization_id,username,email,password_hash,role,enabled,created_at,updated_at)
      VALUES(${input.id},${input.email},${input.email},${input.password_hash},'admin',TRUE,${t},${t})
      RETURNING id,organization_id,username,email,role,enabled,created_at,updated_at`;
    await tx`INSERT INTO ingest_keys(id,organization_id,name,key_hash,key_prefix,environment,enabled,created_at,last_used_at,created_by)
      VALUES(${input.connector_id},${input.id},${input.connector_name},${input.key_hash},${input.key_raw.slice(0,8)},${input.environment},TRUE,${t},NULL,${input.email})`;
    await tx`INSERT INTO detection_rules(organization_id,rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by)
      VALUES(${input.id},'auth-bruteforce-v1','Authentication brute force','Repeated failed authentication attempts from one source.',TRUE,300000,5,'["HIGH","CRITICAL"]'::jsonb,'["ssh","login","authentication"]'::jsonb,'/failed|invalid|denied/i','CRITICAL','Possible brute-force authentication attack',${t},'system')
      ON CONFLICT(organization_id,rule_key) DO NOTHING`;
    await tx`INSERT INTO audit(id,organization_id,timestamp,action,actor,target,status)
      VALUES(${crypto.randomUUID()},${input.id},${t},'ORGANIZATION_CREATED',${input.email},${input.id},'ACTIVE')`;
    return {organization:orgs[0],user:users[0],connector:{id:input.connector_id,name:input.connector_name,environment:input.environment,created_at:t}};
  });
  return result;
}
async function prune(){
  await ensure();
  const cut=new Date(Date.now()-retentionDays*86400000).toISOString();
  await q('DELETE FROM events WHERE timestamp<$1',[cut]);
  await q('DELETE FROM alerts WHERE id IN(SELECT id FROM alerts ORDER BY created_at DESC OFFSET 5000)');
  await q('DELETE FROM audit WHERE id IN(SELECT id FROM audit ORDER BY timestamp DESC OFFSET 5000)');
}
async function health(){await ensure();await q('SELECT 1');return true;}
async function close(){await sql.end({timeout:5});}

module.exports={
  DEFAULT_ORGANIZATION_ID,
  createOrganization,
  provisionOrganization,
  getOrganization,
  listIntegrations,
  getIntegration,
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
  listRules,
  getRules,
  upsertRule,
  close
};
