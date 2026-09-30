const fs=require('fs');
const path=require('path');
const Database=require('better-sqlite3');
const {dataDir,retentionDays,adminUser,adminPasswordHash,ingestKey,dbBusyTimeoutMs}=require('./config');

fs.mkdirSync(dataDir,{recursive:true});
const db=new Database(path.join(dataDir,'sentinel.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma(`busy_timeout = ${dbBusyTimeoutMs}`);
db.exec(`
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, severity TEXT NOT NULL,
  category TEXT NOT NULL, source_ip TEXT NOT NULL, message TEXT NOT NULL, hostname TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity_timestamp ON events(severity,timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_timestamp ON events(source_ip,timestamp DESC);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, source_ip TEXT NOT NULL, severity TEXT NOT NULL,
  status TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, count INTEGER NOT NULL,
  updated_at TEXT, updated_by TEXT, rule_key TEXT
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','analyst')), enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_keys (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, rotated_at TEXT, revoked_at TEXT, last_used_at TEXT,
  created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_rules (
  rule_key TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  window_ms INTEGER NOT NULL, threshold INTEGER NOT NULL, severities TEXT NOT NULL, categories TEXT NOT NULL,
  message_pattern TEXT NOT NULL, alert_severity TEXT NOT NULL, title TEXT NOT NULL, updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_status ON alerts(rule_key,status);
CREATE TABLE IF NOT EXISTS audit (
  id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, target TEXT, status TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp DESC);
`);

function readLegacy(name){try{return JSON.parse(fs.readFileSync(path.join(dataDir,name),'utf8'))}catch{return []}}
function migrateLegacy(){
  if(db.prepare('SELECT COUNT(*) count FROM events').get().count===0){
    const legacy=readLegacy('events.json');const stmt=db.prepare('INSERT OR IGNORE INTO events VALUES (@id,@timestamp,@severity,@category,@source_ip,@message,@hostname)');
    const tx=db.transaction(items=>items.slice(-10000).forEach(e=>stmt.run(e)));tx(legacy);
  }
  if(db.prepare('SELECT COUNT(*) count FROM alerts').get().count===0){
    const stmt=db.prepare('INSERT OR IGNORE INTO alerts(id,created_at,source_ip,severity,status,title,description,count,updated_at,updated_by) VALUES (@id,@created_at,@source_ip,@severity,@status,@title,@description,@count,@updated_at,@updated_by)');
    const tx=db.transaction(items=>items.slice(-5000).forEach(a=>stmt.run({...a,updated_at:a.updated_at||null,updated_by:a.updated_by||null})));tx(readLegacy('alerts.json'));
  }
  if(db.prepare('SELECT COUNT(*) count FROM audit').get().count===0){
    const stmt=db.prepare('INSERT OR IGNORE INTO audit(id,timestamp,action,actor,target,status) VALUES (@id,@timestamp,@action,@actor,@target,@status)');
    const tx=db.transaction(items=>items.slice(-5000).forEach(a=>stmt.run({...a,target:a.target||null,status:a.status||null})));tx(readLegacy('audit.json'));
  }
}
try { db.prepare('ALTER TABLE alerts ADD COLUMN rule_key TEXT').run(); } catch (error) { if (!/duplicate column name/i.test(error.message)) throw error; }
try { db.prepare('ALTER TABLE ingest_keys ADD COLUMN last_used_at TEXT').run(); } catch (error) { if (!/duplicate column name/i.test(error.message)) throw error; }
migrateLegacy();

const now=()=>new Date().toISOString();
if(db.prepare('SELECT COUNT(*) count FROM users').get().count===0 && adminPasswordHash){
  db.prepare('INSERT INTO users(username,password_hash,role,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(adminUser,adminPasswordHash,'admin',1,now(),now());
}
if(db.prepare('SELECT COUNT(*) count FROM ingest_keys').get().count===0 && ingestKey){
  const hash=require('crypto').createHash('sha256').update(ingestKey).digest('hex');
  db.prepare('INSERT INTO ingest_keys(id,name,key_hash,key_prefix,enabled,created_at,last_used_at,created_by) VALUES (?,?,?,?,?,?,?,?)').run(require('crypto').randomUUID(),'bootstrap',hash,ingestKey.slice(0,8),1,now(),null,adminUser);
}
if(db.prepare('SELECT COUNT(*) count FROM detection_rules').get().count===0){
  db.prepare('INSERT INTO detection_rules(rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').run('auth-bruteforce-v1','Authentication brute force','Repeated failed authentication attempts from one source.',1,300000,5,JSON.stringify(['HIGH','CRITICAL']),JSON.stringify(['ssh','login','authentication']),'/failed|invalid|denied/i','CRITICAL','Possible brute-force authentication attack',now(),'system');
}

const insertEvent=db.prepare('INSERT OR REPLACE INTO events VALUES (@id,@timestamp,@severity,@category,@source_ip,@message,@hostname)');
const insertMany=db.transaction(items=>{for(const e of items)insertEvent.run(e)});
function prune(){
  const cutoff=new Date(Date.now()-retentionDays*86400000).toISOString();
  db.prepare('DELETE FROM events WHERE timestamp < ?').run(cutoff);
  db.prepare('DELETE FROM alerts WHERE rowid NOT IN (SELECT rowid FROM alerts ORDER BY created_at DESC LIMIT 5000)').run();
  db.prepare('DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY timestamp DESC LIMIT 5000)').run();
}
function getEvents(options={}){
  const {search='',severity='',category='',source_ip='',since='',limit,offset=0}=options;
  const where=[],params={};
  if(search){where.push('(lower(message) LIKE @search OR lower(category) LIKE @search OR lower(source_ip) LIKE @search OR lower(hostname) LIKE @search)');params.search='%'+search.toLowerCase()+'%'}
  if(severity) {where.push('severity=@severity');params.severity=severity}
  if(category) {where.push('category=@category');params.category=category}
  if(source_ip) {where.push('source_ip=@source_ip');params.source_ip=source_ip}
  if(since) {where.push('timestamp>=@since');params.since=since}
  const clause=where.length?'WHERE '+where.join(' AND '):'';
  const total=db.prepare('SELECT COUNT(*) count FROM events '+clause).get(params).count;
  const events=limit===undefined
    ?db.prepare('SELECT * FROM events '+clause+' ORDER BY timestamp DESC').all(params)
    :db.prepare('SELECT * FROM events '+clause+' ORDER BY timestamp DESC LIMIT @limit OFFSET @offset').all({...params,limit,offset});
  return {events,total};
}
function getRecentEvents(source_ip,since){return db.prepare('SELECT * FROM events WHERE source_ip=? AND timestamp>=? ORDER BY timestamp DESC').all(source_ip,since)}
function getAlerts(status){return status?db.prepare('SELECT * FROM alerts WHERE status=? ORDER BY created_at DESC').all(status):db.prepare('SELECT * FROM alerts ORDER BY created_at DESC').all()}
function getActiveAlert(rule_key,source_ip){return db.prepare("SELECT * FROM alerts WHERE rule_key=? AND source_ip=? AND status IN ('NEW','ACKNOWLEDGED') ORDER BY created_at DESC LIMIT 1").get(rule_key,source_ip)||null}
function getAudit(){return db.prepare('SELECT * FROM audit ORDER BY timestamp DESC LIMIT 100').all()}
function getUser(username){return db.prepare('SELECT id,username,password_hash,role,enabled,created_at,updated_at FROM users WHERE username=? AND enabled=1').get(username)||null}
function listUsers(){return db.prepare('SELECT id,username,role,enabled,created_at,updated_at FROM users ORDER BY username').all()}
function addUser(user){const t=now();return db.prepare('INSERT INTO users(username,password_hash,role,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(user.username,user.password_hash,user.role,1,t,t).lastInsertRowid}
function setUserEnabled(id,enabled){db.prepare('UPDATE users SET enabled=?,updated_at=? WHERE id=?').run(enabled?1:0,now(),id);return db.prepare('SELECT id,username,role,enabled,created_at,updated_at FROM users WHERE id=?').get(id)||null}
function getIngestKeys(){return db.prepare('SELECT id,name,key_prefix,enabled,created_at,rotated_at,revoked_at,last_used_at,created_by FROM ingest_keys ORDER BY created_at DESC').all()}
function verifyIngestKey(value){const crypto=require('crypto');const hash=crypto.createHash('sha256').update(String(value||'')).digest('hex');const key=db.prepare('SELECT id,name,key_prefix FROM ingest_keys WHERE key_hash=? AND enabled=1 AND revoked_at IS NULL').get(hash)||null;if(key)db.prepare('UPDATE ingest_keys SET last_used_at=? WHERE id=?').run(now(),key.id);return key}
function createIngestKey(key){const t=now();db.prepare('INSERT INTO ingest_keys(id,name,key_hash,key_prefix,enabled,created_at,last_used_at,created_by) VALUES (?,?,?,?,?,?,?,?)').run(key.id,key.name,key.hash,key.raw.slice(0,8),1,t,null,key.created_by);return {id:key.id,name:key.name,key_prefix:key.raw.slice(0,8),created_at:t}}
function revokeIngestKey(id,user){const t=now();db.prepare('UPDATE ingest_keys SET enabled=0,revoked_at=?,rotated_at=? WHERE id=?').run(t,t,id);return db.prepare('SELECT id,name,key_prefix,enabled,created_at,rotated_at,revoked_at,last_used_at,created_by FROM ingest_keys WHERE id=?').get(id)||null}
function listRules(){return db.prepare('SELECT * FROM detection_rules ORDER BY rule_key').all().map(deserializeRule)}
function deserializeRule(r){return {...r,enabled:Boolean(r.enabled),severities:JSON.parse(r.severities),categories:JSON.parse(r.categories)}}
function getRules(){return listRules().filter(r=>r.enabled)}
function upsertRule(rule,user){const t=now();db.prepare('INSERT INTO detection_rules(rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_key) DO UPDATE SET name=excluded.name,description=excluded.description,enabled=excluded.enabled,window_ms=excluded.window_ms,threshold=excluded.threshold,severities=excluded.severities,categories=excluded.categories,message_pattern=excluded.message_pattern,alert_severity=excluded.alert_severity,title=excluded.title,updated_at=excluded.updated_at,updated_by=excluded.updated_by').run(rule.rule_key,rule.name,rule.description,rule.enabled?1:0,rule.window_ms,rule.threshold,JSON.stringify(rule.severities),JSON.stringify(rule.categories),rule.message_pattern,rule.alert_severity,rule.title,t,user);return db.prepare('SELECT * FROM detection_rules WHERE rule_key=?').get(rule.rule_key)}
function getStats(){return db.prepare(`SELECT
 (SELECT COUNT(*) FROM events) totalEvents,
 (SELECT COUNT(*) FROM events WHERE severity='CRITICAL') criticalEvents,
 (SELECT COUNT(*) FROM events WHERE severity='HIGH') highEvents,
 (SELECT COUNT(DISTINCT source_ip) FROM events) sources,
 (SELECT COUNT(*) FROM alerts WHERE status='NEW') openAlerts`).get()}
function addEvents(items){insertMany(items)}
function addAlert(a){db.prepare('INSERT OR REPLACE INTO alerts(id,created_at,source_ip,severity,status,title,description,count,updated_at,updated_by,rule_key) VALUES (@id,@created_at,@source_ip,@severity,@status,@title,@description,@count,@updated_at,@updated_by,@rule_key)').run({...a,updated_at:a.updated_at||null,updated_by:a.updated_by||null,rule_key:a.rule_key||null})}
function updateAlert(id,status,user){const a=db.prepare('SELECT * FROM alerts WHERE id=?').get(id);if(!a)return null;db.prepare('UPDATE alerts SET status=?,updated_at=?,updated_by=? WHERE id=?').run(status,new Date().toISOString(),user,id);return db.prepare('SELECT * FROM alerts WHERE id=?').get(id)}
function addAudit(a){db.prepare('INSERT OR REPLACE INTO audit(id,timestamp,action,actor,target,status) VALUES (@id,@timestamp,@action,@actor,@target,@status)').run({...a,target:a.target||null,status:a.status||null})}
function health(){db.prepare('SELECT 1').get();return true}
function close(){db.close()}
module.exports={db,getEvents,getRecentEvents,getAlerts,getActiveAlert,getAudit,getStats,addEvents,addAlert,updateAlert,addAudit,prune,health,getUser,listUsers,addUser,setUserEnabled,getIngestKeys,verifyIngestKey,createIngestKey,revokeIngestKey,listRules,getRules,upsertRule,close};