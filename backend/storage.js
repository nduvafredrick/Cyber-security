const fs=require('fs');
const path=require('path');
const Database=require('better-sqlite3');
const {dataDir,retentionDays}=require('./config');

fs.mkdirSync(dataDir,{recursive:true});
const db=new Database(path.join(dataDir,'sentinel.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
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
  updated_at TEXT, updated_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status,created_at DESC);
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
migrateLegacy();

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
function getAudit(){return db.prepare('SELECT * FROM audit ORDER BY timestamp DESC LIMIT 100').all()}
function getStats(){return db.prepare(`SELECT
 (SELECT COUNT(*) FROM events) totalEvents,
 (SELECT COUNT(*) FROM events WHERE severity='CRITICAL') criticalEvents,
 (SELECT COUNT(*) FROM events WHERE severity='HIGH') highEvents,
 (SELECT COUNT(DISTINCT source_ip) FROM events) sources,
 (SELECT COUNT(*) FROM alerts WHERE status='NEW') openAlerts`).get()}
function addEvents(items){insertMany(items)}
function addAlert(a){db.prepare('INSERT OR REPLACE INTO alerts(id,created_at,source_ip,severity,status,title,description,count,updated_at,updated_by) VALUES (@id,@created_at,@source_ip,@severity,@status,@title,@description,@count,@updated_at,@updated_by)').run({...a,updated_at:a.updated_at||null,updated_by:a.updated_by||null})}
function updateAlert(id,status,user){const a=db.prepare('SELECT * FROM alerts WHERE id=?').get(id);if(!a)return null;db.prepare('UPDATE alerts SET status=?,updated_at=?,updated_by=? WHERE id=?').run(status,new Date().toISOString(),user,id);return db.prepare('SELECT * FROM alerts WHERE id=?').get(id)}
function addAudit(a){db.prepare('INSERT OR REPLACE INTO audit(id,timestamp,action,actor,target,status) VALUES (@id,@timestamp,@action,@actor,@target,@status)').run({...a,target:a.target||null,status:a.status||null})}
function health(){db.prepare('SELECT 1').get();return true}
module.exports={db,getEvents,getRecentEvents,getAlerts,getAudit,getStats,addEvents,addAlert,updateAlert,addAudit,prune,health};