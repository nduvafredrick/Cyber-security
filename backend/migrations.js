const DEFAULT_ORGANIZATION_ID='org-default';
const DEFAULT_ORGANIZATION_NAME='Default Organization';
const DEFAULT_ORGANIZATION_SLUG='default';

function now(){
  return new Date().toISOString();
}

function sqliteMigrationV1(db){
  db.exec([
    'CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL, source_ip TEXT NOT NULL, message TEXT NOT NULL, hostname TEXT NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)',
    'CREATE INDEX IF NOT EXISTS idx_events_severity_timestamp ON events(severity,timestamp DESC)',
    'CREATE INDEX IF NOT EXISTS idx_events_source_timestamp ON events(source_ip,timestamp DESC)',
    'CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, source_ip TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, count INTEGER NOT NULL, updated_at TEXT, updated_by TEXT, rule_key TEXT)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status,created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_rule_status ON alerts(rule_key,status)',
    'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN (\'admin\',\'analyst\')), enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS ingest_keys (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, rotated_at TEXT, revoked_at TEXT, last_used_at TEXT, created_by TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS detection_rules (rule_key TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, window_ms INTEGER NOT NULL, threshold INTEGER NOT NULL, severities TEXT NOT NULL, categories TEXT NOT NULL, message_pattern TEXT NOT NULL, alert_severity TEXT NOT NULL, title TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, target TEXT, status TEXT)',
    'CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp DESC)'
  ].join(';\n'));
}

function sqliteMigrationV2(db){
  db.exec('CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)');
  db.prepare('INSERT OR IGNORE INTO organizations(id,name,slug,created_at,updated_at) VALUES (?,?,?,?,?)').run(DEFAULT_ORGANIZATION_ID,DEFAULT_ORGANIZATION_NAME,DEFAULT_ORGANIZATION_SLUG,now(),now());

  db.pragma('foreign_keys = OFF');
  try{
    const migrate=db.transaction(()=>{
      db.exec('CREATE TABLE users_new (id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id TEXT NOT NULL REFERENCES organizations(id), username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN (\'admin\',\'analyst\')), enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)');
      db.prepare('INSERT INTO users_new(id,organization_id,username,password_hash,role,enabled,created_at,updated_at) SELECT id,?,username,password_hash,role,enabled,created_at,updated_at FROM users').run(DEFAULT_ORGANIZATION_ID);
      db.exec('DROP TABLE users');
      db.exec('ALTER TABLE users_new RENAME TO users');

      db.exec('CREATE TABLE ingest_keys_new (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, rotated_at TEXT, revoked_at TEXT, last_used_at TEXT, created_by TEXT NOT NULL)');
      db.prepare('INSERT INTO ingest_keys_new(id,organization_id,name,key_hash,key_prefix,enabled,created_at,rotated_at,revoked_at,last_used_at,created_by) SELECT id,?,name,key_hash,key_prefix,enabled,created_at,rotated_at,revoked_at,last_used_at,created_by FROM ingest_keys').run(DEFAULT_ORGANIZATION_ID);
      db.exec('DROP TABLE ingest_keys');
      db.exec('ALTER TABLE ingest_keys_new RENAME TO ingest_keys');

      db.exec('CREATE TABLE events_new (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), timestamp TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL, source_ip TEXT NOT NULL, message TEXT NOT NULL, hostname TEXT NOT NULL)');
      db.prepare('INSERT INTO events_new(id,organization_id,timestamp,severity,category,source_ip,message,hostname) SELECT id,?,timestamp,severity,category,source_ip,message,hostname FROM events').run(DEFAULT_ORGANIZATION_ID);
      db.exec('DROP TABLE events');
      db.exec('ALTER TABLE events_new RENAME TO events');

      db.exec('CREATE TABLE alerts_new (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), created_at TEXT NOT NULL, source_ip TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, count INTEGER NOT NULL, updated_at TEXT, updated_by TEXT, rule_key TEXT)');
      db.prepare('INSERT INTO alerts_new(id,organization_id,created_at,source_ip,severity,status,title,description,count,updated_at,updated_by,rule_key) SELECT id,?,created_at,source_ip,severity,status,title,description,count,updated_at,updated_by,rule_key FROM alerts').run(DEFAULT_ORGANIZATION_ID);
      db.exec('DROP TABLE alerts');
      db.exec('ALTER TABLE alerts_new RENAME TO alerts');

      db.exec('CREATE TABLE detection_rules_new (organization_id TEXT NOT NULL REFERENCES organizations(id), rule_key TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, window_ms INTEGER NOT NULL, threshold INTEGER NOT NULL, severities TEXT NOT NULL, categories TEXT NOT NULL, message_pattern TEXT NOT NULL, alert_severity TEXT NOT NULL, title TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL, PRIMARY KEY (organization_id,rule_key))');
      db.prepare('INSERT INTO detection_rules_new(organization_id,rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by) SELECT ?,rule_key,name,description,enabled,window_ms,threshold,severities,categories,message_pattern,alert_severity,title,updated_at,updated_by FROM detection_rules').run(DEFAULT_ORGANIZATION_ID);
      db.exec('DROP TABLE detection_rules');
      db.exec('ALTER TABLE detection_rules_new RENAME TO detection_rules');

      db.exec('CREATE TABLE audit_new (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), timestamp TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, target TEXT, status TEXT)');
      db.prepare('INSERT INTO audit_new(id,organization_id,timestamp,action,actor,target,status) SELECT id,?,timestamp,action,actor,target,status FROM audit').run(DEFAULT_ORGANIZATION_ID);
      db.exec('DROP TABLE audit');
      db.exec('ALTER TABLE audit_new RENAME TO audit');

      db.exec([
        'CREATE INDEX idx_events_timestamp ON events(timestamp DESC)',
        'CREATE INDEX idx_events_severity_timestamp ON events(severity,timestamp DESC)',
        'CREATE INDEX idx_events_source_timestamp ON events(source_ip,timestamp DESC)',
        'CREATE INDEX idx_events_org_timestamp ON events(organization_id,timestamp DESC)',
        'CREATE INDEX idx_events_org_severity_timestamp ON events(organization_id,severity,timestamp DESC)',
        'CREATE INDEX idx_events_org_source_timestamp ON events(organization_id,source_ip,timestamp DESC)',
        'CREATE INDEX idx_alerts_status_created ON alerts(status,created_at DESC)',
        'CREATE INDEX idx_alerts_rule_status ON alerts(rule_key,status)',
        'CREATE INDEX idx_alerts_org_status_created ON alerts(organization_id,status,created_at DESC)',
        'CREATE INDEX idx_alerts_org_rule_status ON alerts(organization_id,rule_key,status)',
        'CREATE INDEX idx_users_org_username ON users(organization_id,username)',
        'CREATE INDEX idx_ingest_keys_org_created ON ingest_keys(organization_id,created_at DESC)',
        'CREATE INDEX idx_rules_org_enabled ON detection_rules(organization_id,enabled)',
        'CREATE INDEX idx_audit_timestamp ON audit(timestamp DESC)',
        'CREATE INDEX idx_audit_org_timestamp ON audit(organization_id,timestamp DESC)'
      ].join(';\n'));
    });
    migrate();
  }finally{
    db.pragma('foreign_keys = ON');
  }
}

function sqliteMigrationV3(db){
  db.exec([
    "ALTER TABLE organizations ADD COLUMN industry TEXT NOT NULL DEFAULT 'Other'",
    "ALTER TABLE organizations ADD COLUMN company_size TEXT NOT NULL DEFAULT 'Unknown'",
    "ALTER TABLE users ADD COLUMN email TEXT",
    "ALTER TABLE ingest_keys ADD COLUMN environment TEXT NOT NULL DEFAULT 'Production'",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email) WHERE email IS NOT NULL"
  ].join(';\n'));
}

function sqliteMigrationV4(db){
  db.exec('CREATE TABLE IF NOT EXISTS integrations (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN (\'agent\',\'syslog\',\'http_api\',\'ssh\',\'cloud_api\')), environment TEXT NOT NULL DEFAULT \'Production\', status TEXT NOT NULL DEFAULT \'ACTIVE\' CHECK(status IN (\'ACTIVE\',\'DISABLED\')), ingest_key_id TEXT REFERENCES ingest_keys(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_seen_at TEXT)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_integrations_org_created ON integrations(organization_id,created_at DESC)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_integrations_org_status ON integrations(organization_id,status)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_integrations_ingest_key ON integrations(ingest_key_id)');
}

function runSqliteMigrations(db){
  db.exec('CREATE TABLE IF NOT EXISTS _schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL)');
  const applied=new Set(db.prepare('SELECT version FROM _schema_migrations').all().map(row=>row.version));
  const migrations=[[1,sqliteMigrationV1],[2,sqliteMigrationV2],[3,sqliteMigrationV3],[4,sqliteMigrationV4],[5,sqliteMigrationV5]];
  for(const [version,migration] of migrations){
    if(applied.has(version))continue;
    migration(db);
    db.prepare('INSERT INTO _schema_migrations(version,applied_at) VALUES(?,?)').run(version,now());
  }
}

async function postgresMigrationV1(q){
  await q([
    'CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,timestamp TIMESTAMPTZ NOT NULL,severity TEXT NOT NULL,category TEXT NOT NULL,source_ip TEXT NOT NULL,message TEXT NOT NULL,hostname TEXT NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)',
    'CREATE INDEX IF NOT EXISTS idx_events_severity_timestamp ON events(severity,timestamp DESC)',
    'CREATE INDEX IF NOT EXISTS idx_events_source_timestamp ON events(source_ip,timestamp DESC)',
    'CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,created_at TIMESTAMPTZ NOT NULL,source_ip TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,title TEXT NOT NULL,description TEXT NOT NULL,count INTEGER NOT NULL,updated_at TIMESTAMPTZ,updated_by TEXT,rule_key TEXT)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status,created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_rule_status ON alerts(rule_key,status)',
    'CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN (\'admin\',\'analyst\')),enabled BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL)',
    'CREATE TABLE IF NOT EXISTS ingest_keys(id TEXT PRIMARY KEY,name TEXT NOT NULL,key_hash TEXT NOT NULL UNIQUE,key_prefix TEXT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL,rotated_at TIMESTAMPTZ,revoked_at TIMESTAMPTZ,last_used_at TIMESTAMPTZ,created_by TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS detection_rules(rule_key TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT TRUE,window_ms BIGINT NOT NULL,threshold INTEGER NOT NULL,severities JSONB NOT NULL,categories JSONB NOT NULL,message_pattern TEXT NOT NULL,alert_severity TEXT NOT NULL,title TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL,updated_by TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,timestamp TIMESTAMPTZ NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,target TEXT,status TEXT)',
    'CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp DESC)'
  ].join(';\n'));
}

async function postgresMigrationV2(q){
  await q('CREATE TABLE IF NOT EXISTS organizations(id TEXT PRIMARY KEY,name TEXT NOT NULL,slug TEXT NOT NULL UNIQUE,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL)');
  await q('INSERT INTO organizations(id,name,slug,created_at,updated_at) VALUES($1,$2,$3,NOW(),NOW()) ON CONFLICT(id) DO NOTHING',[DEFAULT_ORGANIZATION_ID,DEFAULT_ORGANIZATION_NAME,DEFAULT_ORGANIZATION_SLUG]);

  for(const table of ['events','alerts','users','ingest_keys','detection_rules','audit']){
    await q('ALTER TABLE '+table+' ADD COLUMN IF NOT EXISTS organization_id TEXT');
    await q('UPDATE '+table+' SET organization_id=$1 WHERE organization_id IS NULL',[DEFAULT_ORGANIZATION_ID]);
    await q('ALTER TABLE '+table+' ALTER COLUMN organization_id SET NOT NULL');
    await q('ALTER TABLE '+table+' DROP CONSTRAINT IF EXISTS '+table+'_organization_id_fkey');
    await q('ALTER TABLE '+table+' ADD CONSTRAINT '+table+'_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES organizations(id)');
  }

  await q('ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_pkey');
  await q('ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_pkey PRIMARY KEY (organization_id,rule_key)');
  await q([
    'CREATE INDEX IF NOT EXISTS idx_events_org_timestamp ON events(organization_id,timestamp DESC)',
    'CREATE INDEX IF NOT EXISTS idx_events_org_severity_timestamp ON events(organization_id,severity,timestamp DESC)',
    'CREATE INDEX IF NOT EXISTS idx_events_org_source_timestamp ON events(organization_id,source_ip,timestamp DESC)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_org_status_created ON alerts(organization_id,status,created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_org_rule_status ON alerts(organization_id,rule_key,status)',
    'CREATE INDEX IF NOT EXISTS idx_users_org_username ON users(organization_id,username)',
    'CREATE INDEX IF NOT EXISTS idx_ingest_keys_org_created ON ingest_keys(organization_id,created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_rules_org_enabled ON detection_rules(organization_id,enabled)',
    'CREATE INDEX IF NOT EXISTS idx_audit_org_timestamp ON audit(organization_id,timestamp DESC)'
  ].join(';\n'));
}

async function postgresMigrationV3(q){
  await q("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS industry TEXT DEFAULT 'Other'");
  await q("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS company_size TEXT DEFAULT 'Unknown'");
  await q("UPDATE organizations SET industry='Other' WHERE industry IS NULL");
  await q("UPDATE organizations SET company_size='Unknown' WHERE company_size IS NULL");
  await q("ALTER TABLE organizations ALTER COLUMN industry SET NOT NULL");
  await q("ALTER TABLE organizations ALTER COLUMN company_size SET NOT NULL");
  await q("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT");
  await q("ALTER TABLE ingest_keys ADD COLUMN IF NOT EXISTS environment TEXT DEFAULT 'Production'");
  await q("UPDATE ingest_keys SET environment='Production' WHERE environment IS NULL");
  await q("ALTER TABLE ingest_keys ALTER COLUMN environment SET NOT NULL");
  await q("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email) WHERE email IS NOT NULL");
}

async function postgresMigrationV4(q){
  await q("CREATE TABLE IF NOT EXISTS integrations(id TEXT PRIMARY KEY,organization_id TEXT NOT NULL REFERENCES organizations(id),name TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN ('agent','syslog','http_api','ssh','cloud_api')),environment TEXT NOT NULL DEFAULT 'Production',status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','DISABLED')),ingest_key_id TEXT REFERENCES ingest_keys(id),created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ)");
  await q('CREATE INDEX IF NOT EXISTS idx_integrations_org_created ON integrations(organization_id,created_at DESC)');
  await q('CREATE INDEX IF NOT EXISTS idx_integrations_org_status ON integrations(organization_id,status)');
  await q('CREATE INDEX IF NOT EXISTS idx_integrations_ingest_key ON integrations(ingest_key_id)');
}

function sqliteMigrationV5(db){
  db.exec("ALTER TABLE events ADD COLUMN event_type TEXT NOT NULL DEFAULT 'generic'");
  db.exec("ALTER TABLE events ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'");
  db.exec("ALTER TABLE events ADD COLUMN agent_id TEXT");
  db.exec("CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), integration_id TEXT REFERENCES integrations(id), name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','disabled')), credential_hash TEXT, credential_prefix TEXT, version TEXT, hostname TEXT, os TEXT, last_seen_at TEXT, last_heartbeat TEXT, events_received INTEGER NOT NULL DEFAULT 0, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL, enrolled_at TEXT, disabled_at TEXT)");
  db.exec('CREATE INDEX IF NOT EXISTS idx_agents_org ON agents(organization_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_agents_integration ON agents(integration_id)');
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_credential_hash ON agents(credential_hash) WHERE credential_hash IS NOT NULL');
  db.exec('CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT NOT NULL)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_agent_enrollment_agent ON agent_enrollment_tokens(agent_id)');
  db.exec('CREATE TABLE IF NOT EXISTS ingest_batches (agent_id TEXT NOT NULL, batch_id TEXT NOT NULL, received_at TEXT NOT NULL, accepted INTEGER NOT NULL, PRIMARY KEY(agent_id,batch_id))');
}

async function postgresMigrationV5(q){
  await q("ALTER TABLE events ADD COLUMN IF NOT EXISTS event_type TEXT NOT NULL DEFAULT 'generic'");
  await q("ALTER TABLE events ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb");
  await q("ALTER TABLE events ADD COLUMN IF NOT EXISTS agent_id TEXT");
  await q("CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY,organization_id TEXT NOT NULL REFERENCES organizations(id),integration_id TEXT REFERENCES integrations(id),name TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','disabled')),credential_hash TEXT,credential_prefix TEXT,version TEXT,hostname TEXT,os TEXT,last_seen_at TIMESTAMPTZ,last_heartbeat JSONB,events_received INTEGER NOT NULL DEFAULT 0,created_by INTEGER REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL,enrolled_at TIMESTAMPTZ,disabled_at TIMESTAMPTZ)");
  await q('CREATE INDEX IF NOT EXISTS idx_agents_org ON agents(organization_id)');
  await q('CREATE INDEX IF NOT EXISTS idx_agents_integration ON agents(integration_id)');
  await q('CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_credential_hash ON agents(credential_hash) WHERE credential_hash IS NOT NULL');
  await q('CREATE TABLE IF NOT EXISTS agent_enrollment_tokens(id BIGSERIAL PRIMARY KEY,agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,token_hash TEXT NOT NULL UNIQUE,expires_at TIMESTAMPTZ NOT NULL,used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL)');
  await q('CREATE INDEX IF NOT EXISTS idx_agent_enrollment_agent ON agent_enrollment_tokens(agent_id)');
  await q('CREATE TABLE IF NOT EXISTS ingest_batches(agent_id TEXT NOT NULL,batch_id TEXT NOT NULL,received_at TIMESTAMPTZ NOT NULL,accepted INTEGER NOT NULL,PRIMARY KEY(agent_id,batch_id))');
}

async function runPostgresMigrations(q){
  await q('CREATE TABLE IF NOT EXISTS _schema_migrations(version INTEGER PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL)');
  const applied=new Set((await q('SELECT version FROM _schema_migrations')).map(row=>Number(row.version)));
  const migrations=[[1,postgresMigrationV1],[2,postgresMigrationV2],[3,postgresMigrationV3],[4,postgresMigrationV4],[5,postgresMigrationV5]];
  for(const [version,migration] of migrations){
    if(applied.has(version))continue;
    await migration(q);
    await q('INSERT INTO _schema_migrations(version,applied_at) VALUES($1,NOW())',[version]);
  }
}

module.exports={
  DEFAULT_ORGANIZATION_ID,
  DEFAULT_ORGANIZATION_NAME,
  DEFAULT_ORGANIZATION_SLUG,
  runSqliteMigrations,
  runPostgresMigrations
};
