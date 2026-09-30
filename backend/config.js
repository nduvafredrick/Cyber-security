require('dotenv').config();
const path=require('path');
const crypto=require('crypto');

function required(name,value){
  if(!value)throw new Error(`Missing required environment variable: ${name}`);
  return value;
}
const env=process.env.NODE_ENV||'development';
const port=Number(process.env.PORT||3001);
if(!Number.isInteger(port)||port<0||port>65535)throw new Error('PORT must be a valid TCP port');

const dataDir=path.resolve(process.env.DATA_DIR||path.join(__dirname,'data'));
const config={
  env,
  port,
  dataDir,
  databaseUrl:process.env.DATABASE_URL||null,
  jwtSecret:process.env.JWT_SECRET||'local-development-secret',
  ingestKey:process.env.INGEST_API_KEY||'local-development-ingest-key',
  metricsApiKey:process.env.METRICS_API_KEY||null,
  adminUser:process.env.ADMIN_USER||'admin',
  adminPasswordHash:process.env.ADMIN_PASSWORD_HASH||null,
  corsOrigins:(process.env.CORS_ORIGIN||'http://localhost:5173').split(',').map(x=>x.trim()).filter(Boolean),
  retentionDays:Math.max(1,Math.floor(Number(process.env.LOG_RETENTION_DAYS||90))),
  dbBusyTimeoutMs:Math.max(1000,Math.floor(Number(process.env.DB_BUSY_TIMEOUT_MS||5000))),
  backupDir:path.resolve(process.env.BACKUP_DIR||path.join(dataDir,'backups')),
  backupRetentionCount:Math.max(1,Math.floor(Number(process.env.BACKUP_RETENTION_COUNT||7))),
  trustProxy:(v=>v==null||v===''||v==='false'?false:v==='true'?true:/^\d+$/.test(v)?Number(v):v)(process.env.TRUST_PROXY),
  ingestRateLimitPerMinute:Math.max(1,Math.floor(Number(process.env.INGEST_RATE_LIMIT_PER_MINUTE||300))),
  bulkIngestRateLimitPerMinute:Math.max(1,Math.floor(Number(process.env.BULK_INGEST_RATE_LIMIT_PER_MINUTE||60))),
  loginRateLimitPer15Minutes:Math.max(1,Math.floor(Number(process.env.LOGIN_RATE_LIMIT_PER_15_MINUTES||10))),
  sessionCookieSecure:process.env.SESSION_COOKIE_SECURE==null?env==='production':process.env.SESSION_COOKIE_SECURE==='true',
  upgradeInsecureRequests:process.env.CSP_UPGRADE_INSECURE_REQUESTS==null?env==='production':process.env.CSP_UPGRADE_INSECURE_REQUESTS==='true',
  hsts:process.env.HSTS==null?env==='production':process.env.HSTS==='true',
  instanceId:crypto.randomBytes(4).toString('hex')
};

if(env==='production'){
  required('JWT_SECRET',process.env.JWT_SECRET);
  required('INGEST_API_KEY',process.env.INGEST_API_KEY);
  required('METRICS_API_KEY',config.metricsApiKey);
  required('ADMIN_PASSWORD_HASH',config.adminPasswordHash);
  required('DATABASE_URL',config.databaseUrl);
  if(config.jwtSecret.length<32)throw new Error('JWT_SECRET must be at least 32 characters in production');
  if(config.ingestKey.length<20)throw new Error('INGEST_API_KEY must be at least 20 characters in production');
  if(config.metricsApiKey.length<20)throw new Error('METRICS_API_KEY must be at least 20 characters in production');
}
module.exports=config;
