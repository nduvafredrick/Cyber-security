require('dotenv').config();
const path=require('path');
const crypto=require('crypto');
const config={
  env:process.env.NODE_ENV||'development',
  port:Number(process.env.PORT||3001),
  dataDir:path.join(__dirname,'data'),
  jwtSecret:process.env.JWT_SECRET||'local-development-secret',
  ingestKey:process.env.INGEST_API_KEY||'local-development-ingest-key',
  adminUser:process.env.ADMIN_USER||'admin',
  adminPasswordHash:process.env.ADMIN_PASSWORD_HASH||null,
  corsOrigins:(process.env.CORS_ORIGIN||'http://localhost:5173').split(',').map(x=>x.trim()).filter(Boolean),
  retentionDays:Math.max(1,Number(process.env.LOG_RETENTION_DAYS||90))
};
if(config.env==='production' && (!process.env.JWT_SECRET||!process.env.INGEST_API_KEY||!config.adminPasswordHash)) throw new Error('Production requires JWT_SECRET, INGEST_API_KEY and ADMIN_PASSWORD_HASH');
config.instanceId=crypto.randomBytes(4).toString('hex');
module.exports=config;