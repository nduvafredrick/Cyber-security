const express=require('express');
const cors=require('cors');
const helmet=require('helmet');
const rateLimit=require('express-rate-limit');
const crypto=require('crypto');
const net=require('net');
const path=require('path');
const {WebSocketServer}=require('ws');
const config=require('./config');
const store=require('./storage');
const security=require('./security');
const detection=require('./detection');
const logger=require('./logger');
const bcrypt=require('bcryptjs');

const app=express();
app.disable('x-powered-by');
if(config.trustProxy!==false)app.set('trust proxy',config.trustProxy);
app.use((req,res,next)=>{const requestId=crypto.randomUUID();req.requestId=requestId;res.setHeader('X-Request-Id',requestId);const started=process.hrtime.bigint();res.on('finish',()=>{metrics.requests++;if(res.statusCode>=500)metrics.errors++;logger.info('http_request',{request_id:requestId,method:req.method,path:req.path,status:res.statusCode,duration_ms:Number(process.hrtime.bigint()-started)/1e6,actor:req.user?.username||null})});next()});
app.use(helmet({contentSecurityPolicy:config.upgradeInsecureRequests?undefined:false,hsts:config.hsts}));
const corsMiddleware=cors({credentials:true,origin:(origin,cb)=>!origin||config.corsOrigins.includes(origin)?cb(null,true):cb(new Error('Origin not allowed'))});
app.use((req,res,next)=>{const origin=req.get('origin');if(!origin)return next();try{if(new URL(origin).host===req.get('host')){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Access-Control-Allow-Credentials','true');if(req.method==='OPTIONS'){res.setHeader('Access-Control-Allow-Methods','GET,HEAD,PUT,PATCH,POST,DELETE');res.setHeader('Access-Control-Allow-Headers',req.get('access-control-request-headers')||'Content-Type');return res.status(204).end()}return next()}}catch{}return corsMiddleware(req,res,next)});
app.use(express.json({limit:'1mb'}));
app.use('/api',(_q,r,n)=>{r.set('Cache-Control','no-store');n()});
const ingestClientKey=(req)=>'k:'+crypto.createHash('sha256').update(String(req.headers['x-api-key']||'')).digest('hex');
const ingestRateLimit=rateLimit({windowMs:60000,keyGenerator:ingestClientKey,limit:config.ingestRateLimitPerMinute,standardHeaders:true,legacyHeaders:false,message:(req)=>({error:'Ingestion rate limit exceeded',request_id:req.requestId})});
const ONBOARDING_INDUSTRIES=['Technology','Finance','Healthcare','Education','Retail','Manufacturing','Government','Non-profit','Other'];
const ONBOARDING_COMPANY_SIZES=['1-10','11-50','51-200','201-500','501-1000','1000+'];
const ONBOARDING_ENVIRONMENTS=['Production','Staging','Development'];
const INTEGRATION_TYPES=['agent','syslog','http_api','ssh','cloud_api'];
const onboardingRateLimit=rateLimit({windowMs:3600000,limit:5,standardHeaders:true,legacyHeaders:false,message:()=>({error:'Too many onboarding attempts. Please try again later.'})});
const agentEnrollmentRateLimit=rateLimit({windowMs:60000,limit:config.agentEnrollmentRateLimitPerMinute,standardHeaders:true,legacyHeaders:false,keyGenerator:req=>req.ip,message:()=>({error:'Too many enrollment attempts. Please try again later.'})});
const agentIngestRateLimit=rateLimit({windowMs:1000,limit:config.agentIngestRateLimitPerSecond,standardHeaders:true,legacyHeaders:false,keyGenerator:req=>req.agent?.id||req.ip,message:()=>({error:'Agent ingestion rate limit exceeded',request_id:req.requestId})});
function slugify(value){
  const base=String(value||'').normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,60);
  return (base||'company')+'-'+crypto.randomBytes(3).toString('hex');
}
function normalizeEmail(value){
  return String(value||'').trim().toLowerCase();
}
const bulkIngestRateLimit=rateLimit({windowMs:60000,keyGenerator:ingestClientKey,limit:config.bulkIngestRateLimitPerMinute,standardHeaders:true,legacyHeaders:false,message:(req)=>({error:'Bulk ingestion rate limit exceeded',request_id:req.requestId})});
function normalize(input){
  if(!input||typeof input!=='object'||Array.isArray(input))throw Error('Event must be an object');
  const severity=String(input.severity||'INFO').toUpperCase();
  if(!['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(severity))throw Error('Invalid severity');
  const timestamp=input.timestamp||new Date().toISOString();
  if(Number.isNaN(Date.parse(timestamp)))throw Error('Invalid timestamp');
  const ip=String(input.source_ip||input.sourceIp||'unknown');
  if(ip!=='unknown'&&net.isIP(ip)===0)throw Error('Invalid source_ip');
  const text=(v,n)=>String(v??'').slice(0,n);
  return {id:Date.now()+'-'+crypto.randomBytes(4).toString('hex'),timestamp:new Date(timestamp).toISOString(),severity,category:text(input.category||'general',100),source_ip:ip,message:text(input.message||'Event received',1000),hostname:text(input.hostname||'unknown',255)};
}
const clients=new Set();
function heartbeatClients(clientSet=clients){
  for(const ws of clientSet){
    if(ws.isAlive===false){ws.terminate();clients.delete(ws);continue}
    ws.isAlive=false;
    try{ws.ping()}catch{ws.terminate();clients.delete(ws)}
  }
}
function closeWebSocketClients(){
  for(const ws of clients)ws.terminate();
  clients.clear();
}
const metrics={requests:0,errors:0,events_ingested:0,alerts_created:0};
function matches(event,filter={}){const q=String(filter.search||'').trim().toLowerCase();return(!filter.severity||event.severity===filter.severity)&&(!q||event.message.toLowerCase().includes(q)||event.category.toLowerCase().includes(q)||event.source_ip.toLowerCase().includes(q)||event.hostname.toLowerCase().includes(q))}
function broadcast(payload,filterable=false,organizationId){for(const ws of clients){if(ws.readyState!==1||ws.organization_id!==organizationId)continue;if(filterable&&payload.type==='event'&&!matches(payload.event,ws.filter))continue;try{ws.send(JSON.stringify(payload))}catch{ws.terminate();clients.delete(ws)}}}
async function processEvent(e,organizationId){metrics.events_ingested++;const event={...e,organization_id:organizationId};await store.addEvents([event]);const recent=await store.getRecentEvents(organizationId,event.source_ip,new Date(Date.now()-300000).toISOString());const alert=detection.evaluate(event,recent,await store.getRules(organizationId));let createdAlert=null;if(alert&&!await store.getActiveAlert(organizationId,alert.rule_key,alert.source_ip)){createdAlert={...alert,organization_id:organizationId};await store.addAlert(createdAlert);metrics.alerts_created++;broadcast({type:'alert',alert:createdAlert},false,organizationId)}broadcast({type:'event',event},true,organizationId);return createdAlert}
app.get('/health',(_q,r)=>r.json({status:'ok',service:'sentinel-siem',version:'3.1.0'}));
app.get('/metrics',security.metricsAuth,(_q,r)=>{r.type('text/plain').send('# HELP sentinel_http_requests_total Total HTTP responses\n# TYPE sentinel_http_requests_total counter\nsentinel_http_requests_total '+metrics.requests+'\n# HELP sentinel_http_errors_total HTTP 5xx responses\n# TYPE sentinel_http_errors_total counter\nsentinel_http_errors_total '+metrics.errors+'\n# HELP sentinel_events_ingested_total Events accepted by ingestion endpoints\n# TYPE sentinel_events_ingested_total counter\nsentinel_events_ingested_total '+metrics.events_ingested+'\n# HELP sentinel_alerts_created_total Alerts created by detection rules\n# TYPE sentinel_alerts_created_total counter\nsentinel_alerts_created_total '+metrics.alerts_created+'\n')});
app.get('/ready',async(_q,r)=>{try{await store.health();r.json({status:'ready',database:'ok',instance:config.instanceId})}catch(err){logger.error('readiness_failed',{error:err.message});r.status(503).json({status:'not_ready',database:'error'})}});
app.post('/api/onboarding',onboardingRateLimit,async(req,res)=>{
  try{
    const body=req.body||{};
    const companyName=String(body.company_name||'').trim();
    const industry=String(body.industry||'');
    const companySize=String(body.company_size||'');
    const email=normalizeEmail(body.admin_email);
    const password=String(body.password||'');
    const connectorName=String(body.connector_name||'').trim();
    const environment=String(body.environment||'');
    if(companyName.length<2||companyName.length>120)throw Error('Company name must be 2-120 characters');
    if(!ONBOARDING_INDUSTRIES.includes(industry))throw Error('Invalid industry');
    if(!ONBOARDING_COMPANY_SIZES.includes(companySize))throw Error('Invalid company size');
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)throw Error('Enter a valid administrator email');
    if(password.length<12)throw Error('Password must be at least 12 characters');
    if(connectorName.length<2||connectorName.length>80)throw Error('Connector name must be 2-80 characters');
    if(!ONBOARDING_ENVIRONMENTS.includes(environment))throw Error('Invalid connector environment');
    const apiKey=security.generateIngestKey();
    const organizationId=crypto.randomUUID();
    const connectorId=crypto.randomUUID();
    const provisioned=await store.provisionOrganization({
      id:organizationId,
      name:companyName,
      slug:slugify(companyName),
      industry,
      company_size:companySize,
      email,
      password_hash:bcrypt.hashSync(password,12),
      connector_id:connectorId,
      connector_name:connectorName,
      environment,
      key_hash:crypto.createHash('sha256').update(apiKey).digest('hex'),
      key_raw:apiKey
    });
    const user=provisioned.user;
    const organization=provisioned.organization;
    security.setSession(res,security.token(user));
    logger.info('organization_provisioned',{organization_id:organization.id,actor:user.username});
    res.status(201).json({
      organization,
      user,
      connector:{...provisioned.connector,api_key:apiKey,endpoint:'/api/ingest/event'}
    });
  }catch(err){
    logger.warn('organization_onboarding_failed',{error:err.message});
    res.status(400).json({error:/UNIQUE|duplicate|unique/i.test(err.message)?'That administrator email is already registered.':err.message});
  }
});
app.post('/api/auth/login',rateLimit({windowMs:900000,limit:config.loginRateLimitPer15Minutes,standardHeaders:true,legacyHeaders:false}),async(req,res)=>{const user=await security.login(req.body?.username,req.body?.password);if(!user)return res.status(401).json({error:'Invalid credentials'});await store.addAudit({id:crypto.randomUUID(),organization_id:user.organization_id,timestamp:new Date().toISOString(),action:'LOGIN_SUCCESS',actor:user.username});security.setSession(res,security.token(user));logger.info('authentication_success',{actor:user.username,organization_id:user.organization_id});res.json({user,organization:await store.getOrganization(user.organization_id)})});
app.post('/api/auth/logout',security.auth,async(req,res)=>{security.clearSession(res);await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'LOGOUT',actor:req.user.username});res.status(204).end()});
app.get('/api/auth/me',security.auth,async(req,res)=>res.json({user:req.user,organization:await store.getOrganization(req.user.organization_id)}));
app.get('/api/admin/users',security.auth,security.requireRole('admin'),async(req,res)=>res.json({users:await store.listUsers(req.user.organization_id)}));
app.post('/api/admin/users',security.auth,security.requireRole('admin'),async(req,res)=>{try{const username=String(req.body?.username||'').trim(),password=String(req.body?.password||''),role=req.body?.role==='admin'?'admin':'analyst';if(!/^[a-zA-Z0-9._-]{3,50}$/.test(username))throw Error('Invalid username');if(password.length<12)throw Error('Password must be at least 12 characters');const id=await store.addUser({username,password_hash:bcrypt.hashSync(password,12),role,organization_id:req.user.organization_id});await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'USER_CREATED',actor:req.user.username,target:username,status:role});res.status(201).json({user:(await store.listUsers(req.user.organization_id)).find(x=>x.id===id)})}catch(err){res.status(400).json({error:/UNIQUE|constraint/i.test(err.message)?'Username already exists':err.message})}});
app.patch('/api/admin/users/:id',security.auth,security.requireRole('admin'),async(req,res)=>{if(Number(req.params.id)===req.user.id&&req.body?.enabled===false)return res.status(400).json({error:'You cannot disable your own account'});const user=await store.setUserEnabled(Number(req.params.id),req.body?.enabled!==false,req.user.organization_id);if(!user)return res.status(404).json({error:'User not found'});await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'USER_STATUS_CHANGE',actor:req.user.username,target:user.username,status:user.enabled?'ENABLED':'DISABLED'});res.json({user})});
app.get('/api/admin/ingest-keys',security.auth,security.requireRole('admin'),async(req,res)=>res.json({keys:await store.getIngestKeys(req.user.organization_id)}));
async function issueIngestKey(req,name,environment='Production'){
  const raw=security.generateIngestKey();
  const key={id:crypto.randomUUID(),organization_id:req.user.organization_id,name:String(name||'connector-key').trim().slice(0,80)||'connector-key',environment:ONBOARDING_ENVIRONMENTS.includes(environment)?environment:'Production',raw,hash:crypto.createHash('sha256').update(raw).digest('hex'),created_by:req.user.username};
  const record=await store.createIngestKey(key);
  await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'INGEST_KEY_CREATED',actor:req.user.username,target:record.id,status:'ACTIVE'});
  return {key:raw,record};
}
app.post('/api/admin/ingest-keys',security.auth,security.requireRole('admin'),async(req,res)=>{try{res.status(201).json(await issueIngestKey(req,req.body?.name,req.body?.environment))}catch(err){res.status(400).json({error:err.message})}});
app.post('/api/admin/ingest-keys/rotate',security.auth,security.requireRole('admin'),async(req,res)=>{for(const existing of (await store.getIngestKeys(req.user.organization_id)).filter(k=>k.enabled))await store.revokeIngestKey(existing.id,req.user.organization_id);res.status(201).json(await issueIngestKey(req,req.body?.name||'rotated-key',req.body?.environment))});
app.post('/api/admin/ingest-keys/:id/rotate',security.auth,security.requireRole('admin'),async(req,res)=>{const existing=(await store.getIngestKeys(req.user.organization_id)).find(k=>k.id===req.params.id);if(!existing)return res.status(404).json({error:'Key not found'});if(existing.enabled)await store.revokeIngestKey(existing.id,req.user.organization_id);res.status(201).json(await issueIngestKey(req,req.body?.name||existing.name,req.body?.environment||existing.environment))});
app.delete('/api/admin/ingest-keys/:id',security.auth,security.requireRole('admin'),async(req,res)=>{const key=await store.revokeIngestKey(req.params.id,req.user.organization_id);if(!key)return res.status(404).json({error:'Key not found'});await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'INGEST_KEY_REVOKED',actor:req.user.username,target:key.id,status:'REVOKED'});res.json({key})});
app.get('/api/admin/integrations',security.auth,security.requireRole('admin'),async(req,res)=>res.json({integrations:await store.listIntegrations(req.user.organization_id)}));
app.post('/api/admin/integrations',security.auth,security.requireRole('admin'),async(req,res)=>{
  try{
    const name=String(req.body?.name||'').trim();
    const type=String(req.body?.type||'');
    const environment=String(req.body?.environment||'Production');
    if(name.length<2||name.length>80)throw Error('Integration name must be 2-80 characters');
    if(!INTEGRATION_TYPES.includes(type))throw Error('Invalid integration type');
    if(!ONBOARDING_ENVIRONMENTS.includes(environment))throw Error('Invalid integration environment');
    const raw=security.generateIngestKey();
    const integrationId=crypto.randomUUID();
    const keyId=crypto.randomUUID();
    const result=await store.createIntegrationWithKey({
      id:integrationId,
      organization_id:req.user.organization_id,
      name,
      type,
      environment,
      key_id:keyId,
      key_raw:raw,
      key_hash:crypto.createHash('sha256').update(raw).digest('hex'),
      created_by:req.user.username
    });
    await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'INTEGRATION_CREATED',actor:req.user.username,target:integrationId,status:type});
    res.status(201).json({integration:result.integration,api_key:result.key.raw,endpoint:'/api/ingest/event'});
  }catch(err){res.status(400).json({error:err.message})}
});
app.get('/api/admin/integrations/:id',security.auth,security.requireRole('admin'),async(req,res)=>{
  const integration=await store.getIntegration(req.params.id,req.user.organization_id);
  if(!integration)return res.status(404).json({error:'Integration not found'});
  res.json({integration});
});
app.patch('/api/admin/integrations/:id',security.auth,security.requireRole('admin'),async(req,res)=>{
  const status=req.body?.status;
  if(!['ACTIVE','DISABLED'].includes(status))return res.status(400).json({error:'Invalid integration status'});
  const integration=await store.setIntegrationStatus(req.params.id,status,req.user.organization_id);
  if(!integration)return res.status(404).json({error:'Integration not found'});
  await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'INTEGRATION_STATUS_CHANGE',actor:req.user.username,target:integration.id,status});
  res.json({integration});
});
function agentHealth(agent){
  if(agent.status==='pending')return 'pending';
  if(agent.status==='disabled')return 'disabled';
  if(!agent.last_seen_at)return 'offline';
  const age=Date.now()-Date.parse(agent.last_seen_at);
  if(age>300000)return 'offline';
  if(age>90000)return 'stale';
  let heartbeat=agent.last_heartbeat;
  if(typeof heartbeat==='string'){try{heartbeat=JSON.parse(heartbeat)}catch{heartbeat=null}}
  if(heartbeat?.status==='degraded'||heartbeat?.status==='error'||Number(heartbeat?.queue_depth||0)>1000)return 'degraded';
  return 'online';
}
function publicAgent(agent){const {credential_hash,...safe}=agent;return {...safe,health:agentHealth(agent)}}
function makeEnrollmentToken(){return 'sge_'+crypto.randomBytes(32).toString('base64url')}
function makeAgentCredential(agentId){const secret=crypto.randomBytes(32).toString('base64url');return {credential:'sga_'+agentId+'.'+secret,secret}}
function validateAgentEvent(input){
  if(!input||typeof input!=='object'||Array.isArray(input))throw Error('Event must be an object');
  const timestamp=String(input.timestamp||'');
  if(!/^\\d{4}-\\d{2}-\\d{2}T/.test(timestamp)||!timestamp.endsWith('Z')||Number.isNaN(Date.parse(timestamp)))throw Error('Invalid timestamp');
  if(Date.parse(timestamp)>Date.now()+86400000)throw Error('Timestamp is too far in the future');
  const source=String(input.source||'');
  if(!['linux','windows','syslog','app','other'].includes(source))throw Error('Invalid source');
  const category=String(input.category||'');
  if(!['authentication','system','network','malware','application','other'].includes(category))throw Error('Invalid category');
  const eventType=String(input.event_type||'');
  if(!/^[a-z0-9_]{1,64}$/.test(eventType))throw Error('Invalid event_type');
  const severity=String(input.severity||'').toUpperCase();
  if(!['LOW','MEDIUM','HIGH','CRITICAL'].includes(severity))throw Error('Invalid severity');
  const hostname=String(input.host||'').trim();
  if(!hostname||hostname.length>255)throw Error('Invalid host');
  const message=String(input.message||'');
  if(!message||message.length>8192)throw Error('Invalid message');
  const sourceIp=input.source_ip==null?'unknown':String(input.source_ip);
  if(sourceIp!=='unknown'&&net.isIP(sourceIp)===0)throw Error('Invalid source_ip');
  const metadata=input.metadata==null?{}:input.metadata;
  if(!metadata||typeof metadata!=='object'||Array.isArray(metadata)||JSON.stringify(metadata).length>16384)throw Error('Invalid metadata');
  return {id:crypto.randomUUID(),timestamp:new Date(timestamp).toISOString(),severity,category,event_type:eventType,source_ip:sourceIp,message,hostname,metadata};
}
app.post('/api/agents',security.auth,security.requireRole('admin'),async(req,res)=>{
  try{
    const name=String(req.body?.name||'').trim();
    if(name.length<2||name.length>80)throw Error('Agent name must be 2-80 characters');
    const integrationId=req.body?.integration_id?String(req.body.integration_id):null;
    let integration=null;
    if(integrationId){integration=await store.getIntegration(integrationId,req.user.organization_id);if(!integration||integration.type!=='agent')return res.status(404).json({error:'Agent integration not found'})}
    const agentId='agt_'+crypto.randomBytes(6).toString('hex');
    const enrollmentToken=makeEnrollmentToken();
    const expiresAt=new Date(Date.now()+86400000).toISOString();
    const agent=await store.createAgent({id:agentId,organization_id:req.user.organization_id,integration_id:integrationId,name,created_by:req.user.id});
    await store.createEnrollmentToken(agent.id,req.user.organization_id,crypto.createHash('sha256').update(enrollmentToken).digest('hex'),expiresAt);
    await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'agent.created',actor:req.user.username,target:agent.id,status:'pending'});
    res.status(201).json({agent:publicAgent(agent),enrollment_token:enrollmentToken,expires_at:expiresAt});
  }catch(err){res.status(400).json({error:err.message})}
});
app.get('/api/agents',security.auth,security.requireRole('admin'),async(req,res)=>res.json({agents:(await store.listAgents(req.user.organization_id)).map(publicAgent)}));
app.get('/api/agents/:id',security.auth,security.requireRole('admin'),async(req,res)=>{const agent=await store.getAgent(req.params.id,req.user.organization_id);if(!agent)return res.status(404).json({error:'Agent not found'});res.json({agent:publicAgent(agent)})});
app.post('/api/agents/:id/disable',security.auth,security.requireRole('admin'),async(req,res)=>{const agent=await store.setAgentStatus(req.params.id,'disabled',req.user.organization_id);if(!agent)return res.status(404).json({error:'Agent not found'});await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'agent.disabled',actor:req.user.username,target:agent.id,status:'disabled'});res.json({agent:publicAgent(agent)})});
app.post('/api/agents/:id/enable',security.auth,security.requireRole('admin'),async(req,res)=>{const agent=await store.setAgentStatus(req.params.id,'active',req.user.organization_id);if(!agent)return res.status(404).json({error:'Agent not found'});await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'agent.enabled',actor:req.user.username,target:agent.id,status:'active'});res.json({agent:publicAgent(agent)})});
app.post('/api/agents/:id/rotate',security.auth,security.requireRole('admin'),async(req,res)=>{const agent=await store.rotateAgent(req.params.id,req.user.organization_id);if(!agent)return res.status(404).json({error:'Agent not found'});const token=makeEnrollmentToken();const expiresAt=new Date(Date.now()+86400000).toISOString();await store.createEnrollmentToken(agent.id,req.user.organization_id,crypto.createHash('sha256').update(token).digest('hex'),expiresAt);await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'agent.rotated',actor:req.user.username,target:agent.id,status:'pending'});res.json({agent:publicAgent(agent),enrollment_token:token,expires_at:expiresAt})});
app.delete('/api/agents/:id',security.auth,security.requireRole('admin'),async(req,res)=>{const agent=await store.getAgent(req.params.id,req.user.organization_id);if(!agent)return res.status(404).json({error:'Agent not found'});await store.deleteAgent(agent.id,req.user.organization_id);await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'agent.deleted',actor:req.user.username,target:agent.id,status:'DELETED'});res.status(204).end()});
app.post('/api/agent/enroll',agentEnrollmentRateLimit,async(req,res)=>{
  try{
    const token=String(req.body?.enrollment_token||'');
    const hostname=String(req.body?.hostname||'').slice(0,255);
    const os=String(req.body?.os||'').slice(0,32);
    const version=String(req.body?.agent_version||'').slice(0,32);
    if(!token||!hostname||!os||!version)return res.status(401).json({error:'invalid_enrollment_token',message:'Enrollment token is invalid or expired'});
    const hashToken=crypto.createHash('sha256').update(token).digest('hex');
    // Enrollment credential is generated after resolving the token; storage requires the agent id for the final credential string.
    const tokenRow=await store.getEnrollmentToken?.(hashToken);
    if(!tokenRow)return res.status(401).json({error:'invalid_enrollment_token',message:'Enrollment token is invalid or expired'});
    const credential=makeAgentCredential(tokenRow.agent_id);
    const agent=await store.enrollAgent(hashToken,{credential_hash:crypto.createHash('sha256').update(credential.secret).digest('hex'),credential_prefix:credential.credential.slice(0,8),version,hostname,os});
    if(!agent)return res.status(401).json({error:'invalid_enrollment_token',message:'Enrollment token is invalid or expired'});
    await store.addAudit({id:crypto.randomUUID(),organization_id:agent.organization_id,timestamp:new Date().toISOString(),action:'agent.enrolled',actor:'agent',target:agent.id,status:req.ip});
    res.json({agent_id:agent.id,organization_id:agent.organization_id,integration_id:agent.integration_id,credential:credential.credential,heartbeat_interval_s:30,limits:{max_batch_events:500,max_body_bytes:1048576}});
  }catch(err){res.status(401).json({error:'invalid_enrollment_token',message:'Enrollment token is invalid or expired'})}
});
app.post('/api/agent/heartbeat',security.agentCredential,async(req,res)=>{const body=req.body||{};const status=['ok','degraded','error'].includes(body.status)?body.status:'error';const heartbeat={agent_version:String(body.agent_version||'').slice(0,32),timestamp:body.timestamp||null,status,uptime_s:Number(body.uptime_s)||0,hostname:String(body.hostname||'').slice(0,255),events_sent_total:Number(body.events_sent_total)||0,queue_depth:Number(body.queue_depth)||0,errors_since_last:Number(body.errors_since_last)||0,last_error:body.last_error?String(body.last_error).slice(0,1000):null};const agent=await store.updateAgentHeartbeat(req.agent.id,heartbeat);if(!agent)return res.status(403).json({error:'agent_disabled',message:'Agent is disabled'});if(agent.integration_id)await store.touchIntegration(agent.integration_id,agent.organization_id);res.json({server_time:new Date().toISOString(),heartbeat_interval_s:30,config_version:1,commands:[]})});
app.post('/api/ingest/events',security.agentCredential,agentIngestRateLimit,async(req,res)=>{
  try{
    const body=req.body||{};
    const batchId=String(body.batch_id||'');
    if(!/^[A-Za-z0-9_-]{10,128}$/.test(batchId))return res.status(400).json({error:{code:'invalid_batch_id',message:'batch_id is required'}});
    if(!Array.isArray(body.events)||body.events.length<1)return res.status(400).json({error:{code:'invalid_batch',message:'events must contain at least one event'}});
    if(body.events.length>500)return res.status(413).json({error:{code:'batch_too_large',message:'Maximum 500 events per batch'}});
    const claimed=await store.claimIngestBatch(req.agent.id,batchId,body.events.length);
    if(claimed.duplicate)return res.json({batch_id:batchId,accepted:claimed.accepted,rejected:[],duplicate:true});
    const accepted=[];const rejected=[];
    body.events.forEach((item,index)=>{try{accepted.push({...validateAgentEvent(item),organization_id:req.agent.organization_id,agent_id:req.agent.id})}catch(err){rejected.push({index,error:err.message})}});
    if(accepted.length){await store.addEvents(accepted);await store.incrementAgentEvents(req.agent.id,accepted.length);for(const e of accepted){const recent=await store.getRecentEvents(req.agent.organization_id,e.source_ip,new Date(Date.now()-300000).toISOString());const a=detection.evaluate(e,recent,await store.getRules(req.agent.organization_id));if(a&&!await store.getActiveAlert(req.agent.organization_id,a.rule_key,a.source_ip)){const alert={...a,organization_id:req.agent.organization_id};await store.addAlert(alert);metrics.alerts_created++;broadcast({type:'alert',alert},false,req.agent.organization_id)}metrics.events_ingested++;broadcast({type:'event',event:e},true,req.agent.organization_id)}}
    if(req.agent.integration_id)await store.touchIntegration(req.agent.integration_id,req.agent.organization_id);
    res.json({batch_id:batchId,accepted:accepted.length,rejected,duplicate:false});
  }catch(err){logger.warn('agent_batch_rejected',{error:err.message,agent_id:req.agent?.id||null});res.status(400).json({error:'invalid_batch',message:err.message})}
});
app.get('/api/admin/detection-rules',security.auth,security.requireRole('admin'),async(req,res)=>res.json({rules:await store.listRules(req.user.organization_id)}));
app.put('/api/admin/detection-rules/:ruleKey',security.auth,security.requireRole('admin'),async(req,res)=>{try{const body=req.body||{},rule={rule_key:String(req.params.ruleKey).trim(),name:String(body.name||'').slice(0,100),description:String(body.description||'').slice(0,500),enabled:body.enabled!==false,window_ms:Number(body.window_ms),threshold:Number(body.threshold),severities:Array.isArray(body.severities)?body.severities:[],categories:Array.isArray(body.categories)?body.categories.map(String):[],message_pattern:String(body.message_pattern||''),alert_severity:String(body.alert_severity||'HIGH').toUpperCase(),title:String(body.title||'Detection rule').slice(0,150)};if(!rule.rule_key||!rule.name||rule.window_ms<1000||rule.window_ms>86400000||!Number.isInteger(rule.threshold)||rule.threshold<1||rule.threshold>10000)throw Error('Invalid rule configuration');if(!['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(rule.alert_severity))throw Error('Invalid alert severity');if(!rule.severities.every(x=>['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(x)))throw Error('Invalid event severity');const patternMatch=rule.message_pattern.match(/^\/(.*)\/([a-z]*)$/i);new RegExp(patternMatch?patternMatch[1]:rule.message_pattern,patternMatch?patternMatch[2]:'');const saved=await store.upsertRule(rule,req.user.username,req.user.organization_id);await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'DETECTION_RULE_UPDATED',actor:req.user.username,target:rule.rule_key,status:rule.enabled?'ENABLED':'DISABLED'});res.json({rule:{...saved,enabled:Boolean(saved.enabled),severities:Array.isArray(saved.severities)?saved.severities:JSON.parse(saved.severities),categories:Array.isArray(saved.categories)?saved.categories:JSON.parse(saved.categories)}})}catch(err){res.status(400).json({error:err.message})}});
app.post('/api/ingest/event',security.apiKey,ingestRateLimit,async(req,res)=>{try{const e=normalize(req.body);const alert=await processEvent(e,req.ingestKey.organization_id);res.status(201).json({event:{...e,organization_id:req.ingestKey.organization_id},alert})}catch(err){logger.warn('event_rejected',{error:err.message});res.status(400).json({error:err.message})}});
app.post('/api/ingest/bulk',security.apiKey,bulkIngestRateLimit,async(req,res)=>{try{if(!Array.isArray(req.body)||req.body.length>1000)throw Error('Payload must contain 1-1000 events');const items=req.body.map(normalize).map(e=>({...e,organization_id:req.ingestKey.organization_id}));const alerts=[];await store.addEvents(items);metrics.events_ingested+=items.length;for(const e of items){const recent=await store.getRecentEvents(req.ingestKey.organization_id,e.source_ip,new Date(Date.now()-300000).toISOString());const a=detection.evaluate(e,recent,await store.getRules(req.ingestKey.organization_id));if(a&&!await store.getActiveAlert(req.ingestKey.organization_id,a.rule_key,a.source_ip)){const alert={...a,organization_id:req.ingestKey.organization_id};await store.addAlert(alert);metrics.alerts_created++;alerts.push(alert);broadcast({type:'alert',alert},false,req.ingestKey.organization_id)}broadcast({type:'event',event:e},true,req.ingestKey.organization_id)}res.status(201).json({count:items.length,alerts:alerts.length})}catch(err){logger.warn('bulk_rejected',{error:err.message});res.status(400).json({error:err.message})}});
app.get('/api/events',security.auth,async(req,res)=>{await store.prune();const severity=req.query.severity?String(req.query.severity).toUpperCase():'';const category=req.query.category?String(req.query.category):'';const search=req.query.search?String(req.query.search).trim():'';const offset=Math.max(0,Number.parseInt(req.query.offset,10)||0);const limit=Math.min(100,Math.max(1,Number.parseInt(req.query.limit,10)||50));const result=await store.getEvents({organization_id:req.user.organization_id,search,severity,category,limit,offset});res.json({events:result.events,total:result.total,offset,limit,hasMore:offset+limit<result.total})});
app.get('/api/alerts',security.auth,async(req,res)=>res.json({alerts:await store.getAlerts(req.user.organization_id,req.query.status?String(req.query.status):'')}));
app.patch('/api/alerts/:id',security.auth,async(req,res)=>{if(req.user.role!=='admin')return res.status(403).json({error:'Forbidden'});if(!['NEW','ACKNOWLEDGED','RESOLVED','CLOSED'].includes(req.body?.status))return res.status(400).json({error:'Invalid status'});const a=await store.updateAlert(req.params.id,req.body.status,req.user.username,req.user.organization_id);if(!a)return res.status(404).json({error:'Alert not found'});await store.addAudit({id:crypto.randomUUID(),organization_id:req.user.organization_id,timestamp:new Date().toISOString(),action:'ALERT_STATUS_CHANGE',actor:req.user.username,target:a.id,status:a.status});broadcast({type:'alert.updated',alert:a},false,req.user.organization_id);res.json({alert:a})});
app.get('/api/stats/summary',security.auth,async(req,res)=>res.json(await store.getStats(req.user.organization_id)));
app.get('/api/audit',security.auth,async(req,res)=>res.json({audit:await store.getAudit(req.user.organization_id)}));
app.use('/api',(_q,r)=>r.status(404).json({error:'Not Found'}));
const frontendDist=path.join(__dirname,'..','frontend','dist');
const frontendAssets=path.join(frontendDist,'assets');
app.use('/assets',express.static(frontendAssets,{fallthrough:false,setHeaders:res=>res.setHeader('Cache-Control','public,max-age=31536000,immutable')}));
app.use(express.static(frontendDist,{index:'index.html',setHeaders:(res,file)=>{if(file.endsWith('index.html'))res.setHeader('Cache-Control','no-store')}}));
app.get('*',(_q,r)=>r.sendFile(path.join(__dirname,'..','frontend','dist','index.html')));
app.use((err,req,res,_next)=>{if(res.headersSent)return;const status=err.type==='entity.too.large'?413:err.message==='Origin not allowed'?403:500;logger.error('request_failed',{request_id:req.requestId,error:err.message,status});res.status(status).json({error:status===413?'Payload too large':status===403?'Origin not allowed':'Internal server error',request_id:req.requestId})});
const wss=new WebSocketServer({noServer:true});let server;
function attachWebSocket(){server.on('upgrade',async(req,socket,head)=>{if(!req.url.startsWith('/ws'))return socket.destroy();const session=security.readCookie(req,security.COOKIE_NAME);try{req.user=await security.authenticatedUser(session)}catch{socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');return socket.destroy()}wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req))})}
wss.on('connection',(ws,req)=>{ws.organization_id=req.user.organization_id;ws.isAlive=true;ws.on('pong',()=>{ws.isAlive=true});ws.filter={};clients.add(ws);ws.on('message',raw=>{try{const msg=JSON.parse(raw.toString());if(msg.type==='subscribe')ws.filter={severity:['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(msg.severity)?msg.severity:'',search:String(msg.search||'').slice(0,100)}}catch{}});ws.on('close',()=>clients.delete(ws));ws.on('error',()=>{clients.delete(ws);ws.terminate()})});
function startServer(){server=app.listen(config.port,()=>logger.info('server_started',{port:config.port,env:config.env,instance:config.instanceId}));attachWebSocket();heartbeatTimer=setInterval(heartbeatClients,30000);heartbeatTimer.unref();return server}
let heartbeatTimer;
let shuttingDown=false;
function shutdown(signal){
  if(shuttingDown)return;
  shuttingDown=true;
  if(heartbeatTimer)clearInterval(heartbeatTimer);
  logger.info('server_shutdown_started',{signal});
  for(const ws of clients)ws.close(1001,'Server shutting down');
  wss.close();
  if(!server)return process.exit(0);
  server.close(async()=>{try{await store.close()}finally{logger.info('server_shutdown_complete');process.exit(0)}});
  setTimeout(async()=>{try{await store.close()}catch{}process.exit(1)},10000).unref();
}
if(require.main===module)startServer();
process.on('SIGTERM',()=>shutdown('SIGTERM'));
process.on('SIGINT',()=>shutdown('SIGINT'));
process.on('uncaughtException',err=>{logger.error('uncaught_exception',{error:err?.stack||String(err)});shutdown('uncaughtException')});
process.on('unhandledRejection',reason=>{logger.error('unhandled_rejection',{error:reason?.stack||String(reason)});shutdown('unhandledRejection')});
module.exports={app,startServer,normalize,processEvent,heartbeatClients,closeWebSocketClients};
