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
const onboardingRateLimit=rateLimit({windowMs:3600000,limit:5,standardHeaders:true,legacyHeaders:false,message:()=>({error:'Too many onboarding attempts. Please try again later.'})});
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
function heartbeatClients(){
  for(const ws of clients){
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
app.post('/api/auth/login',rateLimit({windowMs:900000,limit:10,standardHeaders:true,legacyHeaders:false}),async(req,res)=>{const user=await security.login(req.body?.username,req.body?.password);if(!user)return res.status(401).json({error:'Invalid credentials'});await store.addAudit({id:crypto.randomUUID(),organization_id:user.organization_id,timestamp:new Date().toISOString(),action:'LOGIN_SUCCESS',actor:user.username});security.setSession(res,security.token(user));logger.info('authentication_success',{actor:user.username,organization_id:user.organization_id});res.json({user,organization:await store.getOrganization(user.organization_id)})});
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
app.use((err,req,res,_next)=>{if(res.headersSent)return;const status=err.message==='Origin not allowed'?403:500;logger.error('request_failed',{request_id:req.requestId,error:err.message,status});res.status(status).json({error:status===403?'Origin not allowed':'Internal server error',request_id:req.requestId})});
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
