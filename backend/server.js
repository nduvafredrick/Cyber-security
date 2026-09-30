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
app.use(helmet(config.upgradeInsecureRequests?{}:{contentSecurityPolicy:false,hsts:config.hsts}));
app.use(cors({credentials:true,origin:(origin,cb)=>!origin||config.corsOrigins.includes(origin)?cb(null,true):cb(new Error('Origin not allowed'))}));
app.use(express.json({limit:'1mb'}));
app.use('/api',(_q,r,n)=>{r.set('Cache-Control','no-store');n()});
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
function matches(event,filter={}){const q=String(filter.search||'').trim().toLowerCase();return(!filter.severity||event.severity===filter.severity)&&(!q||event.message.toLowerCase().includes(q)||event.category.toLowerCase().includes(q)||event.source_ip.toLowerCase().includes(q)||event.hostname.toLowerCase().includes(q))}
function broadcast(payload,filterable=false){for(const ws of clients){if(ws.readyState!==1)continue;if(filterable&&payload.type==='event'&&!matches(payload.event,ws.filter))continue;try{ws.send(JSON.stringify(payload))}catch{ws.terminate();clients.delete(ws)}}}
function processEvent(e){store.addEvents([e]);const recent=store.getRecentEvents(e.source_ip,new Date(Date.now()-300000).toISOString());const alert=detection.evaluate(e,recent,store.getRules());let createdAlert=null;if(alert&&!store.getActiveAlert(alert.rule_key,alert.source_ip)){store.addAlert(alert);createdAlert=alert;broadcast({type:'alert',alert})}broadcast({type:'event',event:e},true);return createdAlert}
app.get('/health',(_q,r)=>r.json({status:'ok',service:'sentinel-siem',version:'3.1.0'}));
app.get('/ready',(_q,r)=>{try{store.health();r.json({status:'ready',database:'ok',instance:config.instanceId})}catch(err){logger.error('readiness_failed',{error:err.message});r.status(503).json({status:'not_ready',database:'error'})}});
app.post('/api/auth/login',rateLimit({windowMs:900000,limit:10,standardHeaders:true,legacyHeaders:false}),(req,res)=>{const user=security.login(req.body?.username,req.body?.password);if(!user)return res.status(401).json({error:'Invalid credentials'});store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'LOGIN_SUCCESS',actor:user.username});security.setSession(res,security.token(user));logger.info('authentication_success',{actor:user.username});res.json({user})});
app.post('/api/auth/logout',security.auth,(req,res)=>{security.clearSession(res);store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'LOGOUT',actor:req.user.username});res.status(204).end()});
app.get('/api/auth/me',security.auth,(req,res)=>res.json({user:req.user}));
app.get('/api/admin/users',security.auth,security.requireRole('admin'),(_req,res)=>res.json({users:store.listUsers()}));
app.post('/api/admin/users',security.auth,security.requireRole('admin'),(req,res)=>{try{const username=String(req.body?.username||'').trim(),password=String(req.body?.password||''),role=req.body?.role==='admin'?'admin':'analyst';if(!/^[a-zA-Z0-9._-]{3,50}$/.test(username))throw Error('Invalid username');if(password.length<12)throw Error('Password must be at least 12 characters');const id=store.addUser({username,password_hash:bcrypt.hashSync(password,12),role});store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'USER_CREATED',actor:req.user.username,target:username,status:role});res.status(201).json({user:store.listUsers().find(x=>x.id===id)})}catch(err){res.status(400).json({error:/UNIQUE|constraint/i.test(err.message)?'Username already exists':err.message})}});
app.patch('/api/admin/users/:id',security.auth,security.requireRole('admin'),(req,res)=>{if(Number(req.params.id)===req.user.id&&req.body?.enabled===false)return res.status(400).json({error:'You cannot disable your own account'});const user=store.setUserEnabled(Number(req.params.id),req.body?.enabled!==false);if(!user)return res.status(404).json({error:'User not found'});store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'USER_STATUS_CHANGE',actor:req.user.username,target:user.username,status:user.enabled?'ENABLED':'DISABLED'});res.json({user})});
app.get('/api/admin/ingest-keys',security.auth,security.requireRole('admin'),(_req,res)=>res.json({keys:store.getIngestKeys()}));
app.post('/api/admin/ingest-keys/rotate',security.auth,security.requireRole('admin'),(req,res)=>{for(const existing of store.getIngestKeys().filter(k=>k.enabled))store.revokeIngestKey(existing.id,req.user.username);const raw=security.generateIngestKey(),key={id:crypto.randomUUID(),name:String(req.body?.name||'rotated-key').slice(0,80),raw,hash:crypto.createHash('sha256').update(raw).digest('hex'),created_by:req.user.username};const record=store.createIngestKey(key);store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'INGEST_KEY_CREATED',actor:req.user.username,target:record.id,status:'ACTIVE'});res.status(201).json({key:raw,record})});
app.delete('/api/admin/ingest-keys/:id',security.auth,security.requireRole('admin'),(req,res)=>{const key=store.revokeIngestKey(req.params.id,req.user.username);if(!key)return res.status(404).json({error:'Key not found'});store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'INGEST_KEY_REVOKED',actor:req.user.username,target:key.id,status:'REVOKED'});res.json({key})});
app.get('/api/admin/detection-rules',security.auth,security.requireRole('admin'),(_req,res)=>res.json({rules:store.listRules()}));
app.put('/api/admin/detection-rules/:ruleKey',security.auth,security.requireRole('admin'),(req,res)=>{try{const body=req.body||{},rule={rule_key:String(req.params.ruleKey).trim(),name:String(body.name||'').slice(0,100),description:String(body.description||'').slice(0,500),enabled:body.enabled!==false,window_ms:Number(body.window_ms),threshold:Number(body.threshold),severities:Array.isArray(body.severities)?body.severities:[],categories:Array.isArray(body.categories)?body.categories.map(String):[],message_pattern:String(body.message_pattern||''),alert_severity:String(body.alert_severity||'HIGH').toUpperCase(),title:String(body.title||'Detection rule').slice(0,150)};if(!rule.rule_key||!rule.name||rule.window_ms<1000||rule.window_ms>86400000||!Number.isInteger(rule.threshold)||rule.threshold<1||rule.threshold>10000)throw Error('Invalid rule configuration');if(!['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(rule.alert_severity))throw Error('Invalid alert severity');if(!rule.severities.every(x=>['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(x)))throw Error('Invalid event severity');const patternMatch=rule.message_pattern.match(/^\/(.*)\/([a-z]*)$/i);new RegExp(patternMatch?patternMatch[1]:rule.message_pattern,patternMatch?patternMatch[2]:'');const saved=store.upsertRule(rule,req.user.username);store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'DETECTION_RULE_UPDATED',actor:req.user.username,target:rule.rule_key,status:rule.enabled?'ENABLED':'DISABLED'});res.json({rule:{...saved,enabled:Boolean(saved.enabled),severities:JSON.parse(saved.severities),categories:JSON.parse(saved.categories)}})}catch(err){res.status(400).json({error:err.message})}});
app.post('/api/ingest/event',security.apiKey,(req,res)=>{try{const e=normalize(req.body);const alert=processEvent(e);res.status(201).json({event:e,alert})}catch(err){logger.warn('event_rejected',{error:err.message});res.status(400).json({error:err.message})}});
app.post('/api/ingest/bulk',security.apiKey,(req,res)=>{try{if(!Array.isArray(req.body)||req.body.length>1000)throw Error('Payload must contain 1-1000 events');const items=req.body.map(normalize);const alerts=[];store.addEvents(items);for(const e of items){const recent=store.getRecentEvents(e.source_ip,new Date(Date.now()-300000).toISOString());const a=detection.evaluate(e,recent,store.getRules());if(a&&!store.getActiveAlert(a.rule_key,a.source_ip)){store.addAlert(a);alerts.push(a);broadcast({type:'alert',alert:a})}broadcast({type:'event',event:e},true)}res.status(201).json({count:items.length,alerts:alerts.length})}catch(err){logger.warn('bulk_rejected',{error:err.message});res.status(400).json({error:err.message})}});
app.get('/api/events',security.auth,(req,res)=>{store.prune();const severity=req.query.severity?String(req.query.severity).toUpperCase():'';const category=req.query.category?String(req.query.category):'';const search=req.query.search?String(req.query.search).trim():'';const offset=Math.max(0,Number.parseInt(req.query.offset,10)||0);const limit=Math.min(100,Math.max(1,Number.parseInt(req.query.limit,10)||50));const result=store.getEvents({search,severity,category,limit,offset});res.json({events:result.events,total:result.total,offset,limit,hasMore:offset+limit<result.total})});
app.get('/api/alerts',security.auth,(req,res)=>res.json({alerts:store.getAlerts(req.query.status?String(req.query.status):'')}));
app.patch('/api/alerts/:id',security.auth,(req,res)=>{if(req.user.role!=='admin')return res.status(403).json({error:'Forbidden'});if(!['NEW','ACKNOWLEDGED','RESOLVED','CLOSED'].includes(req.body?.status))return res.status(400).json({error:'Invalid status'});const a=store.updateAlert(req.params.id,req.body.status,req.user.username);if(!a)return res.status(404).json({error:'Alert not found'});store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'ALERT_STATUS_CHANGE',actor:req.user.username,target:a.id,status:a.status});broadcast({type:'alert.updated',alert:a});res.json({alert:a})});
app.get('/api/stats/summary',security.auth,(_q,res)=>res.json(store.getStats()));
app.get('/api/audit',security.auth,(_q,res)=>res.json({audit:store.getAudit()}));
app.use('/api',(_q,r)=>r.status(404).json({error:'Not Found'}));
app.use(express.static(path.join(__dirname,'..','frontend','dist'),{setHeaders:(res,file)=>{if(file.endsWith('index.html'))res.setHeader('Cache-Control','no-store');else res.setHeader('Cache-Control','public,max-age=31536000,immutable')}}));
app.get('*',(_q,r)=>r.sendFile(path.join(__dirname,'..','frontend','dist','index.html')));
const wss=new WebSocketServer({noServer:true});let server;
function attachWebSocket(){server.on('upgrade',(req,socket,head)=>{if(!req.url.startsWith('/ws'))return socket.destroy();const token=security.readCookie(req,security.COOKIE_NAME);try{security.verifyToken(token)}catch{socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');return socket.destroy()}wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req))})}
wss.on('connection',ws=>{ws.filter={};clients.add(ws);ws.on('message',raw=>{try{const msg=JSON.parse(raw.toString());if(msg.type==='subscribe')ws.filter={severity:['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(msg.severity)?msg.severity:'',search:String(msg.search||'').slice(0,100)}}catch{}});ws.on('close',()=>clients.delete(ws));ws.on('error',()=>{clients.delete(ws);ws.terminate()})});
function startServer(){server=app.listen(config.port,()=>logger.info('server_started',{port:config.port,env:config.env,instance:config.instanceId}));attachWebSocket();return server}
if(require.main===module)startServer();
process.on('SIGTERM',()=>server?.close(()=>process.exit(0)));process.on('SIGINT',()=>server?.close(()=>process.exit(0)));
module.exports={app,startServer,normalize,processEvent};
