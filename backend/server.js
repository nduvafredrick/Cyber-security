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

const app=express();
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({credentials:true,origin:(origin,cb)=>!origin||config.corsOrigins.includes(origin)?cb(null,true):cb(new Error('Origin not allowed'))}));
app.use(express.json({limit:'1mb'}));
app.use('/api',(_q,r,n)=>{r.set('Cache-Control','no-store');n()});
app.use((req,res,next)=>{const started=Date.now();res.on('finish',()=>logger.info('http_request',{method:req.method,path:req.path,status:res.statusCode,duration_ms:Date.now()-started}));next()});

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
function matches(event,filter={}){
  const q=String(filter.search||'').trim().toLowerCase();
  return (!filter.severity||event.severity===filter.severity)&&(!q||event.message.toLowerCase().includes(q)||event.category.toLowerCase().includes(q)||event.source_ip.toLowerCase().includes(q)||event.hostname.toLowerCase().includes(q));
}
function broadcast(payload,filterable=false){
  for(const ws of clients){
    if(ws.readyState!==1)continue;
    if(filterable&&payload.type==='event'&&!matches(payload.event,ws.filter))continue;
    try{ws.send(JSON.stringify(payload))}catch{ws.terminate();clients.delete(ws)}
  }
}
function processEvent(e){
  store.addEvents([e]);
  const recent=store.getRecentEvents(e.source_ip,new Date(Date.now()-300000).toISOString());
  const alert=detection.evaluate(e,recent);
  let createdAlert=null;
  if(alert && !store.getActiveAlert(alert.rule_key,alert.source_ip)){
    store.addAlert(alert);
    createdAlert=alert;
    broadcast({type:'alert',alert});
  }
  broadcast({type:'event',event:e},true);
  return createdAlert;
}

app.get('/health',(_q,r)=>r.json({status:'ok',service:'sentinel-siem',version:'3.1.0'}));
app.get('/ready',(_q,r)=>{try{store.health();r.json({status:'ready',database:'ok',instance:config.instanceId})}catch(err){logger.error('readiness_failed',{error:err.message});r.status(503).json({status:'not_ready',database:'error'})}});

app.post('/api/auth/login',rateLimit({windowMs:900000,limit:10,standardHeaders:true,legacyHeaders:false}),(req,res)=>{
  const user=security.login(req.body?.username,req.body?.password);
  if(!user)return res.status(401).json({error:'Invalid credentials'});
  store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'LOGIN_SUCCESS',actor:user.username});
  security.setSession(res,security.token(user));
  logger.info('authentication_success',{actor:user.username});
  res.json({user});
});
app.post('/api/auth/logout',security.auth,(req,res)=>{security.clearSession(res);store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'LOGOUT',actor:req.user.username});res.status(204).end()});
app.get('/api/auth/me',security.auth,(req,res)=>res.json({user:req.user}));

app.post('/api/ingest/event',security.apiKey,(req,res)=>{
  try{const e=normalize(req.body);const alert=processEvent(e);res.status(201).json({event:e,alert})}
  catch(err){logger.warn('event_rejected',{error:err.message});res.status(400).json({error:err.message})}
});
app.post('/api/ingest/bulk',security.apiKey,(req,res)=>{
  try{
    if(!Array.isArray(req.body)||req.body.length>1000)throw Error('Payload must contain 1-1000 events');
    const items=req.body.map(normalize);
    const alerts=[];
    store.addEvents(items);
    for(const e of items){
      const recent=store.getRecentEvents(e.source_ip,new Date(Date.now()-300000).toISOString());
      const a=detection.evaluate(e,recent);
      if(a && !store.getActiveAlert(a.rule_key,a.source_ip)){store.addAlert(a);alerts.push(a);broadcast({type:'alert',alert:a})}
      broadcast({type:'event',event:e},true);
    }
    res.status(201).json({count:items.length,alerts:alerts.length});
  }catch(err){logger.warn('bulk_rejected',{error:err.message});res.status(400).json({error:err.message})}
});

app.get('/api/events',security.auth,(req,res)=>{
  store.prune();
  const severity=req.query.severity?String(req.query.severity).toUpperCase():'';
  const category=req.query.category?String(req.query.category):'';
  const search=req.query.search?String(req.query.search).trim():'';
  const offset=Math.max(0,Number.parseInt(req.query.offset,10)||0);
  const limit=Math.min(100,Math.max(1,Number.parseInt(req.query.limit,10)||50));
  const result=store.getEvents({search,severity,category,limit,offset});
  res.json({events:result.events,total:result.total,offset,limit,hasMore:offset+limit<result.total});
});
app.get('/api/alerts',security.auth,(req,res)=>res.json({alerts:store.getAlerts(req.query.status?String(req.query.status):'')}));
app.patch('/api/alerts/:id',security.auth,(req,res)=>{
  if(req.user.role!=='admin')return res.status(403).json({error:'Forbidden'});
  if(!['NEW','ACKNOWLEDGED','RESOLVED','CLOSED'].includes(req.body?.status))return res.status(400).json({error:'Invalid status'});
  const a=store.updateAlert(req.params.id,req.body.status,req.user.username);
  if(!a)return res.status(404).json({error:'Alert not found'});
  store.addAudit({id:crypto.randomUUID(),timestamp:new Date().toISOString(),action:'ALERT_STATUS_CHANGE',actor:req.user.username,target:a.id,status:a.status});
  broadcast({type:'alert.updated',alert:a});
  res.json({alert:a});
});
app.get('/api/stats/summary',security.auth,(_q,res)=>res.json(store.getStats()));
app.get('/api/audit',security.auth,(_q,res)=>res.json({audit:store.getAudit()}));
app.use('/api',(_q,r)=>r.status(404).json({error:'Not Found'}));
app.use(express.static(path.join(__dirname,'..','frontend','dist'),{maxAge:'1h',immutable:true}));
app.get('*',(_q,r)=>r.sendFile(path.join(__dirname,'..','frontend','dist','index.html')));

const wss=new WebSocketServer({noServer:true});
let server;
function attachWebSocket(){
  server.on('upgrade',(req,socket,head)=>{
    if(!req.url.startsWith('/ws'))return socket.destroy();
    const token=security.readCookie(req,security.COOKIE_NAME);
    try{security.verifyToken(token)}catch{socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');return socket.destroy()}
    wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req));
  });
}
wss.on('connection',ws=>{
  ws.filter={};
  clients.add(ws);
  ws.on('message',raw=>{
    try{
      const msg=JSON.parse(raw.toString());
      if(msg.type==='subscribe')ws.filter={severity:['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(msg.severity)?msg.severity:'',search:String(msg.search||'').slice(0,100)};
    }catch{}
  });
  ws.on('close',()=>clients.delete(ws));
  ws.on('error',()=>{clients.delete(ws);ws.terminate()});
});

function startServer(){
  server=app.listen(config.port,()=>logger.info('server_started',{port:config.port,env:config.env,instance:config.instanceId}));
  attachWebSocket();
  return server;
}
if(require.main===module)startServer();
process.on('SIGTERM',()=>server?.close(()=>process.exit(0)));
process.on('SIGINT',()=>server?.close(()=>process.exit(0)));

module.exports={app,startServer,normalize,processEvent};