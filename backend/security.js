const crypto=require('crypto');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcryptjs');
const {jwtSecret,sessionCookieSecure,metricsApiKey,databaseUrl}=require('./config');
const store=require('./storage');

const COOKIE_NAME='sentinel_session';
function token(user){return jwt.sign({id:user.id,username:user.username,role:user.role},jwtSecret,{expiresIn:'8h',issuer:'sentinel-siem'})}
function verifyToken(value){return jwt.verify(value,jwtSecret,{issuer:'sentinel-siem'})}
function readCookie(req,name){const raw=String(req.headers.cookie||'');for(const part of raw.split(';')){const i=part.indexOf('=');if(i<0)continue;const k=part.slice(0,i).trim();if(k===name)return decodeURIComponent(part.slice(i+1).trim())}return ''}
function auth(req,res,next){try{const bearer=(req.headers.authorization||'').replace(/^Bearer\\s+/i,'');const value=bearer||readCookie(req,COOKIE_NAME);const session=verifyToken(value);const result=store.getUser(session.username);if(result&&typeof result.then==='function')return result.then(user=>{if(!user)throw Error('User disabled or removed');req.user={id:user.id,username:user.username,role:user.role};next()}).catch(()=>res.status(401).json({error:'Authentication required'}));if(!result)throw Error('User disabled or removed');req.user={id:result.id,username:result.username,role:result.role};next()}catch{res.status(401).json({error:'Authentication required'})}}
function apiKey(req,res,next){const supplied=String(req.headers['x-api-key']||'');const result=store.verifyIngestKey(supplied);if(result&&typeof result.then==='function')return result.then(key=>{if(!key)return res.status(401).json({error:'Invalid API key'});req.ingestKey=key;next()}).catch(()=>res.status(401).json({error:'Invalid API key'}));if(!result)return res.status(401).json({error:'Invalid API key'});req.ingestKey=result;next()}
function metricsAuth(req,res,next){
  if(process.env.NODE_ENV!=='production')return next();
  const supplied=String(req.headers['x-metrics-key']||'');
  const a=Buffer.from(supplied),b=Buffer.from(metricsApiKey||'');
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:'Metrics authentication required'});
  next();
}
function login(username,password){const result=store.getUser(String(username||''));if(result&&typeof result.then==='function')return result.then(user=>user&&bcrypt.compareSync(String(password||''),user.password_hash)?{id:user.id,username:user.username,role:user.role}:null);if(!result||!bcrypt.compareSync(String(password||''),result.password_hash))return null;return {id:result.id,username:result.username,role:result.role}}
function setSession(res,value){const secure=sessionCookieSecure?' Secure':'';res.setHeader('Set-Cookie',COOKIE_NAME+'='+encodeURIComponent(value)+'; HttpOnly;'+secure+' SameSite=Strict; Path=/; Max-Age=28800')}
function clearSession(res,value=''){const secure=sessionCookieSecure?' Secure':'';res.setHeader('Set-Cookie',COOKIE_NAME+'='+encodeURIComponent(value)+'; HttpOnly;'+secure+' SameSite=Strict; Path=/; Max-Age=0')}
function requireRole(role){return (req,res,next)=>{if(req.user?.role!==role)return res.status(403).json({error:'Forbidden'});next()}}
function generateIngestKey(){return 'sk_'+crypto.randomBytes(24).toString('base64url')}
module.exports={token,verifyToken,auth,apiKey,metricsAuth,login,setSession,clearSession,COOKIE_NAME,readCookie,requireRole,generateIngestKey};
