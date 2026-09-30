const crypto=require('crypto');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcryptjs');
const {jwtSecret,sessionCookieSecure}=require('./config');
const store=require('./storage');

const COOKIE_NAME='sentinel_session';
function token(user){return jwt.sign({id:user.id,username:user.username,role:user.role},jwtSecret,{expiresIn:'8h',issuer:'sentinel-siem'})}
function verifyToken(value){return jwt.verify(value,jwtSecret,{issuer:'sentinel-siem'})}
function readCookie(req,name){const raw=String(req.headers.cookie||'');for(const part of raw.split(';')){const i=part.indexOf('=');if(i<0)continue;const k=part.slice(0,i).trim();if(k===name)return decodeURIComponent(part.slice(i+1).trim())}return ''}
function auth(req,res,next){try{const bearer=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');const value=bearer||readCookie(req,COOKIE_NAME);const session=verifyToken(value);const user=store.getUser(session.username);if(!user)throw Error('User disabled or removed');req.user={id:user.id,username:user.username,role:user.role};next()}catch{res.status(401).json({error:'Authentication required'})}}
function apiKey(req,res,next){const supplied=String(req.headers['x-api-key']||'');const key=store.verifyIngestKey(supplied);if(!key)return res.status(401).json({error:'Invalid API key'});req.ingestKey=key;next()}
function login(username,password){const user=store.getUser(String(username||''));if(!user||!bcrypt.compareSync(String(password||''),user.password_hash))return null;return {id:user.id,username:user.username,role:user.role}}
function setSession(res,value){const secure=sessionCookieSecure?' Secure':'';res.setHeader('Set-Cookie',COOKIE_NAME+'='+encodeURIComponent(value)+'; HttpOnly;'+secure+' SameSite=Strict; Path=/; Max-Age=28800')}
function clearSession(res,value=''){const secure=sessionCookieSecure?' Secure':'';res.setHeader('Set-Cookie',COOKIE_NAME+'='+encodeURIComponent(value)+'; HttpOnly;'+secure+' SameSite=Strict; Path=/; Max-Age=0')}
function requireRole(role){return (req,res,next)=>{if(req.user?.role!==role)return res.status(403).json({error:'Forbidden'});next()}}
function generateIngestKey(){return 'sk_'+crypto.randomBytes(24).toString('base64url')}
module.exports={token,verifyToken,auth,apiKey,login,setSession,clearSession,COOKIE_NAME,readCookie,requireRole,generateIngestKey};
