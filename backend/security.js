const crypto=require('crypto');const jwt=require('jsonwebtoken');const bcrypt=require('bcryptjs');const {jwtSecret,ingestKey,adminUser,adminPasswordHash}=require('./config');
const passwordHash=adminPasswordHash||(process.env.ADMIN_PASSWORD?bcrypt.hashSync(process.env.ADMIN_PASSWORD,12):null);
if(!passwordHash) throw new Error('Set ADMIN_PASSWORD_HASH or ADMIN_PASSWORD');
const COOKIE_NAME='sentinel_session';
function token(user){return jwt.sign(user,jwtSecret,{expiresIn:'8h',issuer:'sentinel-siem'})}
function verifyToken(value){return jwt.verify(value,jwtSecret,{issuer:'sentinel-siem'})}
function readCookie(req,name){const raw=String(req.headers.cookie||'');for(const part of raw.split(';')){const i=part.indexOf('=');if(i<0)continue;const k=part.slice(0,i).trim();if(k===name)return decodeURIComponent(part.slice(i+1).trim())}return ''}
function auth(req,res,next){try{const bearer=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');const value=bearer||readCookie(req,COOKIE_NAME);req.user=verifyToken(value);next()}catch{res.status(401).json({error:'Authentication required'})}}
function apiKey(req,res,next){const a=Buffer.from(String(req.headers['x-api-key']||'')),b=Buffer.from(ingestKey);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:'Invalid API key'});next()}
function login(username,password){if(username!==adminUser||!bcrypt.compareSync(password||'',passwordHash))return null;return {id:1,username:adminUser,role:'admin'}}
function setSession(res,value){res.setHeader('Set-Cookie',`${COOKIE_NAME}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`)}
function clearSession(res){res.setHeader('Set-Cookie',`${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`)}
module.exports={token,verifyToken,auth,apiKey,login,setSession,clearSession,COOKIE_NAME,readCookie};