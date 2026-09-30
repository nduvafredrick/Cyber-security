const crypto=require('crypto');const jwt=require('jsonwebtoken');const bcrypt=require('bcryptjs');const {jwtSecret,ingestKey,adminUser,adminPasswordHash}=require('./config');
const passwordHash=adminPasswordHash||(process.env.ADMIN_PASSWORD?bcrypt.hashSync(process.env.ADMIN_PASSWORD,12):null);
if(!passwordHash) throw new Error('Set ADMIN_PASSWORD_HASH or ADMIN_PASSWORD');
function token(user){return jwt.sign(user,jwtSecret,{expiresIn:'8h',issuer:'sentinel-siem'})}
function auth(req,res,next){try{req.user=jwt.verify((req.headers.authorization||'').replace(/^Bearer\s+/i,''),jwtSecret,{issuer:'sentinel-siem'});next()}catch{res.status(401).json({error:'Authentication required'})}}
function apiKey(req,res,next){const a=Buffer.from(String(req.headers['x-api-key']||'')),b=Buffer.from(ingestKey);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:'Invalid API key'});next()}
function login(username,password){if(username!==adminUser||!bcrypt.compareSync(password||'',passwordHash))return null;return {id:1,username:adminUser,role:'admin'}}
module.exports={token,auth,apiKey,login};