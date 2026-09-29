import express from "express";
import helmet from "helmet";
import cors from "cors";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import { z } from "zod";

const app=express();
const PORT=Number(process.env.PORT||3000);
const JWT_SECRET=process.env.JWT_SECRET;
const INGEST_API_KEY=process.env.INGEST_API_KEY;
if(!JWT_SECRET||JWT_SECRET.length<32) throw new Error("JWT_SECRET must be at least 32 characters");
if(!INGEST_API_KEY||INGEST_API_KEY.length<24) throw new Error("INGEST_API_KEY must be at least 24 characters");
app.disable("x-powered-by");
app.use(helmet({contentSecurityPolicy:false}));
app.use(cors({origin:process.env.CORS_ORIGIN||"http://localhost:3000"}));
app.use(express.json({limit:"256kb"}));

const db=new Database(process.env.DB_PATH||"./sentinel.db");
db.pragma("journal_mode=WAL");
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL,org_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,org_id TEXT NOT NULL,source TEXT NOT NULL,severity TEXT NOT NULL,event_type TEXT NOT NULL,message TEXT NOT NULL,src_ip TEXT,timestamp TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,org_id TEXT NOT NULL,event_id INTEGER,severity TEXT NOT NULL,title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'NEW',created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY,org_id TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL,result TEXT NOT NULL,ip TEXT,created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_org_time ON events(org_id,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_org_status ON alerts(org_id,status);`);

function hashPassword(p){const s=crypto.randomBytes(16);return s.toString("hex")+":"+crypto.scryptSync(p,s,64).toString("hex")}
function verifyPassword(p,v){const [s,h]=v.split(":");const a=crypto.scryptSync(p,Buffer.from(s,"hex"),64);return crypto.timingSafeEqual(a,Buffer.from(h,"hex"))}
function audit(org,actor,action,res,result,req){db.prepare("INSERT INTO audit_logs(org_id,actor,action,resource,result,ip,created_at) VALUES(?,?,?,?,?,?,?)").run(org,actor,action,res,result,req.ip,new Date().toISOString())}

const adminPassword=process.env.ADMIN_PASSWORD;
if(adminPassword&&!db.prepare("SELECT 1 FROM users WHERE username='admin'").get()) db.prepare("INSERT INTO users(username,password_hash,role,org_id) VALUES(?,?,?,?)").run("admin",hashPassword(adminPassword),"admin","default");

const loginSchema=z.object({username:z.string().min(1).max(64),password:z.string().min(1).max(256)});
const eventSchema=z.object({source:z.string().min(1).max(128),severity:z.enum(["low","medium","high","critical"]),event_type:z.string().min(1).max(128),message:z.string().min(1).max(4000),src_ip:z.string().max(64).optional(),timestamp:z.string().datetime().optional()});

function auth(req,res,next){try{const h=req.get("authorization")||"";if(!h.startsWith("Bearer "))return res.status(401).json({error:"Authentication required"});const t=jwt.verify(h.slice(7),JWT_SECRET,{algorithms:["HS256"],issuer:"sentinel-siem"});const u=db.prepare("SELECT id,username,role,org_id FROM users WHERE id=?").get(t.sub);if(!u)return res.status(401).json({error:"Invalid session"});req.user=u;next()}catch{res.status(401).json({error:"Invalid session"})}}
function ingestAuth(req,res,next){const a=Buffer.from(req.get("x-api-key")||"");const b=Buffer.from(INGEST_API_KEY);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:"Invalid ingestion key"});next()}

app.get("/health",(_,res)=>res.json({status:"ok",service:"sentinel-siem"}));
app.post("/api/auth/login",(req,res)=>{const p=loginSchema.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Invalid credentials format"});const u=db.prepare("SELECT * FROM users WHERE username=?").get(p.data.username);if(!u||!verifyPassword(p.data.password,u.password_hash))return res.status(401).json({error:"Invalid username or password"});const token=jwt.sign({sub:String(u.id),role:u.role},JWT_SECRET,{algorithm:"HS256",expiresIn:"15m",issuer:"sentinel-siem"});audit(u.org_id,u.username,"LOGIN","session","SUCCESS",req);res.json({token,user:{id:u.id,username:u.username,role:u.role,org_id:u.org_id}})});
app.get("/api/auth/me",auth,(req,res)=>res.json({user:req.user}));

app.post("/api/ingest/event",ingestAuth,(req,res)=>{const p=eventSchema.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Invalid event"});const e=p.data,org=String(req.get("x-org-id")||"default").slice(0,64),ts=e.timestamp||new Date().toISOString();const x=db.prepare("INSERT INTO events(org_id,source,severity,event_type,message,src_ip,timestamp) VALUES(?,?,?,?,?,?,?)").run(org,e.source,e.severity,e.event_type,e.message,e.src_ip||null,ts);if(["high","critical"].includes(e.severity))db.prepare("INSERT INTO alerts(org_id,event_id,severity,title,created_at) VALUES(?,?,?,?,?)").run(org,x.lastInsertRowid,e.severity,`${e.severity.toUpperCase()} event from ${e.source}`,new Date().toISOString());res.status(201).json({id:x.lastInsertRowid})});

app.get("/api/events",auth,(req,res)=>{const limit=Math.min(Math.max(Number(req.query.limit)||50,1),100);res.json({events:db.prepare("SELECT * FROM events WHERE org_id=? ORDER BY id DESC LIMIT ?").all(req.user.org_id,limit)})});
app.get("/api/alerts",auth,(req,res)=>res.json({alerts:db.prepare("SELECT * FROM alerts WHERE org_id=? ORDER BY id DESC LIMIT 100").all(req.user.org_id)}));
app.patch("/api/alerts/:id",auth,(req,res)=>{const p=z.enum(["NEW","ACKNOWLEDGED","INVESTIGATING","RESOLVED"]).safeParse(req.body?.status);if(!p.success)return res.status(400).json({error:"Invalid status"});const x=db.prepare("UPDATE alerts SET status=? WHERE id=? AND org_id=?").run(p.data,req.params.id,req.user.org_id);if(!x.changes)return res.status(404).json({error:"Alert not found"});audit(req.user.org_id,req.user.username,"UPDATE","alert:"+req.params.id,p.data,req);res.json({ok:true})});
app.get("/api/stats/summary",auth,(req,res)=>{const o=req.user.org_id;res.json({events:db.prepare("SELECT COUNT(*) n FROM events WHERE org_id=?").get(o).n,open_alerts:db.prepare("SELECT COUNT(*) n FROM alerts WHERE org_id=? AND status!='RESOLVED'").get(o).n,critical:db.prepare("SELECT COUNT(*) n FROM alerts WHERE org_id=? AND severity='critical' AND status!='RESOLVED'").get(o).n})});
app.get("/api/audit",auth,(req,res)=>{if(req.user.role!=="admin")return res.status(403).json({error:"Admin role required"});res.json({logs:db.prepare("SELECT * FROM audit_logs WHERE org_id=? ORDER BY id DESC LIMIT 100").all(req.user.org_id)})});

app.use(express.static("frontend"));
app.listen(PORT,()=>console.log(`Sentinel SIEM listening on :${PORT}`));