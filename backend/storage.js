const fs=require('fs');
const path=require('path');
const {dataDir,retentionDays}=require('./config');
const files={events:path.join(dataDir,'events.json'),alerts:path.join(dataDir,'alerts.json'),audit:path.join(dataDir,'audit.json')};
fs.mkdirSync(dataDir,{recursive:true});
function read(file,fallback=[]){try{return fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):fallback}catch{return fallback}}
function write(file,value){const tmp=file+'.tmp';fs.writeFileSync(tmp,JSON.stringify(value));fs.renameSync(tmp,file)}
let events=read(files.events),alerts=read(files.alerts),audit=read(files.audit);
function prune(){const cutoff=Date.now()-retentionDays*86400000;events=events.filter(e=>Date.parse(e.timestamp)>=cutoff);write(files.events,events.slice(-10000))}
module.exports={
 getEvents:()=>events,getAlerts:()=>alerts,getAudit:()=>audit,
 addEvents(items){events.push(...items);write(files.events,events.slice(-10000))},
 updateAlert(id,status,user){const a=alerts.find(x=>x.id===id);if(!a)return null;a.status=status;a.updated_at=new Date().toISOString();a.updated_by=user;write(files.alerts,alerts.slice(-5000));return a},
 addAlert(a){alerts.push(a);write(files.alerts,alerts.slice(-5000))},
 addAudit(a){audit.push(a);write(files.audit,audit.slice(-5000))},
 prune
};