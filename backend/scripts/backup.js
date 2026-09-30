const fs=require('fs');
const path=require('path');
const Database=require('better-sqlite3');
const {dataDir,backupDir,backupRetentionCount}=require('../config');

const source=path.join(dataDir,'sentinel.db');
if(!fs.existsSync(source))throw new Error('Database not found: '+source);
fs.mkdirSync(backupDir,{recursive:true});

function verify(file){
  const db=new Database(file,{readonly:true});
  try{
    const result=db.pragma('integrity_check',{simple:true});
    if(result!=='ok')throw new Error('SQLite integrity check failed: '+result);
    return result;
  }finally{db.close()}
}

function pruneBackups(){
  const files=fs.readdirSync(backupDir)
    .filter(name=>/^sentinel-.*\.db$/.test(name))
    .map(name=>({name,mtime:fs.statSync(path.join(backupDir,name)).mtimeMs}))
    .sort((a,b)=>b.mtime-a.mtime);
  const deleted=[];
  for(const file of files.slice(backupRetentionCount)){
    fs.rmSync(path.join(backupDir,file.name));
    deleted.push(file.name);
  }
  return {retained:Math.min(files.length,backupRetentionCount),deleted};
}

const stamp=new Date().toISOString().replace(/[:.]/g,'-');
const destination=path.join(backupDir,`sentinel-${stamp}.db`);
const db=new Database(source,{readonly:true});
db.backup(destination).then(()=>{
  try{
    const size=fs.statSync(destination).size;
    if(size<1024)throw new Error('Backup is unexpectedly small');
    const integrity=verify(destination);
    const cleanup=pruneBackups();
    process.stdout.write(JSON.stringify({status:'ok',source,destination,size,integrity,...cleanup})+'\n');
  }catch(err){
    try{fs.rmSync(destination,{force:true})}catch{}
    throw err;
  }finally{
    db.close();
  }
}).catch(err=>{
  try{db.close()}catch{}
  console.error(err.message);
  process.exitCode=1;
});
