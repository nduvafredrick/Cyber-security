const fs=require('fs');
const path=require('path');
const Database=require('better-sqlite3');
const {dataDir,backupDir}=require('../config');

const source=path.join(dataDir,'sentinel.db');
if(!fs.existsSync(source))throw new Error('Database not found: '+source);
fs.mkdirSync(backupDir,{recursive:true});

const stamp=new Date().toISOString().replace(/[:.]/g,'-');
const destination=path.join(backupDir,`sentinel-${stamp}.db`);
const db=new Database(source,{readonly:true});
try{
  db.backup(destination).then(()=>{
    const size=fs.statSync(destination).size;
    if(size<1024)throw new Error('Backup is unexpectedly small');
    process.stdout.write(JSON.stringify({status:'ok',source,destination,size})+'\n');
    db.close();
  }).catch(err=>{
    try{db.close()}catch{}
    console.error(err.message);
    process.exitCode=1;
  });
}catch(err){
  try{db.close()}catch{}
  throw err;
}
