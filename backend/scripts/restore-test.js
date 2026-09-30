const fs=require('fs');
const path=require('path');
const os=require('os');
const Database=require('better-sqlite3');
const {backupDir}=require('../config');

const expectedTables=['events','alerts','users','ingest_keys','detection_rules','audit'];

const backups=fs.readdirSync(backupDir,{withFileTypes:true})
  .filter(entry=>entry.isFile()&&/^sentinel-.*\.db$/.test(entry.name))
  .map(entry=>({name:entry.name,mtime:fs.statSync(path.join(backupDir,entry.name)).mtimeMs}))
  .sort((a,b)=>b.mtime-a.mtime);

if(!backups.length)throw new Error('No SQLite backups found');

const source=path.join(backupDir,backups[0].name);
const temp=path.join(os.tmpdir(),`sentinel-restore-test-${process.pid}-${Date.now()}.db`);
fs.copyFileSync(source,temp);

try{
  const db=new Database(temp,{readonly:true});
  try{
    const integrity=db.pragma('integrity_check',{simple:true});
    if(integrity!=='ok')throw new Error('SQLite integrity check failed: '+integrity);
    const tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map(row=>row.name);
    for(const table of expectedTables){
      if(!tables.includes(table))throw new Error('Restored backup is missing table: '+table);
    }
    const counts=Object.fromEntries(expectedTables.map(table=>[table,db.prepare(`SELECT COUNT(*) AS count FROM "${table}"`).get().count]));
    process.stdout.write(JSON.stringify({status:'ok',backup:source,integrity,tables:expectedTables,counts})+'\n');
  }finally{db.close()}
}finally{
  fs.rmSync(temp,{force:true});
}
