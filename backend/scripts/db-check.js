const fs=require('fs');
const path=require('path');
const Database=require('better-sqlite3');
const {dataDir}=require('../config');

const source=path.join(dataDir,'sentinel.db');
if(!fs.existsSync(source))throw new Error('Database not found: '+source);
const db=new Database(source,{readonly:true});
try{
  const result=db.pragma('integrity_check',{simple:true});
  if(result!=='ok')throw new Error('SQLite integrity check failed: '+result);
  const wal=db.pragma('journal_mode',{simple:true});
  process.stdout.write(JSON.stringify({status:'ok',database:source,journal_mode:wal})+'\n');
}finally{db.close()}
