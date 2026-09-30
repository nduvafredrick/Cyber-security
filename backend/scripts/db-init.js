const store=require('../storage');

try{
  store.health();
  process.stdout.write(JSON.stringify({status:'ok',database:'sentinel.db'})+'\n');
}finally{
  store.close();
}
