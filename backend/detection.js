const crypto=require('crypto');

function evaluate(event,events,rules){
  for(const rule of rules||[]){
    if(!rule.enabled)continue;
    const severities=new Set(rule.severities||[]);
    if(!severities.has(event.severity))continue;
    const categories=new Set((rule.categories||[]).map(String).map(x=>x.toLowerCase()));
    if(categories.size&&!categories.has(String(event.category).toLowerCase()))continue;
    let pattern;
    try{pattern=new RegExp(rule.message_pattern.replace(/^\/(.*)\/([a-z]*)$/,'$1'));}catch{continue}
    if(!pattern.test(event.message))continue;
    const start=Date.now()-Number(rule.window_ms);
    const count=events.filter(item=>item.source_ip===event.source_ip&&Date.parse(item.timestamp)>=start&&pattern.test(item.message)).length;
    if(count<Number(rule.threshold))continue;
    return {
      id:`alert-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
      rule_key:rule.rule_key,
      created_at:new Date().toISOString(),
      source_ip:event.source_ip,
      severity:rule.alert_severity,
      status:'NEW',
      title:rule.title,
      description:`${count} matching events from ${event.source_ip} within ${Math.round(Number(rule.window_ms)/60000)} minutes.`,
      count
    };
  }
  return null;
}
module.exports={evaluate};
