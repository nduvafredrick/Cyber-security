import React,{useCallback,useEffect,useRef,useState}from'react';
import{createRoot}from'react-dom/client';
import'./style.css';

const PAGE_SIZE=40;
const cache=new Map();
const CACHE_TTL=5000;

async function api(path,opts={}){
  const method=(opts.method||'GET').toUpperCase();
  const key=method+' '+path;
  if(method==='GET'){
    const hit=cache.get(key);
    if(hit&&Date.now()-hit.time<CACHE_TTL)return hit.data;
  }
  const r=await fetch(path,{...opts,credentials:'include',headers:{...(opts.body?{'Content-Type':'application/json'}:{}),...(opts.headers||{})}});
  const d=await r.json().catch(()=>({}));
  if(!r.ok)throw Object.assign(Error(d.error||'Request failed'),{status:r.status});
  if(method==='GET')cache.set(key,{time:Date.now(),data:d});
  else cache.clear();
  return d;
}
function Badge({children}){return <span className={'badge '+String(children).toLowerCase()}>{children}</span>}
function eventMatches(e,severity,search){const q=String(search||'').trim().toLowerCase();return(!severity||e.severity===severity)&&(!q||[e.message,e.category,e.source_ip,e.hostname].some(v=>String(v).toLowerCase().includes(q)))}

function App(){
 const[token,setToken]=useState(true),[currentUser,setCurrentUser]=useState(null),[events,setEvents]=useState([]),[alerts,setAlerts]=useState([]),[stats,setStats]=useState({}),[view,setView]=useState('overview'),[searchInput,setSearchInput]=useState(''),[query,setQuery]=useState(''),[severity,setSeverity]=useState(''),[page,setPage]=useState(0),[loading,setLoading]=useState(false),[error,setError]=useState(''),[login,setLogin]=useState({username:'',password:''}),[connected,setConnected]=useState(false);
 const ws=useRef(null),abort=useRef(null),filterRef=useRef({severity:'',search:''});

 useEffect(()=>{filterRef.current={severity,search:query}},[severity,query]);

 const load=useCallback(async()=>{
   abort.current?.abort();
   const c=new AbortController();abort.current=c;setLoading(true);setError('');
   try{
     if(view==='events'){
       const e=await api('/api/events?limit='+PAGE_SIZE+'&offset='+(page*PAGE_SIZE)+'&search='+encodeURIComponent(query)+'&severity='+encodeURIComponent(severity));
       setEvents(e.events||[]);setStats(s=>({...s,eventSearchTotal:e.total??0}));
     }else if(view==='overview'){
       const[e,a,s]=await Promise.all([api('/api/events?limit=12&offset=0'),api('/api/alerts'),api('/api/stats/summary')]);
       setEvents(e.events||[]);setAlerts(a.alerts||[]);setStats({...s,eventSearchTotal:e.total??s.totalEvents??0});
     }else if(view==='alerts'){
       const[a,s]=await Promise.all([api('/api/alerts'),api('/api/stats/summary')]);setAlerts(a.alerts||[]);setStats(s);
     }
   }catch(e){if(e.name!=='AbortError'){if(e.status===401){setToken(false);setError('Your session has expired. Sign in again.')}else setError(e.message)}}finally{if(!c.signal.aborted)setLoading(false)}
 },[view,page,query,severity]);

 useEffect(()=>{api('/api/auth/me').then(d=>{setCurrentUser(d.user);setToken(true)}).catch(()=>{setCurrentUser(null);setToken(false)})},[]);
 useEffect(()=>{if(token)load();return()=>abort.current?.abort()},[token,load]);
 useEffect(()=>{if(view!=='events')return;const t=setTimeout(()=>{setQuery(searchInput.trim());setPage(0)},350);return()=>clearTimeout(t)},[searchInput,view]);
 useEffect(()=>{if(!token)return;let stopped=false,retry=1000,timer;
   const connect=()=>{if(stopped)return;const protocol=location.protocol==='https:'?'wss':'ws';const socket=new WebSocket(protocol+'://'+location.host+'/ws');ws.current=socket;
     socket.onopen=()=>{retry=1000;setConnected(true);socket.send(JSON.stringify({type:'subscribe',...filterRef.current}))};
     socket.onmessage=e=>{try{const d=JSON.parse(e.data);cache.clear();
       if(d.type==='event'){if(viewRef.current==='overview'||(viewRef.current==='events'&&pageRef.current===0&&eventMatches(d.event,filterRef.current.severity,filterRef.current.search)))setEvents(x=>[d.event,...x].slice(0,PAGE_SIZE));setStats(s=>({...s,totalEvents:(s.totalEvents||0)+1}))}
       if(d.type==='alert'){setAlerts(x=>[d.alert,...x].slice(0,500));setStats(s=>({...s,openAlerts:(s.openAlerts||0)+1}))}
       if(d.type==='alert.updated')setAlerts(x=>x.map(a=>a.id===d.alert.id?d.alert:a));
     }catch{}};
     socket.onclose=()=>{setConnected(false);ws.current=null;if(!stopped){timer=setTimeout(connect,retry);retry=Math.min(retry*2,30000)}};
     socket.onerror=()=>socket.close();
   };connect();return()=>{stopped=true;clearTimeout(timer);setConnected(false);ws.current?.close();ws.current=null};
 },[token]);
 const viewRef=useRef(view),pageRef=useRef(page);useEffect(()=>{viewRef.current=view;pageRef.current=page},[view,page]);
 useEffect(()=>{if(connected&&ws.current?.readyState===1)ws.current.send(JSON.stringify({type:'subscribe',...filterRef.current}))},[connected,query,severity]);

 async function signIn(e){e.preventDefault();setLoading(true);setError('');try{const session=await api('/api/auth/login',{method:'POST',body:JSON.stringify(login)});setCurrentUser(session.user);setToken(true);setLogin({username:'',password:''})}catch(e){setError(e.message)}finally{setLoading(false)}}
 async function signOut(){try{await api('/api/auth/logout',{method:'POST'})}catch{}setCurrentUser(null);setToken(false);ws.current?.close()}
 async function alertStatus(id,status){try{const d=await api('/api/alerts/'+id,{method:'PATCH',body:JSON.stringify({status})});setAlerts(x=>x.map(a=>a.id===id?d.alert:a));setStats(s=>({...s,openAlerts:d.alert.status==='NEW'?(s.openAlerts||0):Math.max(0,(s.openAlerts||0)-(d.alert.status!=='NEW'?1:0))}))}catch(e){setError(e.message)}}
 const pageCount=Math.max(1,Math.ceil((stats.eventSearchTotal??0)/PAGE_SIZE));

 if(!token)return <main className="auth"><form onSubmit={signIn} className="login"><div className="brand-mark">S</div><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Sentinel</h1><p className="muted">Security Information & Event Management</p></div><input autoComplete="username" placeholder="Username" value={login.username} onChange={e=>setLogin({...login,username:e.target.value})}/><input autoComplete="current-password" type="password" placeholder="Password" value={login.password} onChange={e=>setLogin({...login,password:e.target.value})}/><button disabled={loading}>{loading?'Signing in…':'Sign in to console'}</button>{error&&<p className="error">{error}</p>}</form></main>;

 return <div className="shell"><aside><div className="logo"><span>S</span><div><strong>Sentinel</strong><small>SIEM CONSOLE</small></div></div><nav>{[['overview','Overview'],['events','Events'],['alerts','Alerts'],['audit','Audit Log'],...(currentUser?.role==='admin'?[['admin','Administration']]:[])].map(([id,label])=><button className={view===id?'active':''} onClick={()=>{setView(id);setPage(0)}} key={id}><i>{id==='overview'?'◈':id==='events'?'≡':id==='alerts'?'△':'⌁'}</i>{label}{id==='alerts'&&stats.openAlerts?<em>{stats.openAlerts}</em>:null}</button>)}</nav><div className="sidebar-foot"><span className="status-dot"/>{connected?'Live connection':'Reconnecting…'}<button className="signout" onClick={signOut}>Sign out</button></div></aside>
 <main className="content"><header><div><p className="eyebrow">SECURITY OPERATIONS CENTER</p><h1>{view==='overview'?'Overview':view==='events'?'Security Events':view==='alerts'?'Alert Queue':'Audit Log'}</h1></div><div className="live"><span className="status-dot"/>{connected?'LIVE':'OFFLINE'}</div></header>{error&&<div className="error notice">{error}<button onClick={()=>setError('')}>Dismiss</button></div>}
 {view==='overview'&&<><section className="metrics">{[['TOTAL EVENTS',stats.totalEvents||0,'events'],['OPEN ALERTS',stats.openAlerts||0,'alerts'],['CRITICAL',stats.criticalEvents||0,'critical'],['SOURCES',stats.sources||0,'sources']].map(x=><article className="metric" key={x[0]}><span>{x[0]}</span><strong>{x[1]}</strong><small>{x[2]==='alerts'?'requires attention':x[2]==='critical'?'critical severity':'monitored'}</small></article>)}</section><div className="grid"><section className="panel"><div className="panel-head"><div><h2>Live event stream</h2><p>Most recent security telemetry</p></div><button className="ghost" onClick={()=>{cache.clear();load()}} disabled={loading}>{loading?'Loading…':'Refresh'}</button></div><EventTable rows={events.slice(0,12)} loading={loading}/></section><section className="panel"><div className="panel-head"><div><h2>Active alerts</h2><p>Detection engine findings</p></div></div>{alerts.filter(a=>a.status==='NEW').slice(0,5).map(a=><AlertRow a={a} key={a.id} onStatus={alertStatus}/>)}{!alerts.some(a=>a.status==='NEW')&&<Empty text="No active alerts"/>}</section></div></>}
 {view==='events'&&<section className="panel"><div className="toolbar"><input aria-label="Search events" placeholder="Search message, IP, category, or hostname…" value={searchInput} onChange={e=>setSearchInput(e.target.value)}/><select aria-label="Filter severity" value={severity} onChange={e=>setSeverity(e.target.value)}><option value="">All severities</option>{['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(x=><option key={x}>{x}</option>)}</select></div><EventTable rows={events} loading={loading}/><Pagination page={page} pageCount={pageCount} total={stats.eventSearchTotal||0} onPage={setPage}/></section>}
 {view==='alerts'&&<section className="panel"><div className="panel-head"><div><h2>Alert queue</h2><p>Investigate and update detections</p></div><button className="ghost" onClick={()=>{cache.clear();load()}} disabled={loading}>Refresh</button></div>{alerts.map(a=><AlertRow a={a} key={a.id} onStatus={alertStatus}/>)}{!alerts.length&&<Empty text="No alerts"/>}</section>}
 {view==='audit'&&<Audit/>}{view==='admin'&&currentUser?.role==='admin'&&<Administration/>}</main></div>
}
function EventTable({rows,loading}){return <div className="table-wrap">{loading&&!rows.length?<div className="empty">Loading security telemetry…</div>:<table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Source</th><th>Message</th></tr></thead><tbody>{rows.map(e=><tr key={e.id}><td className="time">{new Date(e.timestamp).toLocaleTimeString()}</td><td><Badge>{e.severity}</Badge></td><td>{e.category}</td><td className="mono">{e.source_ip}</td><td>{e.message}</td></tr>)}</tbody></table>}{!loading&&!rows.length&&<Empty text="No events match the current filters"/>}</div>}
function AlertRow({a,onStatus}){return <div className="alert"><div><Badge>{a.severity}</Badge><strong>{a.title}</strong><p>{a.description}</p><small>{new Date(a.created_at).toLocaleString()} · {a.source_ip}</small></div><div className="actions">{a.status==='NEW'&&<button onClick={()=>onStatus(a.id,'ACKNOWLEDGED')}>Acknowledge</button>}{a.status==='ACKNOWLEDGED'&&<button onClick={()=>onStatus(a.id,'RESOLVED')}>Resolve</button>}<Badge>{a.status}</Badge></div></div>}
function Pagination({page,pageCount,total,onPage}){if(total<=PAGE_SIZE)return null;return <div className="pagination"><span>{page*PAGE_SIZE+1}–{Math.min((page+1)*PAGE_SIZE,total)} of {total}</span><div><button disabled={page===0} onClick={()=>onPage(page-1)}>Previous</button><button disabled={page>=pageCount-1} onClick={()=>onPage(page+1)}>Next</button></div></div>}
function Empty({text}){return <div className="empty">{text}</div>}
function Audit(){const[a,setA]=useState([]),[loading,setLoading]=useState(true);useEffect(()=>{const c=new AbortController();api('/api/audit',{signal:c.signal}).then(d=>setA(d.audit||[])).catch(()=>{}).finally(()=>setLoading(false));return()=>c.abort()},[]);return <section className="panel"><div className="panel-head"><div><h2>Audit trail</h2><p>Administrative activity</p></div></div>{loading?<Empty text="Loading audit trail…"/>:<table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th></tr></thead><tbody>{a.map(x=><tr key={x.id}><td>{new Date(x.timestamp).toLocaleString()}</td><td>{x.action}</td><td>{x.actor}</td><td className="mono">{x.target||'—'}</td></tr>)}</tbody></table>}</section>}
createRoot(document.getElementById('root')).render(<App/>);

function Administration(){
 const[tab,setTab]=useState('users'),[users,setUsers]=useState([]),[keys,setKeys]=useState([]),[rules,setRules]=useState([]),[form,setForm]=useState({username:'',password:'',role:'analyst'}),[newKey,setNewKey]=useState(null),[message,setMessage]=useState('');
 const load=useCallback(async()=>{try{const[u,k,r]=await Promise.all([api('/api/admin/users'),api('/api/admin/ingest-keys'),api('/api/admin/detection-rules')]);setUsers(u.users);setKeys(k.keys);setRules(r.rules)}catch(e){setMessage(e.message)}},[]);
 useEffect(()=>{load()},[load]);
 async function addUser(e){e.preventDefault();try{await api('/api/admin/users',{method:'POST',body:JSON.stringify(form)});setForm({username:'',password:'',role:'analyst'});setMessage('User created');cache.clear();load()}catch(e){setMessage(e.message)}}
 async function rotate(){try{const d=await api('/api/admin/ingest-keys/rotate',{method:'POST',body:JSON.stringify({name:'console-key'})});setNewKey(d.key);setMessage('New key created. Store it securely; it is shown only once.');cache.clear();load()}catch(e){setMessage(e.message)}}
 async function revoke(id){try{await api('/api/admin/ingest-keys/'+id,{method:'DELETE'});setMessage('Key revoked');cache.clear();load()}catch(e){setMessage(e.message)}}
 async function saveRule(rule){try{await api('/api/admin/detection-rules/'+encodeURIComponent(rule.rule_key),{method:'PUT',body:JSON.stringify(rule)});setMessage('Rule saved');cache.clear();load()}catch(e){setMessage(e.message)}}
 return <section className="panel admin-panel"><div className="panel-head"><div><h2>Administration</h2><p>Users, ingest credentials and detection rules</p></div></div>
 <div className="admin-tabs">{[['users','Users'],['keys','Ingest keys'],['rules','Detection rules']].map(([id,label])=><button className={tab===id?'active':''} onClick={()=>setTab(id)} key={id}>{label}</button>)}</div>
 {message&&<div className="notice">{message}</div>}
 {tab==='users'&&<><form className="admin-form" onSubmit={addUser}><input aria-label="New username" placeholder="Username" value={form.username} onChange={e=>setForm({...form,username:e.target.value})}/><input aria-label="New password" type="password" placeholder="Password (12+ chars)" value={form.password} onChange={e=>setForm({...form,password:e.target.value})}/><select aria-label="New role" value={form.role} onChange={e=>setForm({...form,role:e.target.value})}><option value="analyst">Analyst</option><option value="admin">Admin</option></select><button>Add user</button></form><table><thead><tr><th>User</th><th>Role</th><th>Status</th></tr></thead><tbody>{users.map(u=><tr key={u.id}><td>{u.username}</td><td>{u.role}</td><td>{u.enabled?'Enabled':'Disabled'}</td></tr>)}</tbody></table></>}
 {tab==='keys'&&<><div className="panel-head"><div><p>Only hashed keys are stored. Rotation revokes currently active keys.</p></div><button onClick={rotate}>Rotate key</button></div>{newKey&&<div className="key-reveal"><strong>New ingest key:</strong> <span className="mono">{newKey}</span></div>}<table><thead><tr><th>Name</th><th>Prefix</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>{keys.map(k=><tr key={k.id}><td>{k.name}</td><td className="mono">{k.key_prefix}…</td><td>{k.enabled?'Active':'Revoked'}</td><td>{new Date(k.created_at).toLocaleString()}</td><td>{k.enabled&&<button onClick={()=>revoke(k.id)}>Revoke</button>}</td></tr>)}</tbody></table></>}
 {tab==='rules'&&<div className="rule-list">{rules.map(rule=><RuleEditor key={rule.rule_key} rule={rule} onSave={saveRule}/>)}</div>}
 </section>
}
function RuleEditor({rule,onSave}){const[r,setR]=useState(rule);useEffect(()=>setR(rule),[rule]);return <div className="rule-card"><div><strong>{r.name}</strong><small>{r.rule_key}</small></div><label><input type="checkbox" checked={r.enabled} onChange={e=>setR({...r,enabled:e.target.checked})}/> Enabled</label><input value={r.title} onChange={e=>setR({...r,title:e.target.value})}/><input type="number" min="1" value={r.threshold} onChange={e=>setR({...r,threshold:Number(e.target.value)})}/><input type="number" min="1000" value={r.window_ms} onChange={e=>setR({...r,window_ms:Number(e.target.value)})}/><input value={r.message_pattern} onChange={e=>setR({...r,message_pattern:e.target.value})}/><button onClick={()=>onSave(r)}>Save rule</button></div>}
