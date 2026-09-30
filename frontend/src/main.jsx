import React,{useEffect,useMemo,useRef,useState}from'react';
import{createRoot}from'react-dom/client';
import'./style.css';

const api=async(path,opts={})=>{
  const r=await fetch(path,{...opts,headers:{...(opts.body?{'Content-Type':'application/json'}:{}),...(opts.headers||{})}});
  const d=await r.json().catch(()=>({}));
  if(!r.ok)throw Error(d.error||'Request failed');
  return d;
};

const navItems=[
  ['overview','Overview','⌂'],
  ['events','Events','≡'],
  ['alerts','Alerts','!'],
  ['audit','Audit Log','◌']
];

function Badge({children}){return <span className={'badge '+String(children).toLowerCase().replace(/\s/g,'-')}>{children}</span>}

function App(){
  const[token,setToken]=useState(localStorage.getItem('token'));
  const[events,setEvents]=useState([]);
  const[alerts,setAlerts]=useState([]);
  const[stats,setStats]=useState({});
  const[view,setView]=useState('overview');
  const[search,setSearch]=useState('');
  const[severity,setSeverity]=useState('');
  const[loading,setLoading]=useState(false);
  const[error,setError]=useState('');
  const[login,setLogin]=useState({username:'',password:''});
  const ws=useRef(null);

  const auth={Authorization:`Bearer ${token}`};

  async function load(){
    if(!token)return;
    setLoading(true);
    try{
      const[e,a,s]=await Promise.all([
        api('/api/events?limit=100',{headers:auth}),
        api('/api/alerts',{headers:auth}),
        api('/api/stats/summary',{headers:auth})
      ]);
      setEvents(e.events||[]);
      setAlerts(a.alerts||[]);
      setStats(s||{});
      setError('');
    }catch(e){
      setError(e.message);
      if(/token|auth|unauthorized|expired/i.test(e.message)){
        localStorage.removeItem('token');setToken(null);
      }
    }finally{setLoading(false)}
  }

  useEffect(()=>{
    if(!token)return;
    let active=true;
    load();
    const protocol=location.protocol==='https:'?'wss':'ws';
    const socket=new WebSocket(`${protocol}://${location.host}/ws?token=${encodeURIComponent(token)}`);
    ws.current=socket;
    socket.onmessage=e=>{
      if(!active)return;
      try{
        const d=JSON.parse(e.data);
        if(d.type==='event'){
          setEvents(x=>[d.event,...x].slice(0,100));
          setStats(s=>({...s,totalEvents:(s.totalEvents||0)+1}));
        }
        if(d.type==='alert'){
          setAlerts(x=>[d.alert,...x]);
          setStats(s=>({...s,openAlerts:(s.openAlerts||0)+1}));
        }
        if(d.type==='alert.updated')setAlerts(x=>x.map(a=>a.id===d.alert.id?d.alert:a));
      }catch{}
    };
    return()=>{active=false;socket.close();ws.current=null};
  },[token]);

  const filtered=useMemo(()=>events.filter(e=>
    (!severity||e.severity===severity)&&
    (!search||JSON.stringify(e).toLowerCase().includes(search.toLowerCase()))
  ),[events,severity,search]);

  async function signIn(e){
    e.preventDefault();setError('');
    try{
      const d=await api('/api/auth/login',{method:'POST',body:JSON.stringify(login)});
      localStorage.setItem('token',d.token);setToken(d.token);
    }catch(e){setError(e.message)}
  }

  async function alertStatus(id,status){
    try{
      const d=await api('/api/alerts/'+id,{method:'PATCH',headers:auth,body:JSON.stringify({status})});
      setAlerts(x=>x.map(a=>a.id===id?d.alert:a));
    }catch(e){setError(e.message)}
  }

  function signOut(){localStorage.removeItem('token');setToken(null);setEvents([]);setAlerts([])}

  if(!token)return <Login login={login} setLogin={setLogin} error={error} onSubmit={signIn}/>;

  const pageTitle={overview:'Operations overview',events:'Security events',alerts:'Alert queue',audit:'Audit trail'}[view];

  return <div className="app">
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-symbol">S</div>
        <div><strong>Sentinel</strong><span>SIEM CONSOLE</span></div>
      </div>
      <div className="side-label">Workspace</div>
      <nav>{navItems.map(([id,label,icon])=>
        <button key={id} className={view===id?'active':''} onClick={()=>setView(id)}>
          <i>{icon}</i><span>{label}</span>{id==='alerts'&&stats.openAlerts>0?<em>{stats.openAlerts}</em>:null}
        </button>
      )}</nav>
      <div className="sidebar-bottom">
        <div className="system"><span className="pulse"/>System operational</div>
        <div className="instance">Protected monitoring environment</div>
        <button className="signout" onClick={signOut}>Sign out <span>↗</span></button>
      </div>
    </aside>

    <main className="main">
      <header className="topbar">
        <div>
          <div className="breadcrumb">SENTINEL / <span>{pageTitle.toUpperCase()}</span></div>
          <h1>{pageTitle}</h1>
        </div>
        <div className="top-actions">
          <span className="connection"><span className="pulse"/>LIVE</span>
          <button className="refresh" onClick={load} disabled={loading}>{loading?'Syncing…':'Refresh ↻'}</button>
        </div>
      </header>

      {error&&<div className="notice"><span>!</span>{error}<button onClick={()=>setError('')}>×</button></div>}

      {view==='overview'&&<Overview stats={stats} events={events} alerts={alerts} onAlert={alertStatus}/>}
      {view==='events'&&<section className="card">
        <div className="card-head">
          <div><span className="section-kicker">TELEMETRY</span><h2>Event stream</h2><p>Search and filter the latest security telemetry.</p></div>
          <span className="count">{filtered.length} records</span>
        </div>
        <div className="toolbar"><div className="search"><span>⌕</span><input placeholder="Search IP, category, message…" value={search} onChange={e=>setSearch(e.target.value)}/></div><select value={severity} onChange={e=>setSeverity(e.target.value)}><option value="">All severities</option>{['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(x=><option key={x}>{x}</option>)}</select></div>
        <EventTable rows={filtered}/>
      </section>}
      {view==='alerts'&&<section className="card">
        <div className="card-head"><div><span className="section-kicker">DETECTION</span><h2>Alert queue</h2><p>Review findings and move them through the response lifecycle.</p></div><span className="count">{alerts.length} alerts</span></div>
        <AlertList alerts={alerts} onStatus={alertStatus}/>
      </section>}
      {view==='audit'&&<Audit/>}
    </main>
  </div>
}

function Login({login,setLogin,error,onSubmit}){
  return <main className="auth-page">
    <div className="auth-glow"/>
    <form className="login-card" onSubmit={onSubmit}>
      <div className="auth-brand"><div className="brand-symbol">S</div><div><strong>Sentinel</strong><span>SECURITY OPERATIONS</span></div></div>
      <div className="login-copy"><span className="section-kicker">RESTRICTED CONSOLE</span><h1>Secure access.</h1><p>Authenticate to enter the Sentinel security operations environment.</p></div>
      <label>Username<input autoComplete="username" value={login.username} onChange={e=>setLogin({...login,username:e.target.value})} placeholder="Enter username"/></label>
      <label>Password<input autoComplete="current-password" type="password" value={login.password} onChange={e=>setLogin({...login,password:e.target.value})} placeholder="Enter password"/></label>
      <button className="primary">Enter console <span>→</span></button>
      {error&&<div className="login-error">{error}</div>}
      <small className="auth-foot">Authorized personnel only · Sentinel SIEM</small>
    </form>
  </main>
}

function Overview({stats,events,alerts,onAlert}){
  const critical=stats.criticalEvents||0;
  const open=stats.openAlerts||0;
  return <>
    <section className="hero">
      <div><span className="section-kicker">SECURITY POSTURE</span><h2>Monitoring is active.</h2><p>Sentinel is receiving and analyzing security events in real time.</p></div>
      <div className="hero-mark">◈</div>
    </section>
    <section className="metrics">
      <Metric label="TOTAL EVENTS" value={stats.totalEvents||0} detail="Across monitored sources" icon="01"/>
      <Metric label="OPEN ALERTS" value={open} detail={open?'Requires analyst attention':'No outstanding findings'} icon="02" danger={open>0}/>
      <Metric label="CRITICAL EVENTS" value={critical} detail="Critical severity telemetry" icon="03" danger={critical>0}/>
      <Metric label="SOURCES" value={stats.sources||0} detail="Observed event sources" icon="04"/>
    </section>
    <div className="overview-grid">
      <section className="card">
        <div className="card-head"><div><span className="section-kicker">LIVE TELEMETRY</span><h2>Recent events</h2><p>Latest events received by the collector.</p></div><span className="live-tag"><span className="pulse"/>LIVE</span></div>
        <EventTable rows={events.slice(0,10)}/>
      </section>
      <section className="card">
        <div className="card-head"><div><span className="section-kicker">DETECTION ENGINE</span><h2>Active alerts</h2><p>Prioritized findings.</p></div></div>
        <AlertList alerts={alerts.filter(a=>a.status==='NEW').slice(0,5)} onStatus={onAlert}/>
      </section>
    </div>
  </>
}

function Metric({label,value,detail,icon,danger}){return <article className={'metric '+(danger?'metric-danger':'')}><div className="metric-top"><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><small>{detail}</small></article>}

function EventTable({rows}){
  return <div className="table-scroll"><table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Source</th><th>Message</th></tr></thead><tbody>
    {rows.map(e=><tr key={e.id}><td className="time">{new Date(e.timestamp).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}</td><td><Badge>{e.severity}</Badge></td><td><span className="category">{e.category}</span></td><td className="mono">{e.source_ip||'—'}</td><td className="message">{e.message||'—'}</td></tr>)}
  </tbody></table>{!rows.length&&<Empty text="No events match the current view."/>}</div>
}

function AlertList({alerts,onStatus}){
  if(!alerts.length)return <Empty text="No active alerts. Detection engine is clear."/>
  return <div className="alert-list">{alerts.map(a=><div className="alert-row" key={a.id}>
    <div className="alert-severity"><Badge>{a.severity}</Badge></div>
    <div className="alert-main"><strong>{a.title}</strong><p>{a.description}</p><small>{new Date(a.created_at).toLocaleString()} <span>·</span> {a.source_ip||'Unknown source'}</small></div>
    <div className="alert-actions">{a.status==='NEW'&&<button onClick={()=>onStatus(a.id,'ACKNOWLEDGED')}>Acknowledge</button>}{a.status==='ACKNOWLEDGED'&&<button onClick={()=>onStatus(a.id,'RESOLVED')}>Resolve</button>}<Badge>{a.status}</Badge></div>
  </div>)}</div>
}

function Audit(){
  const[a,setA]=useState([]);
  useEffect(()=>{api('/api/audit',{headers:{Authorization:`Bearer ${localStorage.getItem('token')}`}}).then(d=>setA(d.audit||[])).catch(()=>setA([]))},[]);
  return <section className="card"><div className="card-head"><div><span className="section-kicker">ACCOUNTABILITY</span><h2>Audit trail</h2><p>Administrative activity recorded by Sentinel.</p></div><span className="count">{a.length} records</span></div>
    <div className="table-scroll"><table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th></tr></thead><tbody>{a.map(x=><tr key={x.id}><td className="time">{new Date(x.timestamp).toLocaleString()}</td><td>{x.action}</td><td>{x.actor}</td><td className="mono">{x.target||'—'}</td></tr>)}</tbody></table>{!a.length&&<Empty text="No audit activity available."/>}</div>
  </section>
}

function Empty({text}){return <div className="empty"><span>◌</span><p>{text}</p></div>}

createRoot(document.getElementById('root')).render(<App/>);
