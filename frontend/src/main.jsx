import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const API = '';
function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [events, setEvents] = useState([]);
  const [form, setForm] = useState({ username: 'admin', password: 'SentinelAdmin2024!' });
  const [error, setError] = useState('');
  async function login(e) { e.preventDefault(); const r = await fetch(`${API}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) }); const data = await r.json(); if (!r.ok) return setError(data.error); localStorage.setItem('token', data.token); setToken(data.token); }
  useEffect(() => { if (!token) return; fetch(`${API}/api/events`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()).then(d => setEvents(d.events || [])); }, [token]);
  if (!token) return <main className="login"><form onSubmit={login}><h1>🛡️ Sentinel SIEM</h1><input value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} placeholder="Username"/><input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} placeholder="Password"/><button>Sign in</button>{error && <p className="error">{error}</p>}<small>Default admin: admin / SentinelAdmin2024!</small></form></main>;
  return <main><header><h1>🛡️ Sentinel SIEM</h1><button onClick={() => { localStorage.removeItem('token'); setToken(null); }}>Sign out</button></header><section className="card"><h2>Events <span>{events.length}</span></h2>{events.length === 0 ? <p>No events yet.</p> : <table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Source</th><th>Message</th></tr></thead><tbody>{events.map(e => <tr key={e.id}><td>{new Date(e.timestamp).toLocaleString()}</td><td><b className={e.severity.toLowerCase()}>{e.severity}</b></td><td>{e.category}</td><td>{e.source_ip}</td><td>{e.message}</td></tr>)}</tbody></table>}</section></main>;
}
createRoot(document.getElementById('root')).render(<App />);
