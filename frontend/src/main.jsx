import React, { useEffect, useState, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [events, setEvents] = useState([]);
  const [form, setForm] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const wsRef = useRef(null);
  const reconnectRef = useRef(null);
  const maxEventsRef = useRef(500);

  async function login(e) {
    e.preventDefault();
    setError('');
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(form)
    });
    const data = await r.json();
    if (!r.ok) return setError(data.error || 'Login failed');
    localStorage.setItem('token', data.token);
    setToken(data.token);
  }

  function connectWebSocket(token) {
    if (!token) return;
    const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${protocol}://${location.host}/ws?token=${encodeURIComponent(token)}`);
    ws.onopen = () => {
      clearTimeout(reconnectRef.current);
      console.log('WebSocket connected');
    };
    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        if (data.type === 'event') {
          setEvents(current => [data.event, ...current].slice(0, maxEventsRef.current));
        }
      } catch (e) {
        console.error('WS parse error:', e);
      }
    };
    ws.onerror = () => console.error('WebSocket error');
    ws.onclose = () => {
      console.log('WebSocket closed, reconnecting in 3s...');
      reconnectRef.current = setTimeout(() => connectWebSocket(token), 3000);
    };
    wsRef.current = ws;
  }

  useEffect(() => {
    if (!token) return;
    // Load initial events
    fetch('/api/events', { headers: { Authorization: `Bearer ${token}` } })
      .then(r => {
        if (r.status === 401) { localStorage.removeItem('token'); setToken(null); return; }
        return r.json();
      })
      .then(d => { if (d && d.events) setEvents(d.events.slice(0, maxEventsRef.current)); })
      .catch(e => console.error('Failed to load events:', e));
    // Connect WebSocket
    connectWebSocket(token);
    return () => { if (wsRef.current) wsRef.current.close(); if (reconnectRef.current) clearTimeout(reconnectRef.current); };
  }, [token]);

  if (!token) {
    return (
      <main className="login">
        <form onSubmit={login}>
          <h1>🛡️ Sentinel SIEM</h1>
          <input value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} placeholder="Username" required/>
          <input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} placeholder="Password" required/>
          <button>Sign in</button>
          {error && <p className="error">{error}</p>}
        </form>
      </main>
    );
  }

  return (
    <main>
      <header>
        <h1>🛡️ Sentinel SIEM</h1>
        <button onClick={() => { localStorage.removeItem('token'); setToken(null); }}>Sign out</button>
      </header>
      <section className="card">
        <h2>Events <span>{events.length}</span></h2>
        {events.length === 0 ? (
          <p>No events yet. Send events to /api/ingest/event or /api/ingest/bulk.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Source</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {events.map(e => (
                <tr key={e.id}>
                  <td>{new Date(e.timestamp).toLocaleString()}</td>
                  <td><b className={e.severity.toLowerCase()}>{e.severity}</b></td>
                  <td>{e.category}</td>
                  <td>{e.source_ip}</td>
                  <td>{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
