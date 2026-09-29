const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { WebSocketServer } = require('ws');

const app = express();
const PORT = Number(process.env.PORT || 3001);
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'events.json');
const JWT_SECRET = process.env.JWT_SECRET || 'development-only-change-me';
const INGEST_API_KEY = process.env.INGEST_API_KEY || 'development-ingest-key';
fs.mkdirSync(DATA_DIR, { recursive: true });

let events = fs.existsSync(DATA_FILE) ? JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) : [];
let alerts = [];
const users = [
  { id: 1, username: 'admin', role: 'admin', password: bcrypt.hashSync('SentinelAdmin2024!', 10) },
  { id: 2, username: 'engineer', role: 'engineer', password: bcrypt.hashSync('Engineer2024!', 10) },
  { id: 3, username: 'analyst', role: 'analyst', password: bcrypt.hashSync('Analyst2024!', 10) }
];

const save = () => fs.writeFileSync(DATA_FILE, JSON.stringify(events.slice(-10000), null, 2));
const publicUser = ({ password, ...user }) => user;
const issueToken = user => jwt.sign(publicUser(user), JWT_SECRET, { expiresIn: '8h' });
const auth = (req, res, next) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Authentication required' }); }
};
const normalize = input => ({
  id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  timestamp: input.timestamp || new Date().toISOString(),
  severity: String(input.severity || 'INFO').toUpperCase(),
  category: input.category || 'general',
  source_ip: input.source_ip || input.sourceIp || 'unknown',
  message: input.message || 'Event received',
  hostname: input.hostname || 'unknown'
});

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'sentinel-siem', events: events.length }));
app.post('/api/auth/login', (req, res) => {
  const user = users.find(item => item.username === req.body.username);
  if (!user || !bcrypt.compareSync(req.body.password || '', user.password)) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: issueToken(user), user: publicUser(user) });
});
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));
app.post('/api/ingest/event', (req, res) => {
  if (req.headers['x-api-key'] !== INGEST_API_KEY) return res.status(401).json({ error: 'Invalid API key' });
  const event = normalize(req.body); events.push(event); save(); broadcast({ type: 'event', event });
  res.status(201).json({ event });
});
app.post('/api/ingest/bulk', (req, res) => {
  if (req.headers['x-api-key'] !== INGEST_API_KEY || !Array.isArray(req.body)) return res.status(401).json({ error: 'Invalid API key or payload' });
  const added = req.body.slice(0, 1000).map(normalize); events.push(...added); save(); added.forEach(event => broadcast({ type: 'event', event }));
  res.status(201).json({ count: added.length });
});
app.get('/api/events', auth, (req, res) => {
  const { severity, category, search, limit = 100, offset = 0 } = req.query;
  let result = [...events].reverse();
  if (severity) result = result.filter(e => e.severity === String(severity).toUpperCase());
  if (category) result = result.filter(e => e.category === category);
  if (search) result = result.filter(e => JSON.stringify(e).toLowerCase().includes(String(search).toLowerCase()));
  res.json({ events: result.slice(Number(offset), Number(offset) + Math.min(Number(limit), 1000)), total: result.length });
});
app.get('/api/stats/summary', auth, (_req, res) => res.json({ totalEvents: events.length, openAlerts: alerts.filter(a => a.status === 'NEW').length, criticalEvents: events.filter(e => e.severity === 'CRITICAL').length }));
app.use(express.static(path.join(__dirname, '..', 'frontend', 'dist')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, '..', 'frontend', 'dist', 'index.html')));

const server = app.listen(PORT, () => console.log(`Sentinel SIEM listening on port ${PORT}`));
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Set();
wss.on('connection', ws => { clients.add(ws); ws.on('close', () => clients.delete(ws)); });
function broadcast(message) { const value = JSON.stringify(message); clients.forEach(ws => { if (ws.readyState === 1) ws.send(value); }); }
