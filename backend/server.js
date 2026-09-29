require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { WebSocketServer } = require('ws');

const app = express();
const PORT = Number(process.env.PORT || 3001);
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'events.json');
const JWT_SECRET = process.env.JWT_SECRET;
const INGEST_API_KEY = process.env.INGEST_API_KEY;
const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:3001').split(',').map(o => o.trim()).filter(Boolean);

if (NODE_ENV === 'production' && (!JWT_SECRET || JWT_SECRET.includes('replace') || !INGEST_API_KEY || INGEST_API_KEY.includes('replace') || !process.env.ADMIN_PASSWORD_HASH)) {
  throw new Error('Production requires JWT_SECRET, INGEST_API_KEY, and ADMIN_PASSWORD_HASH');
}
const jwtSecret = JWT_SECRET || 'local-development-secret';
const ingestKey = INGEST_API_KEY || 'local-development-ingest-key';
const adminUser = process.env.ADMIN_USER || 'admin';
const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH || (process.env.ADMIN_PASSWORD ? bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12) : null);
if (!adminPasswordHash) throw new Error('Set ADMIN_PASSWORD_HASH or ADMIN_PASSWORD in the environment');

fs.mkdirSync(DATA_DIR, { recursive: true });
let events = fs.existsSync(DATA_FILE) ? JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) : [];
const alerts = [];
const clients = new Set();
let writeQueued = false;

function persist() {
  if (writeQueued) return;
  writeQueued = true;
  setImmediate(() => {
    writeQueued = false;
    const temporary = `${DATA_FILE}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(events.slice(-10000)));
    fs.renameSync(temporary, DATA_FILE);
  });
}
function publicUser(user) { return { id: user.id, username: user.username, role: user.role }; }
function issueToken(user) { return jwt.sign(publicUser(user), jwtSecret, { expiresIn: '8h' }); }
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try { req.user = jwt.verify(token, jwtSecret); next(); } catch { res.status(401).json({ error: 'Authentication required' }); }
}
function requireRole(role) { return (req, res, next) => req.user?.role === role ? next() : res.status(403).json({ error: 'Forbidden' }); }
function sameSecret(provided, expected) {
  const a = Buffer.from(String(provided || ''));
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function normalize(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Event must be an object');
  const severity = String(input.severity || 'INFO').toUpperCase();
  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity)) throw new Error('Invalid severity');
  const timestamp = input.timestamp || new Date().toISOString();
  if (Number.isNaN(Date.parse(timestamp))) throw new Error('Invalid timestamp');
  const sourceIp = String(input.source_ip || input.sourceIp || 'unknown');
  if (sourceIp !== 'unknown' && net.isIP(sourceIp) === 0) throw new Error('Invalid source_ip: must be valid IPv4 or IPv6');
  const text = value => String(value || '').slice(0, 1000);
  return { id: `${Date.now()}-${crypto.randomBytes(4).toString('hex')}`, timestamp: new Date(timestamp).toISOString(), severity, category: text(input.category || 'general').slice(0, 100), source_ip: sourceIp, message: text(input.message || 'Event received'), hostname: text(input.hostname || 'unknown').slice(0, 255) };
}
function broadcast(message) { const value = JSON.stringify(message); for (const ws of clients) if (ws.readyState === 1) ws.send(value); }

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors((req, callback) => {
  const origin = req.headers.origin;
  const ok = !origin || allowedOrigins.includes(origin) || (origin && new URL(origin).host === req.headers.host);
  callback(null, { origin: ok ? origin : false });
}));
app.use(express.json({ limit: '1mb' }));
app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'sentinel-siem', events: events.length }));
app.post('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false }), (req, res) => {
  const valid = req.body?.username === adminUser && bcrypt.compareSync(req.body?.password || '', adminPasswordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const user = { id: 1, username: adminUser, role: 'admin' };
  res.json({ token: issueToken(user), user: publicUser(user) });
});
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));
function ingest(req, res) {
  if (!sameSecret(req.headers['x-api-key'], ingestKey)) return res.status(401).json({ error: 'Invalid API key' });
  try { const event = normalize(req.body); events.push(event); persist(); broadcast({ type: 'event', event }); return res.status(201).json({ event }); }
  catch (error) { return res.status(400).json({ error: error.message }); }
}
app.post('/api/ingest/event', ingest);
app.post('/api/ingest/bulk', (req, res) => {
  if (!sameSecret(req.headers['x-api-key'], ingestKey)) return res.status(401).json({ error: 'Invalid API key' });
  if (!Array.isArray(req.body) || req.body.length > 1000) return res.status(400).json({ error: 'Payload must be an array of up to 1000 events' });
  try { const added = req.body.map(normalize); events.push(...added); persist(); added.forEach(event => broadcast({ type: 'event', event })); return res.status(201).json({ count: added.length }); }
  catch (error) { return res.status(400).json({ error: error.message }); }
});
app.get('/api/events', auth, (req, res) => {
  const { severity, category, search, limit = 100, offset = 0 } = req.query;
  let result = [...events].reverse();
  if (severity) result = result.filter(e => e.severity === String(severity).toUpperCase());
  if (category) result = result.filter(e => e.category === category);
  if (search) result = result.filter(e => JSON.stringify(e).toLowerCase().includes(String(search).toLowerCase()));
  const start = Math.max(0, Number(offset) || 0); const size = Math.min(Math.max(1, Number(limit) || 100), 1000);
  res.json({ events: result.slice(start, start + size), total: result.length });
});
app.get('/api/stats/summary', auth, (_req, res) => res.json({ totalEvents: events.length, openAlerts: alerts.filter(a => a.status === 'NEW').length, criticalEvents: events.filter(e => e.severity === 'CRITICAL').length }));

// API 404 handler (before static files)
app.use('/api', (req, res) => res.status(404).json({ error: 'Not Found' }));

app.use(express.static(path.join(__dirname, '..', 'frontend', 'dist')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, '..', 'frontend', 'dist', 'index.html')));
app.use((error, _req, res, _next) => res.status(error instanceof SyntaxError ? 400 : 500).json({ error: error instanceof SyntaxError ? 'Invalid JSON body' : 'Internal server error' }));

const server = app.listen(PORT, () => console.log(`Sentinel SIEM listening on port ${PORT}`));
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (request, socket, head) => {
  if (!request.url.startsWith('/ws')) return socket.destroy();
  const token = new URL(request.url, `http://${request.headers.host}`).searchParams.get('token');
  try { jwt.verify(token || '', jwtSecret); } catch { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return socket.destroy(); }
  wss.handleUpgrade(request, socket, head, ws => wss.emit('connection', ws, request));
});
wss.on('connection', ws => { clients.add(ws); ws.on('close', () => clients.delete(ws)); });
