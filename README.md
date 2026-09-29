# 🛡️ Sentinel SIEM

A simple, secure Security Information & Event Management platform for ingesting and analyzing security events.

## Quick Start (Development)

### Prerequisites
- Node.js 20+
- npm

### Setup

```bash
# 1. Backend
cd backend
npm install
cp .env.example .env
# Edit .env: set JWT_SECRET, INGEST_API_KEY, and ADMIN_PASSWORD
# (or use: node -e "console.log(require('bcryptjs').hashSync('yourpassword', 12))" and set ADMIN_PASSWORD_HASH)
node server.js

# 2. Frontend (in another terminal)
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

### First Login

Enter any username (e.g., "admin") and the password you set in `.env`.

---

## Production (Docker)

### Setup

```bash
# Generate secrets (keep these safe)
export JWT_SECRET=$(openssl rand -hex 32)
export INGEST_API_KEY=$(openssl rand -hex 20)

# Generate admin password hash
export ADMIN_PASSWORD_HASH=$(node -e "console.log(require('bcryptjs').hashSync('YOUR_PASSWORD', 12))")

# (Optional) Set domain for CORS
export CORS_ORIGIN=https://yourdomain.com

# Build and run
docker compose up -d

# Seed demo events (first time only)
docker exec sentinel-siem node scripts/seed.js

# Check health
curl http://localhost:3001/health
```

### Configuration

All environment variables:

| Variable | Required | Default | Notes |
|---|---|---|---|
| `JWT_SECRET` | ✅ | — | 32+ random hex chars |
| `INGEST_API_KEY` | ✅ | — | API key for event ingestion |
| `ADMIN_PASSWORD_HASH` | ✅ | — | Bcrypt hash of admin password |
| `ADMIN_USER` | — | `admin` | Admin username |
| `CORS_ORIGIN` | — | `http://localhost:3001` | Comma-separated origins or domain |
| `LOG_RETENTION_DAYS` | — | `90` | Event retention in days |
| `PORT` | — | `3001` | Server port |
| `NODE_ENV` | — | `production` in Docker | Set to `development` for dev |

---

## API Reference

### Authentication

```http
POST /api/auth/login
Content-Type: application/json

{ "username": "admin", "password": "..." }

← { "token": "eyJ...", "user": { "id": 1, "username": "admin", "role": "admin" } }
```

### Event Ingest (API key required)

```http
POST /api/ingest/event
x-api-key: your-ingest-key
Content-Type: application/json

{
  "severity": "HIGH",
  "source_ip": "192.0.2.10",
  "message": "Failed login attempt",
  "category": "authentication",
  "timestamp": "2026-09-29T08:00:00Z",
  "hostname": "gateway"
}

← { "event": { "id": "...", "timestamp": "...", ... } }
```

Bulk ingest (up to 1000 events):

```http
POST /api/ingest/bulk
x-api-key: your-ingest-key
Content-Type: application/json

[{ "severity": "HIGH", ... }, ...]

← { "count": 42 }
```

### Events

```http
GET /api/events?severity=HIGH&category=authentication&search=failed&limit=100&offset=0
Authorization: Bearer <token>

← { "events": [...], "total": 1234 }
```

### Stats

```http
GET /api/stats/summary
Authorization: Bearer <token>

← { "totalEvents": 1234, "openAlerts": 0, "criticalEvents": 5 }
```

### WebSocket (Live Feed)

```javascript
const token = localStorage.getItem('token');
const ws = new WebSocket(`ws://localhost:3001/ws?token=${encodeURIComponent(token)}`);
ws.onmessage = (msg) => console.log(JSON.parse(msg.data));
// Messages: { type: 'event', event: {...} }
```

---

## Architecture

```
.
├── backend/
│   ├── server.js           # Express + WebSocket
│   ├── package.json
│   ├── .env.example
│   ├── data/               # Event storage (JSON)
│   └── scripts/seed.js     # Demo data
├── frontend/
│   ├── src/main.jsx        # React app
│   ├── index.html
│   ├── vite.config.js      # Dev proxy
│   └── package.json
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Security

- Authentication: JWT tokens (8-hour expiry)
- Event ingest: API key (constant-time comparison)
- Rate limiting: 10 login attempts per 15 minutes per IP
- CORS: Restricted by origin
- WebSocket: Requires valid JWT token
- Input validation: Severity, IP, timestamp, string lengths
- Docker: Non-root user, read-only where possible

---

## Roadmap

Planned features (not yet implemented):

- SQLite backend for better performance and persistence
- Alert rules and threshold detection
- Multi-tenancy
- Audit log
- More dashboard pages (Alerts, Rules, Network, Users)
- CSV export

---

## License

MIT
