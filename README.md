# 🛡️ Sentinel SIEM v2

A production-grade, multi-tenant Security Information & Event Management platform.

## What's new in v2

| Area | v1 | v2 |
|------|----|----|
| Multi-tenancy | ❌ Global tables | ✅ Org-scoped — every row has `org_id` |
| Auth | JWT login only | JWT + Refresh tokens (30-day sessions) |
| Audit log | ❌ | ✅ Full action trail with actor, target, IP |
| Alerts | Basic list | Paginated, searchable, bulk actions, notes, modal detail |
| Events | Simple table | Live/Historical toggle, search, CSV export, row detail |
| Rules | Toggle only | Full CRUD with visual condition builder + MITRE mapping |
| Network | Block/unblock | + Top talkers, bar chart, validation |
| Users | Single user | Admin user management — create, delete, role-based |
| WS | Broadcast all | Org-scoped — tenants only see their own events |
| Simulator | Random events | Realistic scenarios + brute-force wave every 90s |
| DB schema | 5 tables, no indexes | 8 tables, 7 indexes, foreign keys |
| Error handling | Minimal | Global Express error handler, try/catch everywhere |
| Docker | ❌ | ✅ Dockerfile + docker-compose |

---

## Quick Start (Development)

```bash
# 1. Install & seed backend
cd backend
cp .env.example .env      # edit secrets if needed
npm install
node scripts/seed.js      # creates DB, org, users, rules

# 2. Start backend
node server.js

# 3. In a new terminal — start frontend
cd frontend
npm install
npm run dev               # http://localhost:5173
```

**Default credentials:**
| Username | Password | Role |
|----------|----------|------|
| admin | SentinelAdmin2024! | admin |
| engineer | Engineer2024! | engineer |
| analyst | Analyst2024! | analyst |

---

## Production (Docker)

```bash
# Generate secrets
export JWT_SECRET=$(openssl rand -hex 32)
export JWT_REFRESH_SECRET=$(openssl rand -hex 32)
export INGEST_API_KEY=$(openssl rand -hex 20)

# Build and run
docker-compose up -d

# Seed the database (first time only)
docker exec sentinel-siem node scripts/seed.js

# Check health
curl http://localhost:3001/health
```

---

## API Reference

### Authentication
```http
POST /api/auth/login
{ "username": "admin", "password": "..." }
→ { token, refreshToken, user }

POST /api/auth/refresh
{ "refreshToken": "..." }
→ { token }

GET /api/auth/me            # requires Bearer token
```

### Event Ingest (API key auth)
```http
# Single event
POST /api/ingest/event
x-api-key: your-ingest-key
{ "severity": "HIGH", "source_ip": "1.2.3.4", "message": "...", "category": "authentication" }

# Bulk (up to 1000)
POST /api/ingest/bulk
x-api-key: your-ingest-key
[{ ... }, { ... }]

# Syslog line
POST /api/ingest/syslog
x-api-key: your-ingest-key
{ "line": "<14>Jan 1 00:00:00 host sshd: Failed password for root from 1.2.3.4" }
```

### Events
```http
GET /api/events?severity=HIGH&category=authentication&search=failed&limit=100&offset=0
GET /api/events/:id
GET /api/events/export/csv?severity=HIGH
```

### Alerts
```http
GET /api/alerts?status=NEW&severity=CRITICAL&search=brute&limit=25&offset=0
PATCH /api/alerts/:id        { status, assignee, notes }
POST /api/alerts/bulk        { ids: [...], action: "resolve"|"close"|"acknowledge" }
DELETE /api/alerts/:id       (admin only)
```

### Rules
```http
GET    /api/rules
POST   /api/rules            { name, severity, logic, mitre_id, window_secs }
PATCH  /api/rules/:id        { enabled, name, severity, ... }
DELETE /api/rules/:id        (admin only)
POST   /api/rules/:id/test   { event: { ... } }  → { matched: true/false }
```

### Stats
```http
GET /api/stats/summary
GET /api/stats/events-by-severity
GET /api/stats/events-over-time?hours=24
GET /api/stats/alerts-over-time
GET /api/stats/top-sources
GET /api/stats/mttr
GET /api/stats/audit          (admin only)
```

---

## Detection Rule Logic

Rules support three types:

### Signature — match every event
```json
{
  "type": "signature",
  "conditions": [
    { "field": "category", "op": "eq",       "value": "malware" },
    { "field": "message",  "op": "contains", "value": "c2" }
  ]
}
```

### Threshold — N events from same group within window
```json
{
  "type": "threshold",
  "count": 5,
  "group_by": "source_ip",
  "conditions": [
    { "field": "protocol", "op": "eq", "value": "SSH" },
    { "field": "message",  "op": "contains", "value": "failed" }
  ]
}
```

### Operators
`eq` · `neq` · `contains` · `not_contains` · `regex` · `gt` · `lt` · `in` · `exists`

---

## Architecture

```
sentinel-v2/
├── backend/
│   ├── server.js              # Express + WS bootstrap
│   ├── db.js                  # sql.js wrapper, schema, migrations
│   ├── correlationEngine.js   # Rule evaluation, threshold counters
│   ├── simulator.js           # Dev log generator
│   ├── websocket.js           # Org-scoped WS broadcast
│   ├── middleware/
│   │   └── audit.js           # Audit log writer
│   ├── routes/
│   │   ├── auth.js            # Login, refresh, user mgmt
│   │   ├── alerts.js          # CRUD + bulk ops
│   │   ├── events.js          # Query + export
│   │   ├── rules.js           # CRUD + test endpoint
│   │   ├── network.js         # Block list + top talkers
│   │   ├── ingest.js          # API key auth, event normalization
│   │   └── stats.js           # Aggregations, MTTR, audit
│   └── scripts/seed.js
└── frontend/
    └── src/
        ├── App.jsx             # Auth, WS, layout
        ├── components/
        │   ├── UI.jsx          # Design system (Badge, Button, Card, Modal, …)
        │   └── Toast.jsx       # Global notification system
        └── pages/
            ├── Dashboard.jsx   # Stats, charts, live feed
            ├── Alerts.jsx      # Table, bulk, modal, notes
            ├── EventLog.jsx    # Live/historical, search, export
            ├── Rules.jsx       # CRUD, visual builder
            ├── Network.jsx     # Block list, top talkers
            ├── Users.jsx       # User management (admin)
            └── AuditLog.jsx    # Action trail (admin)
```
