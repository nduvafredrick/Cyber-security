# Sentinel SIEM

Sentinel is a compact Security Information & Event Management (SIEM) platform for collecting, searching, detecting and monitoring security events through a React SOC console.

## Stack

- React + Vite
- Node.js + Express
- SQLite (`better-sqlite3`) with indexed event storage
- bcrypt + JWT-backed **HttpOnly cookie sessions** with persistent users/roles
- Authenticated WebSocket live telemetry
- Docker / Docker Compose
- GitHub Actions CI

## Authentication

Interactive users authenticate with `POST /api/auth/login`. Sentinel returns an **HttpOnly, Secure, SameSite=Strict** `sentinel_session` cookie containing a short-lived JWT. Browser requests send this cookie automatically; the JWT is not stored in localStorage. `GET /api/auth/me` verifies the session and `POST /api/auth/logout` clears it.

The WebSocket uses the same authenticated session cookie. Connect to `/ws`; there is **no `?token=<JWT>` query parameter**. After connecting, the frontend sends a subscription message such as:

```json
{"type":"subscribe","severity":"HIGH","search":"ssh"}
```

The server applies the subscription filter to live event broadcasts.

## Architecture

```text
frontend/                 React SOC console
backend/server.js         HTTP/WebSocket entry point
backend/config.js         Runtime configuration + production validation
backend/security.js       Cookie/JWT authentication + API-key middleware
backend/storage.js        SQLite persistence, indexes and legacy migration
backend/detection.js      Rule-driven detection engine
backend/logger.js         Structured JSON logging
backend/test/             Automated backend tests
Dockerfile                Production container
docker-compose.yml        Hardened deployment configuration
```

SQLite is the current persistence layer. The storage boundary keeps database concerns isolated so PostgreSQL or another event store can be introduced later if deployment scale requires it.

## Run locally

Backend:

```bash
cd backend
npm install
cp .env.example .env
npm start
```

Frontend development server:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

In development/test, the session cookie is not marked `Secure`, so `http://localhost` and local LAN development can authenticate normally. In production, the cookie is marked `Secure` and the application should be served behind HTTPS.

## Configuration

Required in production:

- `JWT_SECRET` — at least 32 characters
- `INGEST_API_KEY` — at least 20 characters
- `ADMIN_PASSWORD_HASH` — bcrypt hash

Optional:

- `ADMIN_USER` — default `admin`
- `CORS_ORIGIN` — comma-separated allowed origins
- `LOG_RETENTION_DAYS` — default 90
- `PORT` — default 3001
- `DATA_DIR` — SQLite data directory

Generate a bcrypt password hash with:

```bash
node -e "console.log(require('bcryptjs').hashSync('YOUR_PASSWORD', 12))"
```

## API

### Authentication

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

Users are stored in SQLite with bcrypt password hashes and either `admin` or `analyst` roles. The initial admin is bootstrapped from `ADMIN_USER` and `ADMIN_PASSWORD_HASH` on an empty database; subsequent users are managed through the admin API.

Browser authentication uses the session cookie. API clients may also send an `Authorization: Bearer <JWT>` header where direct token authentication is appropriate.

### Events

- `GET /api/events` — supports `limit`, `offset`, `search`, `severity`, and `category`
- `POST /api/ingest/event` with `x-api-key`
- `POST /api/ingest/bulk` with `x-api-key`

### Administration

Admin-only endpoints:

- `GET/POST /api/admin/users` — list/create users
- `PATCH /api/admin/users/:id` — enable/disable a user
- `GET /api/admin/ingest-keys` — list key metadata without secrets
- `POST /api/admin/ingest-keys/rotate` — create a new key and revoke active keys
- `DELETE /api/admin/ingest-keys/:id` — revoke a key
- `GET /api/admin/detection-rules` — list persistent rules
- `PUT /api/admin/detection-rules/:ruleKey` — validate and update a rule

Ingest keys are stored as SHA-256 hashes and the plaintext value is returned only once during rotation.

### Monitoring

- `GET /api/alerts`
- `PATCH /api/alerts/:id`
- `GET /api/stats/summary`
- `GET /api/audit`
- `GET /health` — liveness
- `GET /ready` — readiness/database check
- WebSocket: `/ws`

## Event storage

Events are stored in SQLite at `DATA_DIR/sentinel.db`. SQLite uses WAL mode and indexes commonly queried fields. On first startup with an empty database, Sentinel can migrate legacy `events.json`, `alerts.json`, and `audit.json` files from the data directory. Events are subject to `LOG_RETENTION_DAYS`.

## Testing

Backend:

```bash
cd backend
npm test
```

Frontend/browser:

```bash
cd frontend
npm test
```

The automated suite covers SQLite storage/query behavior, persistent authentication and roles, configurable detection rules, ingest-key rotation, API ingestion, bulk ingestion, WebSocket authentication/live delivery, duplicate-alert suppression, and production environment validation. Playwright browser tests cover sign-in, dashboard rendering, navigation, event search, and severity filtering. CI also performs the frontend build, dependency audit, Docker build, container readiness smoke test, and browser UI tests.

## Docker deployment

Copy `.env.example` to `.env`, replace the production secrets, then run:

```bash
docker compose up -d --build
```

The production container runs non-root, drops Linux capabilities, enables `no-new-privileges`, uses a read-only root filesystem with a persistent data volume, has resource limits, and exposes a health check against `/ready`.

Put Sentinel behind HTTPS/reverse-proxy infrastructure for production use. A Caddy example is provided at `deploy/Caddyfile.example`; Caddy can terminate TLS and proxy both HTTP and WebSocket traffic to Sentinel.

## CI

GitHub Actions verifies backend installation and tests, the frontend production build, high-severity dependency audit, Docker image build, and Docker readiness smoke testing. The workflow runs on pushes, pull requests, or manually through GitHub Actions.

## Security notes

- Helmet security headers
- Restricted CORS
- Login rate limiting
- Constant-time API-key comparison
- JWT issuer validation and expiry
- HttpOnly/Secure/SameSite session cookie
- Input validation and payload limits
- Server-side event pagination/filtering
- Authenticated and filter-aware WebSocket
- Hardened non-root Docker runtime
- Structured JSON logs
- Audit records for authentication and alert changes
- Production environment validation

This is a portfolio/demo SIEM, not a replacement for an enterprise SIEM or security monitoring service.

## Roadmap

The current release is a compact, working SIEM/SOC platform. The following items are the next steps toward a more production-capable security monitoring system:

1. **More detection rules and use cases** — add coverage for account compromise, privilege escalation, suspicious process activity, malware indicators, web attacks, anomalous network behavior, and other common SOC use cases.
2. **More log sources and collectors** — support additional Linux/Windows system logs, application logs, web servers, databases, cloud services, firewalls, and endpoint/security tools.
3. **Reliable high-volume ingestion** — add batching, backpressure, queue-based ingestion, retry handling, connector health, rate controls, and performance testing for sustained event volumes.
4. **Log normalization** — introduce a consistent event schema and parsing pipeline so events from different sources can be searched and correlated consistently.
5. **Long-term retention and backups** — provide configurable retention tiers, scheduled backups, restore verification, archival, and storage monitoring.
6. **Stronger protection against log tampering** — harden audit/event integrity with append-oriented controls, integrity verification, restricted deletion, and separated backup storage.
7. **More sophisticated event correlation** — correlate activity across users, IPs, hosts, time windows, and multiple event types instead of relying primarily on single-rule patterns.
8. **Incident and case management** — allow analysts to create incidents, attach alerts/evidence, assign ownership, track investigation status, record notes, and close cases with an audit trail.
9. **Threat-intelligence integration** — support trusted IOC feeds and enrichment for IP addresses, domains, hashes, and other indicators, with source and freshness tracking.
10. **Monitoring Sentinel itself** — add health and performance telemetry for ingestion, database usage, WebSocket connections, detection processing, storage, and connector availability.
11. **Production database architecture** — evaluate PostgreSQL, OpenSearch, ClickHouse, or another event store when concurrency, event volume, retention, or deployment topology exceeds SQLite's practical limits.
12. **Operational response process** — document alert triage, escalation, investigation, containment, recovery, evidence handling, and post-incident review procedures.
13. **Scoped ingest keys and connector health** — issue separate credentials per source/connector, support scoped permissions, rotation/revocation, expiration, and source-level health status.
14. **Investigation and reporting** — add dashboards, timelines, exports, saved searches, and analyst-friendly reporting.

## License

MIT
