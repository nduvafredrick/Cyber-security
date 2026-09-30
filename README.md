# Sentinel SIEM

Sentinel is a compact Security Information & Event Management (SIEM) platform for collecting, searching, detecting and monitoring security events through a React SOC console.

## Stack

- React + Vite
- Node.js + Express
- SQLite (`better-sqlite3`) with indexed event storage
- bcrypt + JWT-backed **HttpOnly cookie sessions**
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
backend/detection.js      Detection rules
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

For local HTTP development, the `Secure` cookie attribute may require HTTPS depending on the browser. Production deployment should always use HTTPS.

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

Browser authentication uses the session cookie. API clients may also send an `Authorization: Bearer <JWT>` header where direct token authentication is appropriate.

### Events

- `GET /api/events` — supports `limit`, `offset`, `search`, `severity`, and `category`
- `POST /api/ingest/event` with `x-api-key`
- `POST /api/ingest/bulk` with `x-api-key`

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

Run:

```bash
cd backend
npm test
```

The automated suite covers SQLite storage/query behavior and production environment validation. CI additionally builds the frontend, performs a dependency audit, builds the Docker image, and runs a container readiness smoke test.

## Docker deployment

Copy `.env.example` to `.env`, replace the production secrets, then run:

```bash
docker compose up -d --build
```

The production container runs non-root, drops Linux capabilities, enables `no-new-privileges`, uses a read-only root filesystem with a persistent data volume, has resource limits, and exposes a health check against `/ready`.

Put Sentinel behind HTTPS/reverse-proxy infrastructure for production use.

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

1. Add configurable detection-rule management.
2. Add event ingestion connectors and source health.
3. Expand automated API/auth/detection integration tests.
4. Add role-based users and API-key rotation.
5. Add charts, exports and investigation timelines.
6. Evaluate PostgreSQL/OpenSearch/ClickHouse if deployment scale exceeds SQLite.

## License

MIT
