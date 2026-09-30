# Sentinel SIEM

Sentinel is a compact Security Information & Event Management (SIEM) platform for collecting, searching and monitoring security events.

## Stack
- React + Vite
- Node.js + Express
- JWT authentication + bcrypt
- WebSocket live telemetry
- JSON persistence for the demo deployment
- Docker / Docker Compose

## Architecture

```
frontend/                 React SOC console
  src/main.jsx            Application and views
  src/style.css           Dark operations UI
backend/
  server.js               HTTP/WebSocket entry point
  config.js               Runtime configuration
  security.js             Authentication/API-key middleware
  storage.js              Persistence boundary
  detection.js            Detection rules
  scripts/seed.js         Demo telemetry
```

The storage layer is deliberately isolated so SQLite/PostgreSQL can replace the JSON implementation without rewriting the API or UI.

## Run locally

```bash
cd backend && npm install
cp .env.example .env
node server.js
```

In another terminal:

```bash
cd frontend && npm install && npm run dev
```

Open `http://localhost:5173`.

## Configuration

Required in production:
- `JWT_SECRET`
- `INGEST_API_KEY`
- `ADMIN_PASSWORD_HASH`

Optional:
- `ADMIN_USER` (default `admin`)
- `CORS_ORIGIN` (comma-separated)
- `LOG_RETENTION_DAYS` (default 90)
- `PORT` (default 3001)

Generate a bcrypt password hash with:

```bash
node -e "console.log(require('bcryptjs').hashSync('YOUR_PASSWORD', 12))"
```

## API

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/events`
- `GET /api/alerts`
- `PATCH /api/alerts/:id`
- `GET /api/stats/summary`
- `GET /api/audit`
- `POST /api/ingest/event` with `x-api-key`
- `POST /api/ingest/bulk` with `x-api-key`
- `GET /health`
- WebSocket: `/ws?token=<JWT>`

## Security notes

- Helmet security headers
- Restricted CORS
- Login rate limiting
- Constant-time API-key comparison
- JWT issuer validation and expiry
- Input validation and payload limits
- Non-root Docker runtime
- Audit records for administrative authentication and alert changes

This is a portfolio/demo SIEM, not a replacement for an enterprise SIEM or a security monitoring service.

## Roadmap

1. Replace JSON persistence with SQLite/PostgreSQL.
2. Add configurable detection-rule management.
3. Add event ingestion connectors and source health.
4. Add automated tests and security scanning.
5. Add role-based users and API-key rotation.
6. Add charts, exports and investigation timelines.

## License

MIT
