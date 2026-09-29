# Sentinel SIEM

A defensive security-monitoring MVP with authenticated APIs, organization-scoped event storage, alerting, audit logs, and a lightweight SOC dashboard.

## Architecture

Browser dashboard → Express API → authentication / ingestion / alerting → SQLite.

## Security controls

- JWT authentication with short-lived tokens.
- Separate ingestion API key.
- Zod request validation and bounded JSON body size.
- Organization-scoped reads and alert updates.
- Helmet and restricted CORS.
- Password hashing with Node.js scrypt.
- Timing-safe API-key comparison.
- Audit records for authenticated actions.
- SQLite WAL mode and indexes.

## Run locally

Copy `backend/.env.example` to `.env`, set strong secrets, then run:

```bash
npm --prefix backend install
npm --prefix backend start
```

The service listens on port 3000 by default.

## Docker

Create a root `.env` with the required variables and run:

```bash
docker compose up --build
```

## API

- `GET /health`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/ingest/event`
- `GET /api/events`
- `GET /api/alerts`
- `PATCH /api/alerts/:id`
- `GET /api/stats/summary`
- `GET /api/audit`

## Limitations

This is a portfolio/MVP SIEM, not an enterprise SIEM. Production work should add refresh-token rotation, distributed rate limiting and correlation state, stronger RBAC, immutable remote audit storage, retention policies, backups, TLS termination, automated security testing, and a production-grade ingestion pipeline.

See [SECURITY.md](SECURITY.md).