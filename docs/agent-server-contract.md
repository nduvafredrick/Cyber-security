# Sentinel Agent Server Contract v0.1

This document defines the server contract implemented for the first Sentinel Agent.

## Security model

- The organization is always derived server-side from the agent credential.
- Agents make outbound HTTPS requests only.
- Enrollment tokens and agent credentials are high-entropy secrets, shown once and stored as SHA-256 hashes.
- Agent credentials use `sga_<agent_id>.<secret>`.
- Enrollment tokens use `sge_<random>`, expire after 24 hours, and are single-use.
- Secrets are never logged.

## Agent lifecycle

### Admin

`POST /api/agents` — create a pending agent and return a one-time enrollment token.

`GET /api/agents` — list agents in the authenticated administrator's organization.

`GET /api/agents/:id` — return an organization-scoped agent.

`POST /api/agents/:id/disable` — disable an agent immediately.

`POST /api/agents/:id/enable` — re-enable an agent.

`POST /api/agents/:id/rotate` — invalidate the current credential and issue a new enrollment token.

`DELETE /api/agents/:id` — delete the agent. Events retain their plain-text `agent_id`.

Cross-organization agent lookups return 404. Lifecycle actions are audited.

### Enrollment

`POST /api/agent/enroll`

The request contains an enrollment token, hostname, OS and agent version. The token is hashed and resolved to the server-side agent record. The token is atomically marked used before the credential becomes active.

The response contains the organization and integration IDs and the credential once. The agent then stores that credential using OS-appropriate secure storage.

## Heartbeat

`POST /api/agent/heartbeat`

Uses `Authorization: Bearer <agent credential>`.

The server records server-side `last_seen_at`, version, hostname and the latest heartbeat payload.

Health is derived:

- pending: never enrolled
- disabled: explicitly disabled
- online: heartbeat within 90 seconds and status ok
- degraded: heartbeat within 90 seconds but status degraded/error, or queue depth above 1000
- stale: 90 seconds to 5 minutes without a fresh heartbeat
- offline: more than 5 minutes since the last heartbeat

## Event batch ingestion

`POST /api/ingest/events`

Uses the agent credential. Maximum batch size is 500 events and the JSON body is limited to 1 MiB.

Each event requires:

- `timestamp`: RFC 3339 UTC, not more than 24 hours in the future
- `source`: linux, windows, syslog, app, or other
- `category`: authentication, system, network, malware, application, or other
- `event_type`: lowercase alphanumeric/underscore, maximum 64 characters
- `severity`: LOW, MEDIUM, HIGH, or CRITICAL
- `host`: maximum 255 characters
- `message`: maximum 8 KiB

Optional fields:

- `source_ip`
- `metadata`, maximum 16 KiB serialized

The server ignores client-supplied organization and agent identity fields. It assigns organization and agent identity from the authenticated credential.

Batches are idempotent using `(agent_id, batch_id)`. A retry of the same batch is reported as a duplicate and does not insert the events again. Dedupe records are retained for seven days.

Valid events are accepted individually; invalid events are returned with their array indexes. Accepted events enter the existing Sentinel detection and WebSocket pipeline.

## Error behavior

- 200: accepted
- 400: malformed/invalid request
- 401: invalid or unknown credential/enrollment token
- 403: disabled agent
- 413: payload or batch too large
- 429: rate limited
- 5xx/network: agent retries with exponential backoff and jitter

## Rate limits

- Enrollment: 10 attempts/minute per source IP
- Heartbeat: one request every 5 seconds per agent is the intended ceiling
- Event ingestion: 20 requests/second per agent

## Compatibility

The existing `/api/ingest/event`, `/api/ingest/bulk`, and `/api/ingest/syslog` paths remain available during the migration. The new agent path feeds the existing event, detection, alert and WebSocket pipeline.

## v0.1 Go agent scope

The agent will implement:

1. `sentinel-agent enroll --server URL --token ...`
2. secure credential/config storage
3. `sentinel-agent run`
4. periodic heartbeat
5. a stub test-event collector
6. batch upload with ULID batch IDs
7. retry/backoff handling
8. graceful shutdown

Persistent local event queues and production OS collectors are later milestones.
