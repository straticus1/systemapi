# SystemAPI REST and WebSocket reference

Routes are mounted by `controlplane/router.js` and `server.js`. This file lists
what is mounted; `tests/catalog.test.js` checks the area index routes against
the router.

## Authentication

- API key: `X-API-Key: <key>` or `Authorization: Bearer <key>`. A key in the
  query string is refused with `query_key_rejected`.
- Dashboard: the OAuth session cookie set by `/oauth/login`.
- Browser WebSockets: a single-use ticket from `POST /api/v1/ws-ticket`
  (`purpose` is `terminal:open` or `breakglass:open`). Tickets last 60 seconds.
- Agents: `Authorization: Bearer <key>` on the WebSocket upgrade, plus the
  enrollment headers described in `cli_docs.md`.

Every route checks a scope (`hosts:read`, `metrics:read`, `exec:run`,
`alerts:write`, `audit:read`, `admin`, ...). An API key with no scope rows has
no scopes.

## Hosts

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/v1/fleet` | Hosts in your tenants. `?q=` filters by hostname. |
| GET | `/api/v1/fleet/export` | Same list; `?format=csv` for CSV. |
| GET | `/api/v1/fleet/efficiency` | Average CPU and memory per host over the last 100 samples. |
| GET | `/api/v1/fleet/:hostId/software` | Installed software reported by the agent. |
| GET | `/api/v1/fleet/:hostId/cves` | CVEs for that software. Empty unless `DARKAPI_KEY` is set. |
| GET/POST | `/api/v1/fleet/:hostId/comments` | Host notes. |

A host in the list looks like:

```json
{
  "host_id": "c5bf94a5-...",
  "tenant_id": "acme",
  "hostname": "db-01",
  "os": "linux",
  "platform": "ubuntu",
  "status": "online",
  "last_seen_at": "2026-10-12T11:25:16Z",
  "tags": [],
  "cpu_percent": 14.5,
  "sparkline": [12.1, 13.0, 14.5]
}
```

`cpu_percent` is the latest `cpu.usage_percent` sample and is `null` when there
is none. Memory, disk and network figures are stored as telemetry but are not
part of this object.

## Metrics and alerts

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/v1/fleet/:hostId/metrics` | `?metric=cpu.usage_percent` (or `memory.used_percent`, `disk.used_percent`), `?bucket=minute`, `?from=`, `?to=`. |
| GET | `/api/v1/fleet/:hostId/forecast` | Linear forecast over the last 60 samples. |
| GET | `/api/v1/fleet/:hostId/anomalies` | Z-score over the last 60 samples. |
| GET | `/api/v1/alerts` | Alert events. `?status=open|ack|resolved`. |
| POST | `/api/v1/alerts/:id/ack` | |
| POST | `/api/v1/alerts/:id/resolve` | |

Alert events are raised by the control plane's z-score check on CPU and memory
telemetry and posted to the tenant's webhooks. There is no API for alert rules.

## Execution

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/api/v1/fleet/:hostId/execute` | Run a Sysscript on one host. |
| POST | `/api/v1/fleet/execute` | `host_ids` (1 to 50) plus `script`. |
| POST | `/api/v1/fleet/:hostId/breakglass` | Break-glass session (needs `adssh` on the host). |
| GET | `/api/v1/playbooks` | Playbooks in `controlplane/playbooks/`. |
| POST | `/api/v1/playbooks/:id/run` | |
| GET/POST | `/api/v1/schedules` | Cron schedules. `DELETE /api/v1/schedules/:id`. |

Request:

```json
{
  "script": "r = sys.exec.run(\"uname\", \"-a\")\nprint(r[\"output\"])",
  "entitlements": { "allow_exec": true }
}
```

Response:

```json
{
  "success": true,
  "request_id": "9f1c...",
  "result": { "error": "", "output": "Linux db-01 6.8.0 ...\n" },
  "executed_by": "ops@example.com"
}
```

`success` means the agent answered. A script that failed on the host comes
back with `success: true` and a non-empty `result.error`; check that field.

Entitlements are clamped by the caller's scopes before they reach the agent:
`allow_exec` needs `exec:run`; every other entitlement needs `admin`. The
names the agent understands are listed in `cli_docs.md`.

## Audit, compliance, tenants

| Method | Path |
| --- | --- |
| GET | `/api/v1/audit`, `/api/v1/audit/verify`, `/api/v1/audit/export` |
| GET | `/api/v1/security-events` |
| GET | `/api/v1/compliance/export` |
| GET/POST | `/api/v1/webhooks`; `DELETE /api/v1/webhooks/:id` |
| POST | `/api/v1/tenants/:tenant/members` |
| POST | `/api/v1/keys/:keyId/scopes` |
| GET/POST/DELETE | `/api/v1/oauth/links` |

## Threat intelligence

`GET /api/v1/threat-intel/ip/:ip`, `/domain/:domain`, `/otx/:indicator`,
`/crowdsec/:ip`, `/safebrowsing`, and `POST /api/v1/threat-intel/check`. These
proxy cached data from DNSScience (`DNSSCIENCE_API_URL`) and DarkAPI.

## WebSockets

- Agent stream: `/api/v1/systems/stream`. The agent sends `telemetry` every
  5 seconds and `command_result` (`{"error": "...", "output": "..."}`) for each
  script. The server sends `sysscript`, `pty_start`, `pty_input`, `pty_resize`
  and `pty_stop`, each carrying a signed lease.
- Terminal: `/api/v1/systems/terminal/:hostId?ticket=<ticket>`.
