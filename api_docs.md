# SystemAPI REST and WebSocket reference

Routes are mounted by `controlplane/router.js` and `server.js`. This file lists
what is mounted; `tests/catalog.test.js` checks the area index routes against
the router.

## Authentication

- API key: `X-API-Key: <key>` or `Authorization: Bearer <key>`. A key in the
  query string is refused with `query_key_rejected`.
- Dashboard: the OAuth session cookie set by `/oauth/login`. `return_to` must
  be a same-origin path; anything else (including dot segments such as
  `/.//host` or `/%2e%2e//host`) returns to `/`. Logout is
  `POST /oauth/logout` with the session `csrf` (from `GET /oauth/user`).
- SSO identity is the Authentik `sub` only. The Authentik provider must use
  `sub_mode = hashed_user_id`. A session acts as a member only through
  membership rows whose `cp_members.sso_sub` equals that sub byte for byte;
  email, name and username never match, and a NULL `sso_sub` cannot sign in
  (403 `sso_unbound`). One sub maps to one member id (409 `sso_sub_taken`),
  and a member has one sub in every tenant: binding a different sub while
  another row of that member is bound is 409 `sso_sub_conflict`, so changing
  it means unbinding every row first.
  A tenant admin binds one membership row with
  `PUT /api/v1/tenants/:tenant/members/:user/sso` `{"sso_sub": "<sub>"}` and
  removes it with `DELETE` on the same path; each is an audit-chain row
  (`sso_bind`, `sso_unbind`; the sub is stored as a fingerprint). The first
  admin is bound on the server: `node scripts/sso-bind.js <tenant> <member>
  <sub>` (same database and env file as `server.js`, actor
  `bootstrap:sso-bind`).
- Device login (CLI, sahconnect), RFC 8628: `POST /oauth/device` with
  `username` returns exactly `{device_code, user_code, verification_uri,
  expires_in, interval}`. `verification_uri` is `<public URL>/oauth/device/verify`
  with no query; `user_code` is 8 letters from `BCDFGHJKLMNPQRSTVWXZ`, shown as
  `XXXX-XXXX`. There is no `verification_uri_complete`. Poll `POST /oauth/token`
  with `grant_type=urn:ietf:params:oauth:grant-type:device_code`. In the
  browser, `GET /oauth/device/verify` (any query is ignored):
  - no SSO session: a link to `/oauth/login`, which returns to it (no session
    or token is created);
  - a sub not bound on every membership row of a member: 403;
  - otherwise a form where the user types the code. `POST` with `user_code`
    and `csrf` shows a confirm page with the requester's IP, client and start
    time; its "Yes" (`confirm=yes`) or a `provider` button (`google`,
    `github`) approves. Approval needs that confirm page shown in the same
    session and a sub bound on every membership row of the code's member.
  A wrong, used, expired or another member's code gets the same 403. Five
  wrong codes per session (20 per IP) in 15 minutes return 429 `slow_down`,
  and a session's fifth failure denies its member's pending logins. GET never
  approves. Codes last 10 minutes and are single use; the bearer token lasts
  an hour.
- Browser and CLI WebSockets: a single-use ticket from `POST /api/v1/ws-ticket`
  (`purpose` is `terminal:open`, `terminal:root` or `breakglass:open`). Tickets
  last 60 seconds, are bound to one host and purpose, and are audited. Each
  caller gets at most `SYSTEMAPI_TICKET_RATE_PER_HOST` (default 20)
  `terminal:open` tickets a minute per host, and a separate
  `SYSTEMAPI_TICKET_RATE_PRIVILEGED` (default 20) budget for `terminal:root`
  and break-glass; more return 429 `rate_limited`.
  `terminal:root` needs the admin-only scope `terminal:root`.
- Agents: `Authorization: Bearer <key>` on the WebSocket upgrade, plus the
  enrollment headers described in `cli_docs.md`.

`GET /api/v1/audit/verify` returns 403 `scope_denied` to a caller who belongs
to no tenant.

Every route checks a scope (`hosts:read`, `metrics:read`, `exec:run`,
`alerts:write`, `audit:read`, `admin`, ...). An API key with no scope rows has
no scopes.

## Hosts

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/v1/fleet` | Hosts in your tenants. `?q=` filters by hostname. Retired hosts are left out unless `?include_retired=1`; each row carries `retired_at` (null when live). |
| GET | `/api/v1/hosts/resolve?name=` | Exact `host_id`, or exact case-insensitive hostname, in your tenants; retired hosts never match. With several matches, the single online one wins when every other match is offline and last seen more than `SYSTEMAPI_RESOLVE_STALE_HOURS` (default 24) ago. 200, 404 `not_found`, 409 `ambiguous`, 400 `invalid_name`. See `docs/sahconnect-terminal-protocol.md`. |
| POST | `/api/v1/hosts/:host_id/retire` | `admin` scope in the host's tenant. Body `{"reason": "<1-256 chars>", "force": false}`. Stamps `retired_at`, appends a `host_retired` audit row (reason, hostname, forced, last_seen_at) in the same transaction, and keeps the row. A retired host never resolves, is left out of the fleet listing and counts, has no channel policy (deny), and its `host_id` cannot re-enroll (`enroll_error host_retired`). A connected host is refused `409 {"error":"host_online","host_id":...}` unless `"force": true`, which also closes the agent socket (4403 `host_retired`) and so ends its terminal, TCP, file and xfer sessions. 200 `{"host_id","hostname","tenant","retired_at","forced","agent_closed"}`; 400 `reason_required`, `bad_reason`, `bad_force`; 403 `scope_denied`; 404 `not_found`; 409 `already_retired`. The API key the agent enrolled with is not revoked: it is the tenant's key and may serve other hosts. |
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
| PUT/DELETE | `/api/v1/tenants/:tenant/members/:user/sso` (admin; audited) |
| POST | `/api/v1/keys/:keyId/scopes` |
| GET/POST/DELETE | `/api/v1/oauth/links` |

## Threat intelligence

`GET /api/v1/threat-intel/ip/:ip`, `/domain/:domain`, `/otx/:indicator`,
`/crowdsec/:ip`, `/safebrowsing`, and `POST /api/v1/threat-intel/check`. These
proxy cached data from DNSScience (`DNSSCIENCE_API_URL`) and DarkAPI.

## WebSockets

- Agent stream: `/api/v1/systems/stream`. The agent sends `telemetry` every
  5 seconds and `command_result` (`{"error": "...", "output": "..."}`) for each
  script. `sysscript` and `pty_start` carry a signed lease; `pty_renew`
  carries a fresh lease for a live session about every 30 s. Terminal frames
  between server and agent are keyed by `session_id`:
  - server to agent: `pty_start {session_id, action, rows, cols, deadline_unix, lease}`,
    `pty_renew {session_id, lease}`, `pty_input {session_id, data_b64}`,
    `pty_resize {session_id, rows, cols}`, `pty_eof {session_id}`,
    `pty_stop {session_id}`;
  - agent to server: `pty_status {session_id, payload}`, `pty_exit {session_id,
    payload: {code, reason}}`, `pty_renew_rejected {session_id, payload: {error}}`,
    and binary output frames `[len(session_id)][session_id][bytes]`.
  Terminal lease actions are `pty`, `pty_root` and `breakglass`; each signs
  `<action>\n<session_id>\n<deadline_unix>\n<start|renew>`. The agent's
  `pty_status` "started" payload carries `recording` (`agent`, `user_owned` or
  `off`) and `pty_user_privileged_groups`; its `pty_exit` payload carries
  `record {path, digest, bytes_in, bytes_out}` and, on failure,
  `record_error`.
- Terminal: `/api/v1/systems/terminal/:hostId?ticket=<ticket>&purpose=<purpose>&rows=<r>&cols=<c>`.
  A request carrying an `Origin` header must match `SYSTEMAPI_ALLOWED_ORIGINS`
  (comma-separated exact origins; default `https://systemapi.io`, the
  `SYSTEMAPI_PUBLIC_URL` origin, and the local Vite and dev servers outside
  production) or it gets HTTP 403. No `Origin` (the CLI) is accepted.
  The client contract is `docs/sahconnect-terminal-protocol.md`.
  `SYSTEMAPI_PTY_MAX_SECONDS` (default 28800) caps a session,
  `SYSTEMAPI_PTY_MAX_PER_ACTOR` (default 8) caps live sessions per user, and
  `SYSTEMAPI_PTY_CLIENT_BUFFER_MAX` (default 8 MiB) ends a session whose client
  cannot keep up.
