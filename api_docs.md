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
- Watching another user's terminal session: `POST /api/v1/ws-ticket` with
  `purpose` `terminal:watch` (view only) or `terminal:watch_rw` (read-write)
  and `{"session_id": "pts_...", "reason": "<text>", "override": false}`
  (`mode`, if sent, must be `ro` or `rw` to match the purpose). The rules:
  - `reason` is required for every watch: 1 to 256 UTF-8 bytes of printable
    characters, no tabs, newlines or control characters. Missing or blank is
    400 `reason_required`; any other bad reason is 400 `bad_reason`.
  - View only with the user's consent needs the scope `terminal:watch` in
    the session's tenant. It is a new scope, admin only (admin implies it);
    a support key is an admin's key restricted to `terminal:watch`.
  - `override: true` (view only, no prompt) and `terminal:watch_rw` need the
    `admin` scope. Read-write is always sent to the agent with override
    false, so the user is always asked.
  - The server signs a watch lease, sends `watch_request` to the agent, and
    waits up to 35 s for `watch_consent`. On a grant it writes the audit row
    `watch_started` and returns the ticket:
    `{"ticket", "expires_at", "expires_in", "host_id", "purpose", "session_id", "watch_id", "mode", "consent"}`.
    `consent` is false only for an admin override.
  - Refusals: 403 `watch_denied` (the user said no, or no answer in time;
    the request is then withdrawn with `watch_stop`), 404 `unknown_session`
    (no such live session, or not in the caller's tenants), 409 `busy`
    (a consent prompt is already open on that session), 403 `scope_denied`,
    429 `rate_limited` (the privileged ticket budget), 502 `agent_error`
    (the agent reported a grant the server did not ask for), 502
    `lease_required` (the agent refused the lease). Each answer from the
    agent writes `watch_refused`.
  - The watcher opens
    `/api/v1/systems/terminal/<host_id>?ticket=<ticket>&purpose=terminal:watch`
    (or `terminal:watch_rw`) within 60 s; a ticket never opened stops the
    watch. The first frame is
    `pty_status {"status": "started", "session_id", "watch_id", "mode"}`, then
    the session's output as binary frames from that point on. A view-only
    watcher's input is dropped by the server; a read-write watcher's
    `pty_input` is forwarded with its `watch_id`. Resize and EOF from a
    watcher are dropped. When the session ends the watcher gets `pty_exit`
    and close 1000. When the watcher closes, the agent gets `watch_stop` and
    the server writes `watch_stopped`.
- `GET /api/v1/systems/terminal/sessions?host_id=<host_id>` lists live
  terminal sessions for `terminal:watch` holders (support and admin), in the
  tenants where the caller holds that scope. `host_id` is optional (404 for a
  host the caller cannot see). Response:
  `{"sessions": [{"session_id", "host_id", "hostname", "tenant", "actor", "purpose", "started_at", "watchers"}]}`.
- Agents: `Authorization: Bearer <key>` on the WebSocket upgrade, plus the
  enrollment headers described in `cli_docs.md`.

`GET /api/v1/audit/verify` returns 403 `scope_denied` to a caller who belongs
to no tenant. It returns `{"ok": true, "head": "<hash>"}`, or
`{"ok": false, "broken_at": <seq>}` at the first bad link or row hash. A fork
pinned in `KNOWN_FORKS` (`controlplane/chain.js`: the parent, the dead-branch
sibling row and the forked row, by hash) still verifies once, only in that
exact shape, and is listed: `{"ok": true, "head": ..., "known_forks": [25]}`.
`/api/v1/compliance/export` carries the same `known_forks`.
Production has one, seq 25 (2026-10-22, before the append lock in d8c8342).

Every route checks a scope (`hosts:read`, `metrics:read`, `exec:run`,
`alerts:write`, `audit:read`, `admin`, ...). An API key with no scope rows has
no scopes.

## Hosts

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/v1/fleet` | Hosts in your tenants. `?q=` filters by hostname. Retired hosts are left out unless `?include_retired=1`; each row carries `retired_at` (null when live). |
| GET | `/api/v1/hosts/resolve?name=` | Exact `host_id`, or exact case-insensitive hostname, in your tenants; retired hosts never match. With several matches, the single online one wins when every other match is offline and last seen more than `SYSTEMAPI_RESOLVE_STALE_HOURS` (default 24) ago. 200, 404 `not_found`, 409 `ambiguous`, 400 `invalid_name`. See `docs/sahconnect-terminal-protocol.md`. |
| POST | `/api/v1/hosts/:host_id/retire` | `admin` scope in the host's tenant. Body `{"reason": "<1-256 chars>", "force": false}`. Stamps `retired_at`, appends a `host_retired` audit row (reason, hostname, forced, last_seen_at) in the same transaction, and keeps the row. A retired host never resolves, is left out of the fleet listing and counts, has no channel policy (deny), and its `host_id` cannot re-enroll (`enroll_error host_retired`). A connected host is refused `409 {"error":"host_online","host_id":...}` unless `"force": true`, which also closes the agent socket (4403 `host_retired`) and so ends its terminal, TCP, file and xfer sessions. 200 `{"host_id","hostname","tenant","retired_at","forced","agent_closed"}`; 400 `reason_required`, `bad_reason`, `bad_force`; 403 `scope_denied`; 404 `not_found`; 409 `already_retired`. The API key the agent enrolled with is not revoked: it is the tenant's key and may serve other hosts. |
| GET | `/api/v1/hosts/:host_id/capabilities` | `hosts:read` in the host's tenant; another tenant's host is `404 not_found` with an `idor` security event. 200 `{"host_id","health","supported","effective","expected","caps":[{"name","state","reason","since","last_report_at"}]}`. See [Capability health](#capability-health). |
| POST | `/api/v1/hosts/:host_id/capabilities/probe` | `admin` scope in the host's tenant. Sends `capability_probe` to the live agent, which re-runs its probes and reports (old agents ignore it). 202 `{"host_id","probe":"sent"}`; 409 `host_offline` when no agent socket is held by this control plane; 403 `scope_denied`; 404 `not_found`. |
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
part of this object. `/api/v1/fleet` rows and `/api/v1/hosts/resolve` also
carry `health` (below).

### Capability health

Self-reported by the agent: it detects breakage (a missing helper, a kernel
without `openat2`), **not compromise** (a compromised agent can report every
capability ok).

- The dial header `X-SystemAPI-Capabilities` names what the agent binary
  supports; `X-SystemAPI-Capabilities-Degraded` (same grammar: at most 16
  tokens of `[a-z][a-z0-9_]{0,15}`, 256 bytes) names the supported ones whose
  probe failed at dial. The agent then sends `{"type":"capability_report",
  "v":1,"probed_at":"<RFC3339>","caps":[{"name","state","reason"}],
  "interval_s":<int>}` after enroll, every `--capability-interval` (default
  10 minutes), on each dial and on a `capability_probe`. `interval_s` is the
  agent's report interval in seconds: optional (older agents omit it), and
  when present an integer from 60 to 3600, else the frame is refused
  `bad_interval`. It is kept per connection, from the latest report. `state` is `ok`, `degraded`
  or `absent`; `reason` is empty when ok, else one of `enosys_openat2`,
  `binary_missing`, `helper_unit_missing`, `helper_trust_missing`,
  `manager_unreachable`, `flag_off`, `unsupported_os`, `no_systemd`,
  `probe_error`.
- A report is taken only after enroll, at most 8 KiB and 16 entries, names
  from the known list (`pty`, `file`, `tcp`, `xfer`, `service`, `config`,
  `package`, `tweak`, `sysscript_jobs`, `converge`, `config_write`,
  `sysctl_write`, `override_write`; others are dropped); anything else in it
  refuses the whole frame. Per agent socket one report is written at a time
  (writes for one host run in order, never overlapping, across reconnects)
  and reports are at least 60 s apart (the first on a connection and the answer
  to a probe excepted); extras are dropped. 10 refused or dropped reports
  within 10 minutes close the agent socket with 1008 and an
  `agent_capability_flood` security event.
- **Routing.** A connection's effective set is the supported header minus
  the degraded header, then each report withdraws the names it marks
  `degraded` or `absent` and restores the ones it marks `ok`; a name missing
  from a report keeps its state, and a report never adds a name the header
  lacks. `sysscript_jobs` and `converge` follow the header only. A withdrawn
  capability answers `agent_unsupported` with its `reason` (when only the
  degraded header named it: `helper_unit_missing` for a `*_write` token,
  `probe_error` otherwise): `{"error":"agent_unsupported",
  "reason":"enosys_openat2"}` in the channel status frame, or the 501 body
  of an xfer grant.
- **sys writes.** `config write` needs `config_write`, `tweak sysctl-set`
  `sysctl_write`, `unit-override-set` and `resource-limit-set`
  `override_write`; reads stay on `config`/`tweak`. An agent whose header has
  none of the three write tokens is an old agent and its writes gate on
  `config`/`tweak` as before. A new agent without the token answers
  `agent_unsupported` with `helper_unit_missing` (or the reason it reported).
- **Expected** capabilities come from the host's effective channel policy:
  file roots `file` (a write root also `xfer`), config paths `config` and
  `config_write`, service units `service`, tweak sysctls `tweak` and
  `sysctl_write`, tweak units `tweak` and `override_write`, package names
  `package`, a tcp allow list `tcp`.
- **`health`**: `offline` (no agent socket), `unknown` (connected, no
  report on this connection yet: old agents, reports off), `degraded` (an
  expected capability is not in the effective set), else `ok`. The instance
  holding the socket computes it and writes it to `cp_hosts.capability_health`
  (only while the host's presence row names that instance); every other
  replica shows that row (`offline` unless the row is online). Disconnect,
  retire and a restart of the holding instance clear it. A restart finds its
  own rows only with a stable `SYSTEMAPI_INSTANCE_ID` (1..64 of
  `[A-Za-z0-9_.-]`, unique per running process; boot marks every host whose
  presence names it offline before taking sockets). Unset, the presence id
  is random per process and a crashed instance's hosts stay until their
  status is next written.
- **`caps`** are the stored rows, kept for every known name a report
  carried (in the header or not) and across reconnects. A row is written
  only when its state or reason changes; `since` is when the state last
  changed and `last_report_at` the report that last wrote the row.
- Alerts, webhooks and metrics: [Capability and offline alerts](#capability-and-offline-alerts)
  and [Prometheus series](#prometheus-series).

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

### Capability and offline alerts

Built-in rules (plan P1b, `controlplane/capalerts.js`), evaluated by the
instance holding the host's agent socket in the 30 s control tick and after
each accepted capability report. N is the report cadence: the larger of
`SYSTEMAPI_CAPABILITY_INTERVAL_S` (integer 60..3600, default 600; anything
else is the default) and the `interval_s` of the connection's latest report.

| `rule_name` | Opens | Resolves |
| --- | --- | --- |
| `capability:<name>` | an **expected** capability (see Capability health) has been out of the connection's effective set for 2 x N continuously | after 2 consecutive reports with it routable, or at the next report once it is no longer expected |
| `capability:reports` | a connection that sent at least one report sends none for 3 x N | after 2 reports |
| `host:offline` | 5 minutes after the host's last agent socket closed (a reconnect inside that window opens nothing, on any replica: the insert re-checks that the row is not online and has no presence written in the last 90 s) | on reconnect |

- A connection that never sent a report (health `unknown`: old agents,
  reports switched off) never opens a capability alert.
- At most one active (`open` or `ack`) alert per host and rule, across
  replicas: the partial unique index
  `cp_alert_events_active_capability_idx` and `ON CONFLICT DO NOTHING`. A
  retired host gets none. `severity` is `warning` for `capability:*` and
  `critical` for `host:offline`; `message` is the capability, state and
  reason code (no paths).
- At most 6 opens per host per rolling hour (all rules together), per
  instance: a flapping agent cannot flood alerts or webhooks. A held-back
  open is counted once in `systemapi_capability_alert_capped_total{rule}`
  and opens once the hour allows, if its condition still holds.
- A failed database write leaves the rule's state as it was; the next tick
  tries again.
- Retiring a host resolves its active `capability:*` and `host:offline`
  alerts in the retire transaction, each with a `capability_alert_resolve`
  audit row (actor the retiring user, `state` and `reason` `retired`); no
  webhook is sent for them.
- Each open and resolve appends an audit row in the same transaction,
  actor `system:capability`, action `capability_alert_open` or
  `capability_alert_resolve`, payload `{"alert_id","rule","capability",
  "state","reason"}`.
- Webhook body, signed like every webhook (`X-SystemAPI-Signature:
  sha256=<HMAC-SHA256 of the raw body with the webhook secret>`):

  ```json
  {"type":"capability_alert","status":"open","rule":"capability:file","alert_id":42,
   "host_id":"c5bf94a5-...","capability":"file","state":"degraded","reason":"enosys_openat2",
   "ts":"2026-11-03T12:20:00.000Z"}
  ```

  `type` is `capability_alert` (`capability:*`; `capability` is `null` for
  `capability:reports`, with `state` `unknown`, `reason` `report_missing`)
  or `host_offline` (`capability` `null`; `state` `offline`, `reason`
  `no_socket` on open; `online`, `reconnected` on resolve). `status` is
  `open` or `resolved`; a resolve carries `state` `ok` (or `not_expected`)
  and `reason` `""`. Opens keep the anomaly cooldown: at most one open
  webhook per host and rule per 5 minutes (the alert row and its audit row
  are always written). A resolve is sent unless its open's webhook was
  suppressed by that cooldown (then neither goes out). `rule` is the alert's
  `rule_name`; `ts` (ISO 8601, inside the signed body) is when the control
  plane evaluated it, so a receiver can drop replays.
- Limits: `host:offline` cannot fire while the control plane is down, nor
  for a host that went offline before the control plane process started;
  use an external check of `/ready`.

### Prometheus series

`GET /metrics` (prom-client). The capability gauges are set in the 30 s
refresh from the database, so every replica reports the same values; a
retired host's series are removed at retire and left out of every refresh.

| Series | Type | Meaning |
| --- | --- | --- |
| `systemapi_capability_state{host_id,capability,state}` | gauge | 1 for the stored state row of each capability per live host (`cp_host_capabilities`) |
| `systemapi_hosts_health{state}` | gauge | live hosts by health: `ok`, `degraded`, `unknown`, `offline` (`offline` unless the host row is online; otherwise the health last written by the instance holding its socket, `unknown` before any) |
| `systemapi_agent_unsupported_total{capability}` | counter | requests this instance refused `agent_unsupported` because the capability is not routable |
| `systemapi_capability_report_dropped_total{reason}` | counter | capability reports this instance refused or dropped: `pre_enroll`, `stale_socket`, `in_flight` (this socket's previous write still running: never a violation), `too_soon`, `unknown_name`, or a validator code (`too_large`, `bad_frame`, `bad_version`, `bad_probed_at`, `bad_interval`, `bad_caps`, `too_many`, `bad_entry`, `duplicate`, `bad_state`, `bad_reason`) |
| `systemapi_capability_alert_capped_total{rule}` | counter | alert opens this instance held back by the 6-per-host-per-hour cap |

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

On an agent that advertises the `sysscript_jobs` capability, these routes
(and `/api/v1/playbooks/:id/run`) run the script as an async sysscript job
and keep the same answer:

- The body may carry `timeout_s`: the whole-script deadline in seconds,
  from 1 to `SYSTEMAPI_SYSSCRIPT_JOB_MAX_S` (default 1800). The default is
  300. A bad value is 400 `bad_timeout`.
- The route waits up to 28 s. A job that ends in time answers 200 as above,
  with `request_id` and a new `job_id` field both set to the job id. A job
  that timed out or was cancelled answers 200 with `result.error` set to
  `timed_out` or `cancelled`.
- A job still running after 28 s answers 504
  `{"error": "agent_timeout", "job_id": "sjb_..."}`. The job runs on; read
  it with `GET /api/v1/jobs/:job_id`.
- New refusals on this path: 400 `bad_timeout`; 400 `bad_entitlements` (a
  list item the canonical form refuses); 400 `bad_script` (a NUL, text that
  is not well-formed, or over 64 KiB of UTF-8); 429 `too_many_jobs` (8 live
  jobs on the host or 64 in the tenant). On `/fleet/execute` a 429 does not
  end the request: that host's entry is `{"host_id": "...", "error":
  "too_many_jobs"}` and the remaining hosts still run. Every other refusal
  (409, 504, 400) still ends the request, as before.
- The audit actions change. These calls write `sysscript_job_submit` and
  `sysscript_job_end` rows, not `sysscript` and `command_result`. Consumers
  that filter the audit log on the old actions must add the new ones.
- Scheduled scripts become jobs too (`source: "schedule"`, `timeout_s` from
  `SYSTEMAPI_SCHEDULE_JOB_TIMEOUT_S`, default 300). Their `schedule` audit
  row gains `job_id`. Playbooks run by an alert rule become jobs with
  `source: "rule"`.

An agent without the capability keeps the old path, unchanged. So does every
agent when the server runs with `SYSTEMAPI_SYSSCRIPT_JOBS=0`, and an agent
held by another server instance whose presence record is older than 90 s.

Entitlements are clamped by the caller's scopes before they reach the agent:
`allow_exec` needs `exec:run`; every other entitlement needs `admin`. The
names the agent understands are listed in `cli_docs.md`.

### Async sysscript jobs

A job runs a Sysscript on one host without holding the HTTP request open. The
host's agent must advertise `sysscript_jobs` (see `cli_docs.md`,
`--sysscript-jobs`).

| Method | Path | Who |
| --- | --- | --- |
| POST | `/api/v1/fleet/:hostId/jobs` | `exec:run` in the host's tenant |
| GET | `/api/v1/jobs/:jobId` | `exec:run` in the job's tenant |
| GET | `/api/v1/jobs?host_id=&status=&limit=` | `exec:run` in at least one tenant |
| POST | `/api/v1/jobs/:jobId/cancel` | `exec:run` in the job's tenant, and either the submitter or `admin` there |

Every answer carries `Cache-Control: no-store`.

**Submit.** Request:

```json
{
  "script": "sys.exec.run(\"sleep\", \"90\")",
  "entitlements": { "allow_exec": true },
  "timeout_s": 600,
  "wait_s": 0
}
```

- `script`: 1 byte to 64 KiB of UTF-8, well-formed, no NUL.
- `entitlements`: an object, clamped by the caller's scopes as above.
- `timeout_s`: the whole-script deadline, an integer from 1 to
  `SYSTEMAPI_SYSSCRIPT_JOB_MAX_S` (default 1800, at most 3600). The default
  is 300. The agent also caps it at its own `--sysscript-max-seconds`.
- `wait_s`: 0 to 25. With 0 the route answers at once. Otherwise it waits up
  to that long for the job to end.

Response: `202 {"job_id": "sjb_...", "status": "submitted", "deadline_unix": 1767225600}`.
A job that ends within `wait_s` answers `200 {"job": {...}}` instead.

**Read.** `GET /api/v1/jobs/:jobId` answers `200 {"job": {...}}`:

```json
{
  "job_id": "sjb_...", "tenant_id": "acme", "host_id": "...",
  "actor": "user-1", "source": "api", "status": "succeeded", "error": null,
  "timeout_s": 600, "deadline_unix": 1767225600,
  "script_sha256": "...", "entitlements_sha256": "...", "alert_count": 0,
  "output_truncated": false, "output_expired": false,
  "cancel_requested_at": null, "created_at": "...", "accepted_at": "...",
  "started_at": "...", "finished_at": "...", "duration_ms": 90012,
  "output_visible": true, "output": "..."
}
```

- `status`: `submitted`, `accepted`, `running`, then one of `succeeded`,
  `failed`, `cancelled`, `timed_out`.
- `error` on a failed job is a code or the agent's message. Codes from the
  server: `dispatch_timeout` (no agent took it within 60 s), `agent_no_ack`
  (sent, not acknowledged within 15 s), `result_lost` (no result by deadline
  + 60 s), and `agent_lost_job` (the agent reconnected without it). Codes from
  the agent include `agent_busy`, `agent_stopped`, `duplicate_job`,
  `bad_host` and `bad_entitlements`.
- `source`: `api`, `execute`, `fleet_execute`, `playbook`, `schedule` or
  `rule`.
- **Output visibility.** Only the submitter and the tenant's admins see
  `output`. Anyone else with `exec:run` gets `output: null`,
  `output_visible: false`, and `error` reduced to a code (`agent_error` when
  the agent's text is not one).
- `output` is capped at 1 MiB (`output_truncated: true` when it was cut).
- **Retention.** Output is removed `SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS`
  (default 72, 1 to 8760) after the job ends, which sets
  `output_expired: true`. Ended jobs are deleted after
  `SYSTEMAPI_JOB_RETENTION_DAYS` (default 30, 1 to 3650).

**List.** `GET /api/v1/jobs` answers `200 {"jobs": [...]}`: newest first, the
jobs of every tenant where the caller holds `exec:run`, without `output` or
`output_visible`. `host_id` and `status` filter. `limit` is 1 to 3 digits:
0 means the default 50, and anything above 200 is cut to 200.

**Cancel.** Answers `202 {"job": {...}}` with `cancel_requested_at` set. The
job ends `cancelled` once the agent has stopped it: SIGTERM to the script's
process group, then SIGKILL 10 s later. A job that has already ended is 409
`job_finished`.

**Errors.**

| Status | `error` | When |
| --- | --- | --- |
| 400 | `bad_script`, `bad_entitlements`, `bad_timeout`, `bad_wait` | Submit body out of range. |
| 400 | `bad_host_id`, `bad_status`, `bad_limit` | List query. |
| 403 | `scope_denied` | No `exec:run`, or a cancel by someone other than the submitter or an admin. |
| 404 | `not_found` | Unknown host or job, or one in another tenant (logged as an `idor` security event). |
| 409 | `agent_offline` | The host's agent is not connected (or its presence on another instance is older than 90 s). |
| 409 | `job_finished` | Cancel of an ended job. |
| 429 | `too_many_jobs` | 8 live jobs on the host, or 64 in the tenant. |
| 501 | `agent_unsupported` | The agent does not advertise `sysscript_jobs`. |
| 503 | `jobs_disabled` | The server runs with `SYSTEMAPI_SYSSCRIPT_JOBS=0`. |

**Server settings.**

| Variable | Default | Meaning |
| --- | --- | --- |
| `SYSTEMAPI_SYSSCRIPT_JOBS` | `1` | `0` is the kill switch: the `/jobs` routes answer 503 and every caller (`/execute`, `/fleet/execute`, playbooks, schedules, rule playbooks) uses the legacy path. Jobs already submitted still end and are stored. |
| `SYSTEMAPI_SYSSCRIPT_JOB_MAX_S` | `1800` | Largest `timeout_s` accepted (1 to 3600). |
| `SYSTEMAPI_SCHEDULE_JOB_TIMEOUT_S` | `300` | `timeout_s` of a scheduled script (1 to 3600). |
| `SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS` | `72` | Hours output is kept after a job ends. |
| `SYSTEMAPI_JOB_RETENTION_DAYS` | `30` | Days an ended job row is kept. |

Rollout and rollback: `docs/sah-sysscript-jobs.md`.

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
| POST | `/api/v1/keys/:keyId/revoke` |
| GET/POST/DELETE | `/api/v1/oauth/links` |

`/api/v1/audit/verify` recomputes the chain inside the control plane. A full
rewrite from some seq on, or a truncated tail, still verifies there. Audit
anchoring (`docs/sah-audit-anchoring.md`) signs the chain head every interval
and after each break-glass start, writes it to WORM buckets as
`checkpoints/<deployment>/<seq>-<time>.note`, and keeps a copy in
`cp_audit_checkpoints`. `scripts/audit-anchor-verify.js` checks it from another
host. There is no HTTP route for checkpoints.

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
    `pty_stop {session_id}`, `watch_request {session_id, watch_id, mode,
    actor, reason, override, lease}`, `watch_stop {session_id, watch_id}`,
    and `pty_input {session_id, watch_id, data_b64}` from a read-write
    watcher;
  - agent to server: `pty_status {session_id, payload}`, `pty_exit {session_id,
    payload: {code, reason}}`, `pty_renew_rejected {session_id, payload: {error}}`,
    `watch_consent {session_id, payload: {watch_id, granted, consent, result|error, mode, actor, reason}}`,
    and binary output frames `[len(session_id)][session_id][bytes]`.
  Terminal lease actions are `pty`, `pty_root` and `breakglass`; each signs
  `<action>\n<session_id>\n<deadline_unix>\n<start|renew>`. A watch lease
  uses the session's own action and signs
  `<action>\n<session_id>\n<deadline_unix>\nwatch\n<watch_id>\n<ro|rw>\n<true|false>\n<reason>`. The agent's
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
