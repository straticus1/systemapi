# systemapi.io defensive security review

Date: 2026-10-12. This is a reading of the control plane, the agent, the CLI, and the drivers, plus the tests named below. It is not a penetration test. No exploit steps are included. `modules/` was not treated as a feature.

## What this pass checked

From `/Users/ryan/development/systemapi.io`:

- `node --test tests/drivers.test.js` - 10 passed.
- `node --test tests/controlplane.test.js` - 16 passed.

The agent `go test ./...` was green in the previous session and was not re-run here. The dashboard was not opened in a browser. Vite's production build was the earlier frontend check. No live agent dialed this control plane.

## Controls that hold

Production refuses to start when `SESSION_SECRET` is missing or still `default-secret-change-me`. The process exits before session middleware and does not print the secret. `server.js`.

The fleet database pool uses `dbSsl`: `rejectUnauthorized: true`, `minVersion: 'TLSv1.3'`, optional `DB_SSL_CA`. `DB_SSL=disable` turns TLS off. That opt-out is explicit. `server.js`.

JWT verification allowlists `RS256`, `ES256`, and `EdDSA` before verify. `none` and every other alg return null. A missing OIDC client returns null. There is no unsigned fallback. Audience is `OIDC_AUDIENCE` or the Keycloak client id when one of those is set. `playground/auth.js`.

API keys in the query string are rejected (`query_key_rejected`). Browser WebSockets use a single-use `stk_` ticket. Morgan logs `req.path`, so the query string is not in the access line. `controlplane/httpauth.js`, `server.js`.

Agent dial sets TLS 1.3 and does not set `InsecureSkipVerify`. A server URL that contains `api_key` is refused before dial. Enrollment is the headers `x-systemapi-tenant`, `x-systemapi-host-id`, `x-systemapi-hostname`, and `x-systemapi-ssh-pubkey`. The SSH key must be OpenSSH `ssh-ed25519`. Commands stay `not_enrolled` until the control public key is pinned. A changed control key is `control_pubkey_changed` and is not pinned. `systemapi-agent/`.

Entitlement path fields are `[]string`. A JSON bool for a path field grants no paths. Break-glass looks up `adssh` and returns `adssh_missing` when the binary is absent. It does not pass `-r` and it does not fall open to a login shell. The child environment drops names that start with `SYSTEMAPI`, contain `API_KEY`, or start with `ADSTELCO`.

The CLI and both drivers send the key only as `X-API-Key`. They reject a key in the URL, refuse redirects, and cap scripts at 64 KiB. Terraform does not take the key as a variable. Driver tests cover that.

Cross-tenant host reads return not found. A host id that already belongs to another tenant or key is `host_steal`. A user who already has a membership cannot auto-create another tenant. The audit chain detects a tampered payload. Leases match the shared vector in `controlplane/testdata/lease-vector.json`.

## Residuals

An API key with no scope rows has no scopes. `SYSTEMAPI_REQUIRE_SCOPES=0` is an explicit migration escape that still grants operator, including `exec:run` and excluding `breakglass:open` and `admin`. Leave that flag unset. `controlplane/authz.js`.

Webhook HMAC secrets are sealed with AES-256-GCM before insert. The key is `SYSTEMAPI_WEBHOOK_KEY` (64 hex characters) on the control-plane process. Create returns the secret once. Later GET returns the fingerprint. A missing key refuses the create and stores nothing. This is not a remote vault: anyone who can read the process environment can open the column. `controlplane/seal.js`.

`listSecurity` returns only rows whose `tenant_id` is in the caller's set. Enrollment failures stored with a null tenant stay in the table and are not returned by the API. A database reader can still see them. `controlplane/registry.js`.

The browser ticket is a query parameter. The app log omits it. A browser or a proxy can still leak it through `Referer`. Tickets last 60 seconds and are single-use. `controlplane/tickets.js`.

`systemapi_alerts_active` is the process-wide count of alerts with status `open`. It is not a per-tenant series. `controlplane/index.js`.

`upsertSoftware` uses `RETURNING (xmax = 0) AS inserted`. That flag is a PostgreSQL visibility trick and is fragile across versions. `controlplane/registry.js`.

When `DB_PASSWORD` is unset, the playground pool uses `DATABASE_URL` or a local URL and does not call `dbSsl`. The TLS helper applies only on the password path. `server.js`.

CORS allows credentialed requests from `http://localhost:3000` and `http://localhost:5173` in every environment, plus any origin that ends in `.afterdarksys.com` or `.systemapi.io`. Helmet is loaded with `contentSecurityPolicy: false`.

JWT audience, when set, is the OIDC audience or the Keycloak client id. A token whose `aud` is the realm and not the client is rejected. That is fail-closed. Confirm the IdP actually puts the client id in `aud` before production, or legitimate logins will fail.

The agent can emit telemetry before it has pinned the control public key. The server drops telemetry until `hostId` is set, which happens after `registry.enroll` returns. Commands the server sends before the pin are refused by the agent as `not_enrolled`.

Terminal sessions (sahconnect phase 1, 2026-10-14). Each session has a server-generated id; the agent keeps several at once and routes input, resize, EOF and stop by that id. The start lease and every renewal lease (about every 30 s) are verified the same way and are bound to the session id, its deadline and its phase (start or renew), so a renewal cannot start a session, extend another session, or move the deadline. The agent ends a session when the last lease lapses or at the deadline (`SYSTEMAPI_PTY_MAX_SECONDS`, default 28800, also enforced by the server). Input, resize, EOF and stop frames are not individually leased; they reach only a session the lease already authorized. The server routes agent output only to a session owned by that agent connection. Client frames over 64 KiB close with 1009; agent frames over 4 MiB close the agent with 1009. A client whose send buffer passes 8 MiB is ended; an agent that floods its terminal queue is disconnected. The server caps live sessions per actor (8), rate-limits tickets per host (20 a minute), and gives a start 30 s. The agent keeps 4 of 32 slots for break-glass and `terminal:root`, gives each session its own bounded input queue (1 MiB) so a stuck shell cannot block the agent, and ends every session on SIGINT, SIGTERM or disconnect. Ending a session signals its process group and, on Linux, every process in its session; a process that starts its own session (tmux, setsid, a double fork) escapes that and needs cgroups, which phase 1 does not use. Ticket issue, session start and session end are audit-chain rows, and audit rows written since this change hash every column; older rows hash only the payload. A failed end row is retried, then counted (`systemapi_terminal_audit_failures_total`) and recorded as a security event.

`terminal:open` shells run as `--pty-user` with uid, gid and supplementary groups dropped; a root agent without `--pty-user` refuses (`pty_user_unset`), root is refused as the pty user, and membership in privileged groups is logged and audited. A non-root agent refuses `terminal:open` unless `--pty-allow-agent-user` is set, because that shell runs as the agent's own user and can read its key and state or ptrace it. The agent removes `SYSTEMAPI_API_KEY` from its environment after reading it and warns when the key is on argv. `terminal:root` is an admin-only scope with its own lease action, and the server refuses it unless the agent reports `agent` recording.

Recording is done by the agent: every input and output byte goes into an HMAC-chained, per-session file under a 0700 directory, keyed by a 0600 CSPRNG key only the agent reads. The final digest is in the `terminal_end` audit row. A record that cannot be opened, written, or kept up with refuses or ends the session; bytes are not dropped. Mode `user_owned` (non-root agent) means the shell's user holds the key and can rewrite the record; only the audit row's digest then shows what was recorded at the end. The recording file is not marked append-only in the filesystem, and root on the host can rewrite it and recompute the chain.

Terminal follow-up (2026-10-14). The agent refuses `terminal:root` unless it records the session itself (`agent` mode), and the server forwards no client input until the session is announced, which is after the start audit row and the recording check. Ticket rate limits are per actor and host, with a separate budget for break-glass and `terminal:root`. Each recording is capped (`--pty-record-max-bytes`, 1 GiB) and a session is refused when the recording filesystem has less than `--pty-record-min-free` (1 GiB). `systemapi-agent verify-recording` checks a recording's chain, requires its end line, and compares the digest with the audit row. On Linux the agent waits for the shell with `waitid(WNOWAIT)`, signals its process group while the shell is still an unreaped zombie (so the group id cannot be reused), signals other session members through pidfds after re-checking their session id, and only then reaps. On other platforms it reaps first and a reused group id is possible; macOS is not managed.

E2E follow-up (2026-10-14). The enrolled hostname is never overwritten by telemetry, so an agent cannot rename itself into a resolve collision. Terminal WebSocket upgrades that carry an `Origin` must match `SYSTEMAPI_ALLOWED_ORIGINS`; no `Origin` (CLI) is accepted because the ticket is the credential. `GET /api/v1/audit/verify` refuses a caller in no tenant. On macOS the agent sweeps session members with sysctl and getsid, best effort and without pidfds. The agent reconnects with backoff and exits non-zero only on fatal errors. The server binds `HOST` (default 0.0.0.0) and reads `ENV_FILE` or `.env.production` beside `server.js`.

Residual (2026-10-14): cgroup-based containment for setsid/tmux escapes (follow-up). Under the sample systemd unit, `KillMode=control-group` kills such processes when the agent service stops, but not when a single session ends.

Terminal tickets live in process memory. They are lost on restart and are not shared between server nodes; run one node until phase 4 moves them to shared storage. `controlplane/tickets.js`.

Sessions use express-session's default in-memory store. They are lost on restart and are not shared between replicas. `server.js`.

`modules/` no longer contains the unwired quantum, blockchain, machine-learning, and integration files. Do not put them back.

## Not claimed

No browser pass. No production deploy. No `npm audit fix`. The dependency audit that reported 15 issues earlier was not re-run and was not auto-fixed. The control plane has username-first device login and a Google/GitHub link whitelist. The Authentik authorization-code client in `routes/oauth.js` remains separate. Grafana has a dashboard JSON and does not have alerting rules.
