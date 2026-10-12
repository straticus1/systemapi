# systemapi.io defensive security review

Date: 2026-10-12. This is a reading of the control plane, the agent, the CLI, and the drivers, plus the tests named below. It is not a penetration test. No exploit steps are included. `modules/` was not treated as a feature.

## What this pass checked

From `/Users/ryan/development/systemapi.io`:

- `node --test tests/drivers.test.js` — 10 passed.
- `node --test tests/controlplane.test.js` — 16 passed.

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

PTY input, resize, and stop are not covered by a new lease after `pty_start`. A second `pty_start` replaces the session. The timer is the lease expiry.

`modules/` no longer contains the unwired quantum, blockchain, machine-learning, and integration files. Do not put them back.

## Not claimed

No browser pass. No production deploy. No `npm audit fix`. The dependency audit that reported 15 issues earlier was not re-run and was not auto-fixed. The control plane has username-first device login and a Google/GitHub link whitelist. The Authentik authorization-code client in `routes/oauth.js` remains separate. Grafana has a dashboard JSON and does not have alerting rules.
