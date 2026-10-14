# SystemAPI

A control plane for running scripts on your own hosts. A Node.js server
(`server.js`, `controlplane/`, `playground/fleet.js`) talks to a Go agent
(`systemapi-agent/`) that dials out over a WebSocket, and a React dashboard
(`frontend/`) sits on top. Scripts are Starlark ("Sysscripts") and every run
carries explicit entitlements.

## What is wired

- Control plane in `controlplane/`: tenants, hosts, Ed25519-signed leases on
  every command, single-use WebSocket tickets, an audit hash chain in
  PostgreSQL, scopes, schedules, sealed webhooks, playbooks.
- An API key with no scope rows has no scopes. `SYSTEMAPI_REQUIRE_SCOPES=0` is
  an explicit migration escape that grants operator; leave it unset.
- Outbound agent in `systemapi-agent/`. It phones home and does not open a
  listening port or an SSH listener.
- Dashboard in `frontend/`: fleet list with real CPU samples, Sysscript IDE,
  web terminal (opened with a single-use ticket), alert events. Containers and
  SSH key distribution are not wired and say so.
- CLI in `cli/systemapi.js`; the key goes only in an `X-API-Key` header.
- Username-first OAuth2 device login (RFC 8628) in `controlplane/oauth.js`.
  The client prints the verification URI and a user code; the user signs in
  through After Dark SSO (Authentik), types the code, checks the requester
  shown, and confirms. SSO identity is the Authentik `sub` only
  (`cp_members.sso_sub`, provider `sub_mode = hashed_user_id`), bound by a
  tenant admin or, for the first admin, `node scripts/sso-bind.js <tenant>
  <member> <sub>`. The user code alone approves nothing.
  Google and GitHub linking needs an admin whitelist row, and binding a
  linked account the first time also needs that SSO session. API keys remain
  the machine credential.
- Ansible and Terraform drivers in `drivers/`. They call REST, not SSH.
- Grafana dashboard `grafana/dashboards/fleet.json`. `systemapi_alerts_active`
  is the process-wide count of open alerts. There are no Grafana alert rules.
- Alerts: the control plane raises z-score anomalies on CPU and memory and posts
  them to tenant webhooks. `sys.alerts.push` in a script is logged on the agent
  only.
- When `DARKSTORAGE_ACCESS_KEY` and `DARKSTORAGE_SECRET_KEY` are set, each
  script result's SHA-256 is also written to the `systemapi-audits` S3 bucket.
  The PostgreSQL audit chain is the record of truth.
- CVE lookup runs only when `DARKAPI_KEY` is set. Nothing invents CVE ids.

`modules/` used to hold unwired quantum-crypto, blockchain and fake ML code.
It was removed; do not put it back.

## Run it locally

Node 22.12 or newer and Go 1.25.7 or newer (see `systemapi-agent/go.mod`).

```bash
npm ci && npm start            # control plane on :3003
cd frontend && npm ci && npm run dev
cd systemapi-agent && go build -o systemapi-agent . && \
  SYSTEMAPI_API_KEY=<key> ./systemapi-agent --tenant <tenant>
```

`SESSION_SECRET` must be set in production or the server refuses to start.
The server listens on `HOST` (default `0.0.0.0`) and `PORT`. It reads
environment from `ENV_FILE` when set, otherwise from `.env.production` next
to `server.js` (not the working directory); variables already set win. Never
commit an env file. `SYSTEMAPI_ALLOWED_ORIGINS` (comma-separated exact
origins) sets the browser origins allowed to open a terminal WebSocket and to
make credentialed CORS requests; CORS keeps only exact `https://` origins (plus
`http://localhost` outside production) and is never served on `/oauth`.
`SYSTEMAPI_TRUST_PROXY` sets Express `trust proxy`, which decides the client
IP shown on the device-login page and used for its rate limit. It is a hop
count (`1` for one reverse proxy) or a comma-separated CIDR list
(`10.0.0.0/8,::1/128`); `true`, names and bare addresses are refused because
they would trust a spoofable `X-Forwarded-For`. Production refuses to start
without it; elsewhere it defaults to loopback proxies. A sample agent unit is
`systemd/systemapi-agent.service`.
Database TLS is on by default (`DB_SSL=disable` opts out, `DB_SSL_CA` adds a
CA). The playground routes under `/playground` need `DB_PASSWORD` and Redis.

## Checks

```bash
npm test                                   # control plane, drivers, route catalog
cd frontend && npm run lint && npm test && npm run build
cd systemapi-agent && go vet ./... && go test ./...
```

## Images

Build images on linux/amd64 or with `docker buildx --platform linux/amd64`.
An image built natively on Apple Silicon fails on amd64 nodes with
`exec format error`.

## More

- `api_docs.md`: REST and WebSocket routes.
- `cli_docs.md`: agent flags, CLI commands, Sysscript modules and entitlements.
- `SECURITY_REVIEW.md`: controls that hold and known residuals.
- `docs/sah-suite.md`: how SystemAPI fits the wider suite.
