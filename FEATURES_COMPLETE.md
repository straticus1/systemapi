# SystemAPI

Updated 2026-10-12. This file used to be a March 2026 brochure that marked unwired code as complete. That brochure is gone.

What is wired:

- Control plane in `controlplane/`: tenants, hosts, Ed25519 leases, single-use tickets, audit hash chain, scopes, schedules, sealed webhooks, playbooks.
- An API key with no scope rows has no scopes. `SYSTEMAPI_REQUIRE_SCOPES=0` is the explicit migration escape and grants operator.
- Outbound agent in `systemapi-agent/`. It phones home. It does not open an inbound SSH listener.
- Dashboard in `frontend/`. The terminal opens with a single-use ticket. The dashboard has not been exercised in a browser.
- CLI in `cli/systemapi.js`. The API key is an `X-API-Key` header, taken from `SYSTEMAPI_API_KEY`.
- Username-first OAuth2 device login in `controlplane/oauth.js`. `systemapi.js login <username>` prints a verification URL. Google and GitHub can be enabled, and linking either account requires an admin whitelist row. API keys remain the machine credential.
- Ansible and Terraform drivers in `drivers/`. They call REST. They do not open SSH.
- Grafana dashboard `grafana/dashboards/fleet.json`. `systemapi_alerts_active` is the process-wide count of open alerts.

What was removed:

- `modules/` held quantum cryptography, a blockchain audit trail, fake machine-learning operations, and unwired integrations. Nothing in the server imported it. The directory now only records that removal.

CVE lookup runs only when `DARKAPI_KEY` is set. This tree does not invent CVE identifiers.
