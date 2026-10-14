# SAH suite contract

Status: 2026-10-12. This file is the contract for how the SAH names join. Tool commands live in each tool's `docs/usage.md`. If a tool README and this file disagree about what is wired, this file wins.

**sah** means Service Automation Hub. The hub encompasses the platform and the suite of utilities. `adssh` is the development name of the execution shell. The binary, the module `github.com/afterdarksys/adssh`, `adssh-mcp`, `~/.adssh`, and the GitHub repo `afterdarksys/adssh` stay on that name until a rename is explicit.

## Domains

Recorded 2026-10-13. These four names are owned. Nothing is published on them yet. A later publish step hosts the hub site. Until that publish, `systemapi.io` and `computeapi.io` remain the live product sites.

| Domain | Use |
| --- | --- |
| `opensah.com` | Public site of the hub. |
| `opensah.io` | Product hostname, beside `systemapi.io` and `computeapi.io`. |
| `opensah.dev` | Docs and install. |
| `sah.sh` | Short name for the hub and the shell. |

These domains do not rename a repository, a binary, or a Go module. `adssh` stays the development name of the shell.

## Names

| Name | Directory | What exists |
| --- | --- | --- |
| opensah | `~/development/opensah` | `version`, `tools`, `ready`. A local index. |
| sahlink | `~/development/sahlink` | Starts one program and records its stdio. Optional loopback socket relay. |
| sahconnect | `~/development/sahconnect` | HTTP client for systemapi. `ssh` execs the `adssh` binary. |
| sahapi | `~/development/sahapi` | Loopback HTTP service. Three GET proxies. |
| sahcore | `~/development/sahcore` | Unassigned. Docs only. No binary. |
| adssh | `~/development/adssh` | Execution shell: policy, HMAC chain, four-eyes, break-glass, native SSH when policy allows, local `admin serve`. |
| systemapi | `~/development/systemapi.io` | Linux control plane, outbound agent, CLI, dashboard. |
| computeapi | `~/development/computeapi.io` | On-demand compute catalog. |

The joint suite is a product offering of systemapi and computeapi. The git repositories stay separate. computeapi does not grow a shell. systemapi does not open inbound SSH by default.

## Wired join

These calls exist in code. Nothing else in the suite calls across repositories.

1. `sahconnect api METHOD /path` sends `X-API-Key` to `SYSTEMAPI_URL`. The key is an environment variable. It is not a query parameter.
2. `sahconnect ssh -- ARGS` execs `SAHCONNECT_ADSSH` or `adssh` on `PATH`. It adds no arguments.
3. `sahapi serve` proxies three GETs when both `SYSTEMAPI_URL` and `SYSTEMAPI_API_KEY` are set. The map is fixed:
   - `GET /v1/systemapi/fleet` → `GET /api/v1/fleet`
   - `GET /v1/systemapi/alerts` → `GET /api/v1/alerts`
   - `GET /v1/systemapi/audit/verify` → `GET /api/v1/audit/verify`
4. `opensah ready` uses `LookPath` for `sahlink`, `sahconnect`, and `sahapi`. A missing `adssh` is reported and does not fail the check.
5. `sahlink run -- COMMAND` starts `COMMAND`. It does not call systemapi, computeapi, or adssh.
6. `ADSSH_SAH` is a switch inside adssh. It defaults off. Unset, `on`, and any value other than `1`, `true`, or `yes` leave it off. When it is on, `adssh sah` reads one `sah/1` JSON frame from stdin and writes one JSON response. `hello` does not execute a command. `execute` runs the command with `exec` and no shell, and only after a loaded policy allows it. No loaded policy returns `policy_required`. `sahconnect ssh` does not set `ADSSH_SAH` and does not add arguments. The response field `handoff` is `not_wired`. A `lease_id` on the frame does not authorize the command.

No SAH module imports `github.com/afterdarksys/adssh`. The systemapi agent does not import adssh. Break-glass stays a child process (`adssh/docs/systemapi-embed.md`).

Device login stays in `controlplane/oauth.js`. `adssh identity device login` is a client of that server. It stores an opaque bearer and sets the session user with no groups. It does not import OIDC groups. Dashboard login stays Authentik at `https://auth.afterdarksys.com`, client `systemapi-io-client`. An Authentik access token is not the CLI bearer. sahapi does not serve OAuth.

`adssh admin serve` is the local admin API. It is not a second public API.

## Not wired

A machine provisioned by computeapi does not enroll in systemapi. These tools do not hand adssh a systemapi lease. The design sentence "computeapi provisions, the machine enrolls through systemapi, adssh executes under policy and a lease" is not an implementation. The `ADSSH_SAH` switch does not perform that handoff.

Wired compute adapters are Vast.ai and io.net. There is no Azure, Amazon, Google, or Oracle compute adapter. Storage provider names are not compute adapters. There is no k3s allocator and no bare-metal allocator. macOS is not a managed platform. The agent has Darwin software-inventory and PTY branches only.

## Rules

- Add a cross-repo call only by editing the caller, the callee, and the Wired join list in this file in the same change. A roadmap sentence does not make the call real.
- sahapi accepts no client-supplied upstream URL. A caller-chosen URL would turn the proxy into an SSRF hop.
- sahlink does not attach to a PID and does not ptrace. Capture applies to the process it starts.
- Compare tokens by SHA-256 of both sides, then a constant-time compare. Do not print tokens or API keys.
- TLS to https origins is at least TLS 1.3 with the system CA pool. Do not set `InsecureSkipVerify` or `rejectUnauthorized: false`.
- Leave `sahcore` without a binary until a role is assigned. Inventing a program invents a product.

## Next

From the sibling checkouts, `cd ~/development/opensah && go test ./...`. Then `opensah tools`.
