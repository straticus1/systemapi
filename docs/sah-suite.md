# SAH suite contract

Status: 2026-10-17, as of systemapi.io branch `feat/channel-policy-cli` (a8dc200) plus the sahxfer grant route on `feat/suite-contract-xfer`. This file is the contract for how the SAH names join. Tool commands live in each tool's `docs/usage.md`. If a tool README and this file disagree about what is wired, this file wins.

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
| sahlink | `~/development/sahlink` | Code. TCP forward through the SystemAPI TCP channel: `sahlink HOST:PORT`, `-L PORT`, `--via AGENT`, `rdp`. Also the 0.1.0 `run` and `io` commands. |
| sahsync | `~/development/sahsync` | Code. `ls`, `put`, `get`, and `sync` through the SystemAPI file channel. |
| sahxfer | `~/development/sahxfer` | Code. One large file over sealed UDP datagrams under a SystemAPI grant. Not wired (see Partially wired). |
| sahconnect | `~/development/sahconnect` | HTTP client for systemapi. `ssh` execs the `adssh` binary. |
| sahapi | `~/development/sahapi` | Loopback HTTP service. Three GET proxies. |
| sah2grpc | `~/development/sah2grpc` | Library. Go packages and protobuf only. No command. Nothing wired. |
| sahmesh | `~/development/sahmesh` | Idea only. `IDEA.md`. No code. |
| sahcore | `~/development/sahcore` | Unassigned. Docs only. No binary. |
| adssh | `~/development/adssh` | Execution shell: policy, HMAC chain, four-eyes, break-glass, native SSH when policy allows, local `admin serve`. |
| systemapi | `~/development/systemapi.io` | Linux control plane, outbound agent, CLI, dashboard. |
| computeapi | `~/development/computeapi.io` | On-demand compute catalog. |

The joint suite is a product offering of systemapi and computeapi. The git repositories stay separate. computeapi does not grow a shell. systemapi does not open inbound SSH by default.

## Wired join

These calls exist in code. Nothing else in the suite calls across repositories.

1. `sahconnect api METHOD /path` sends `X-API-Key` to `SYSTEMAPI_URL`. The key is an environment variable. It is not a query parameter. SystemAPI also accepts the same API key as `Authorization: Bearer <key>`: a bearer that is not a device-login token is checked as an API key. A key in the query string is refused (`query_key_rejected`).
2. `sahconnect ssh -- ARGS` execs `SAHCONNECT_ADSSH` or `adssh` on `PATH`. It adds no arguments.
3. `sahapi serve` proxies three GETs when both `SYSTEMAPI_URL` and `SYSTEMAPI_API_KEY` are set. The map is fixed:
   - `GET /v1/systemapi/fleet` → `GET /api/v1/fleet`
   - `GET /v1/systemapi/alerts` → `GET /api/v1/alerts`
   - `GET /v1/systemapi/audit/verify` → `GET /api/v1/audit/verify`
4. `opensah ready` uses `LookPath` for `sahlink`, `sahconnect`, and `sahapi`. A missing `adssh` is reported and does not fail the check.
5. `sahlink run -- COMMAND` starts `COMMAND`. `run` does not call systemapi, computeapi, or adssh. The forward commands do (item 8).
6. `ADSSH_SAH` is a switch inside adssh. It defaults off. Unset, `on`, and any value other than `1`, `true`, or `yes` leave it off. When it is on, `adssh sah` reads one `sah/1` JSON frame from stdin and writes one JSON response. `hello` does not execute a command. `execute` runs the command with `exec` and no shell, and only after a loaded policy allows it. No loaded policy returns `policy_required`. `sahconnect ssh` does not set `ADSSH_SAH` and does not add arguments. The response field `handoff` is `not_wired`. A `lease_id` on the frame does not authorize the command.
7. `sahconnect <server>` (Method A, agent PTY) calls systemapi as `docs/sahconnect-terminal-protocol.md` fixes it: `GET /api/v1/hosts/resolve?name=`, then `POST /api/v1/ws-ticket` with purpose `terminal:open` or `terminal:root` (admin-only scope), then the WebSocket `/api/v1/systems/terminal/<host_id>?ticket=&purpose=&rows=&cols=`. The HTTP calls send the device-login bearer or `X-API-Key` in a header; the single-use ticket is the only query-string secret. On the host, the systemapi agent runs the shell as `--pty-user` (or root for `terminal:root`) and records every byte itself in an HMAC-chained file; the final digest goes into the control plane's audit chain. An ordinary session does not call `adssh`. Break-glass still execs `adssh` as a child process and is recorded by the agent as well. A record that cannot be written refuses or ends the session (`recording_unavailable`). There is no SSH fallback and no signed connect policy yet (phases 2 and 3 of `docs/sahconnect-connect-design.md`).
8. `sahlink HOST:PORT`, `sahlink -L PORT HOST:PORT`, `sahlink --via AGENT ADDR:PORT`, and `sahlink rdp HOST` call systemapi as `docs/sah-tcp-protocol.md` fixes it: `GET /api/v1/hosts/resolve?name=`, then `POST /api/v1/ws-ticket` with purpose `tcp:open` and `target` (`{"host":"local"}` or an IP literal, and a port), then one WebSocket `/api/v1/systems/tcp/<host_id>?ticket=&purpose=tcp:open` per accepted connection. The listener is `127.0.0.1` only. `-R` is `reverse_unsupported`. The server refuses a target unless the host's `tcp_policy`, else the tenant default, allows it. No policy is deny. The agent advertises `tcp`, checks its own `--tcp-allow` list, and dials only the target in the signed `tcp` lease. TCP bytes are not recorded. `tcp_start` and `tcp_end` rows go into the audit chain.
9. `sahsync ls`, `put`, `get`, and `sync` call systemapi as `docs/sah-file-protocol.md` fixes it: resolve, then `POST /api/v1/ws-ticket` with purpose `file:read`, `file:write`, or `file:root` (admin only) and `root`, then the WebSocket `/api/v1/systems/file/<host_id>?ticket=&purpose=`. One session carries sequential ops: `stat`, `list`, `read`, `hash`, `write_open`, `write_chunk`, `write_commit`, `write_abort`, `mkdir`, and `remove`. `sync` sends `mkdir`, and `remove` only with `--delete --yes`. The server refuses a root unless the host's `file_policy`, else the tenant default, allows it with the flag the purpose needs. An intent row is written before every `write_commit`, `mkdir`, and `remove` is forwarded. `file_session_start`, `file_op`, `file_read`, and `file_session_end` rows follow. On the host, the file helper is Linux only: a child process dropped to `pty_user` (root for `file:root`) that opens the root with `openat2` and `RESOLVE_NO_SYMLINKS`, and every path beneath it with `RESOLVE_BENEATH`. The agent advertises `file` only when `openat2` works. A macOS or other non-Linux agent, and a Linux kernel without `openat2`, get `agent_unsupported`. There is no fallback.

Two server-side steps sit under items 8 and 9. They are not cross-repo calls.

- Channel policy is set on the server with `scripts/channel-policy.js` (`show`, `set`, `clear`, `inherit`, with `--tenant`, `--host`, and a required `--reason`). There is no HTTP route that writes a host policy. `set` accepts only `--tcp-local PORT`, `--file-read DIR`, and `--file-write DIR`. It never grants `file:root` and refuses system roots. Every change appends an audit-chain row in the same transaction as the write.
- The first admin of a fresh database is created on the server with `scripts/bootstrap-admin.js` (`docs/bootstrap.md`). No HTTP route creates the first credential.
- The lease signing key must be persistent. Set `SYSTEMAPI_ED25519_SEED` (64 hex characters, `openssl rand -hex 32`, generated once) in the server's env file before the first agent enrolls, and never change it. With `NODE_ENV=production` the server refuses to start when it is unset or malformed. Without it, every restart would rotate the key and every enrolled agent would exit with `control_pubkey_changed`. Development keeps an ephemeral key and logs a warning.
- A host record left behind by a re-enroll (same hostname, new `host_id`) is retired with `POST /api/v1/hosts/:host_id/retire` (admin, required `reason`, `force` for a connected host) or `node cli/systemapi.js retire`. Until then `GET /api/v1/hosts/resolve` still answers by name when exactly one match is online and the others have been offline for more than `SYSTEMAPI_RESOLVE_STALE_HOURS` (default 24); otherwise it is `409 ambiguous` and items 7 to 9 and sahxfer need the `host_id`.

No SAH module imports `github.com/afterdarksys/adssh`. The systemapi agent does not import adssh. Break-glass stays a child process (`adssh/docs/systemapi-embed.md`).

Device login stays in `controlplane/oauth.js`. `adssh identity device login` is a client of that server. It stores an opaque bearer and sets the session user with no groups. It does not import OIDC groups. Dashboard login stays Authentik at `https://auth.afterdarksys.com`, client `systemapi-io-client`. An Authentik access token is not the CLI bearer. sahapi does not serve OAuth.

`adssh admin serve` is the local admin API. It is not a second public API.

## Partially wired

These halves exist in code. They do not call each other end to end. They are not in the Wired join.

- **sahxfer grant.** sahxfer's `put --url` and `get --url` call `GET /api/v1/hosts/resolve` and then `POST /api/v1/xfer/grant` (`internal/control/client.go`). systemapi serves `POST /api/v1/xfer/grant` (`playground/xfer.js`): the same credential rules as the channels; `xfer:put` is checked as `file:write`, `xfer:root` as `file:root`, and `xfer:get` as `file:read`, against the file policy root with its read, write, and root flags. That reuse is what the sahxfer design asks for (design §3.1). The route checks the path, size, and sha256, writes an `xfer_intent` row, pushes `xfer_grant` with the key, the route token, and a signed lease (action `xfer` or `xfer_root`, the 18-line payload below) on the agent WebSocket, waits for the agent's `ready`, and returns the design §3.3 JSON. Grants spend their own rate budget, `SYSTEMAPI_TICKET_RATE_XFER` (default 20 per minute per actor and host), so a put loop does not lock the operator out of the terminal and file tickets; `xfer:root` spends the privileged budget. It renews the lease every 30 s while the agent reports progress (`xfer_status` `active`). It cancels the grant after 60 s with no progress, after `idle_seconds` without progress, at `max_seconds`, when the operator loses the scope or the policy root, or when the HTTP client hangs up before the response. The `xfer_result` row is written by a live server process only: a server restart loses it. A grant the server cancels, or whose agent socket drops, waits out the agent's lease window (60 s plus 30 s skew) for a late `xfer_result` from any socket of that host. With none, the row's status is `unknown`, not `aborted`, because the agent commits without waiting for the server (design §3.6). So design §3.5's rule "a missing result means the target path is unchanged" does not hold here. A missing or `unknown` result means the outcome is not known. It is not end to end, for these reasons:
  - No systemapi agent advertises `xfer` or handles `xfer_grant`. Every real host answers `agent_unsupported`.
  - No relay exists. `SYSTEMAPI_XFER_PEER_MODE` picks the peer. `relay` (the default) signs `dial:<SYSTEMAPI_XFER_PEER_UDP>` and returns that address as `peer.udp`; unset is `agent_unsupported`. `direct` signs `listen` and returns the address the agent reports in its `ready` frame, only if it is an IP literal inside `SYSTEMAPI_XFER_DIRECT_ALLOW` (comma-separated CIDRs, default `127.0.0.0/8,::1/128`); a missing or refused address is `internal` and the grant is cancelled. Direct mode is for loopback tests until the owner decides otherwise.
  - Only `put` over `udp` is issued. `xfer:get`, `xfer:root` with `dir: get`, and every QUIC transport answer `agent_unsupported`. A get needs an agent stat-and-hash step that has no wire frame yet.
  - The lease payload is the 18-line form of the sahxfer end-to-end wiring plan (`sahxfer/docs/plans/2026-10-18-end-to-end-wiring.md`, "Frames and payloads"), built by `xferPayload` in `controlplane/lease.js`: grant id, deadline, phase, dir, root, path, size, sha256, overwrite, transfer id, first-packet deadline, `idle_s`, `max_s`, byte cap, profile, transport, peer, and a material hash of the key and route token. It is signed inside the `systemapi-lease-v1` envelope over `"<action>\n<payload>"`. The shared golden vector is `sahxfer/docs/golden-xfer-lease-v2.txt`, copied into `tests/xfer.test.js`. The server keeps the material hash for renewals, not the key. The agent is the only verifier (plan decision 1); until an agent rebuilds and verifies this payload, nothing checks it on the host.
  - The frames are listed in the `playground/xfer.js` header. `xfer_grant` carries `peer` (`listen` or `dial:<host:port>`) in place of `peer_udp`. `xfer_result` may carry `reason` (a PROTOCOL.md §4.4 ABORT name, `stopped`, or `agent_restart`; anything else is not recorded) and `committed`.

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
