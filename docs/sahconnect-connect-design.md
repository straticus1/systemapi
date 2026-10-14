# `sahconnect <server>`: design

Status: APPROVED in principle, 2026-10-14 (decisions below). Nothing here is wired until
`sah-suite.md` lists it (Rules: caller, callee and the Wired join list change
together).

## Goal

```
sahconnect web1
```

opens an interactive shell on `web1`.

- **Method A, `agent` (default).** A shell through SystemAPI. The host's
  outbound agent runs the PTY. The host needs no inbound SSH.
- **Method B, `ssh` (fallback).** A shell over SSH, run through `adssh` under
  policy.
- **Client config** chooses the preference: `agent`, `ssh`, or `agent,ssh`
  (default).
- **The server can enforce** a method per host or tenant. Enforcement always
  beats client config, and the client cannot downgrade around it.

## Non-goals (this design)

- macOS hosts as managed targets (the contract says macOS is not managed).
- File copy, port forwarding, multiplexed sessions. A later design can add
  them.
- Browser terminal changes beyond what the shared server fixes require.

## Selection rules

The server's answer is authoritative. The client's preference only orders the
methods the server allows.

| Server policy for host | Client pref `agent,ssh` | Client pref `agent` | Client pref `ssh` |
|---|---|---|---|
| `any` | A; on A failure → B | A only | B only |
| `agent-only` (enforced) | A; on A failure → **error, no B** | A only | **refused** |
| `ssh-only` (enforced) | B | **refused** | B |
| unknown (SystemAPI unreachable, no valid cached policy) | **error** | **error** | B only if a valid cached signed policy permits ssh; else **error** |

**Downgrade rule.** B is used only when a *fresh, signed* policy statement for
that host permits `ssh`. B is never used because A merely failed or SystemAPI
was unreachable.

## Components

### 1. SystemAPI (server)

1. **Host resolution: `GET /api/v1/hosts/resolve?name=<n>`.** Exact,
   case-insensitive hostname or `host_id` match within the caller's tenants.
   It returns exactly one host or an error. The current fleet search is a
   substring `ILIKE` and must not be used to choose a target.
2. **Access policy.** A new column holds the policy per host, with a tenant
   default:

   ```json
   {"allowed": ["agent","ssh"], "enforce": true, "ssh": {"addr": "...", "port": 22, "user": "...", "host_key": "ssh-ed25519 ..."}}
   ```

   `allowed` is any non-empty subset of `agent` and `ssh`. `enforce=false`
   means the client's preference decides among the allowed methods.
3. **Signed policy statement: `GET /api/v1/hosts/<id>/connect-policy`.** It
   returns `{host_id, tenant, allowed, enforce, ssh?, issued_at, expires_at}`
   signed with the control-plane ed25519 key. That is the key agents already
   pin (`lease.go`). The statement lives a short time (default 15 min).
4. **Ticket issuance enforces policy.** `POST /api/v1/ws-ticket` with purpose
   `terminal:open` is refused when the host's policy does not allow `agent`.
5. **Terminal sessions that outlive 60 s.**
   - Each session gets a session id. The lease is renewed while the session
     is live, or a separate session TTL with a hard maximum is used (default
     8 h), so the PTY no longer dies at the first lease expiry.
   - Subscribers are keyed by session, not host, so several terminals per
     host can run.
6. **Frames.**
   - Add `{type:"pty_exit", code}`, so the client can exit with the remote
     status.
   - Add `{type:"pty_eof"}` for stdin EOF.
7. **Audit.** Write an audit record on ticket issue, terminal open and
   terminal close: who, host, method, session id, duration and exit code.
   There is none today.
8. **Tickets.** They stay single-use, 60 s, and bound to host and purpose.
   Move them out of the in-process Map (to Postgres or Redis) before running
   more than one server node.

### 2. Agent (host)

1. **Several PTYs,** keyed by session id instead of one global `activePTY`.
2. **Session lease renewal** (see 1.5). The agent kills a session only when
   its lease or session TTL expires.
3. **Target user.** The PTY runs as a configured account per host (`pty_user`)
   with privilege dropped, not as the agent's own user (often root). A root
   shell is a separate, higher scope.
4. **Recording.** Every PTY session runs through `adssh`, so its audit chain
   records it. Break-glass already does this; ordinary sessions do not.
5. **For Method B,** the agent reports the host's sshd ed25519 host key and a
   reachable address over its authenticated channel. That gives SystemAPI a
   trusted `host_key` to sign into the policy statement, so B pins the key
   instead of trusting on first use.

### 3. sahconnect (client)

1. **`sahconnect <name>`** (also `sahconnect connect <name>`).
   - Resolve the name (1.1).
   - Fetch and verify the signed policy (1.3) against a pinned control-plane
     public key, using the same trust-on-enroll model as the agent.
   - Choose a method by the rules above.
2. **Method A client.**
   - Get a ticket (1.4), then open
     `wss://<systemapi>/api/v1/systems/terminal/<id>?ticket=…`.
   - Put the local tty in raw mode, send SIGWINCH as `pty_resize`, and
     restore the tty on any exit.
   - Exit with the code from `pty_exit`.
   - TLS 1.3 only. The existing URL guards stay.
3. **Method B client.**
   - Run `adssh` with an ssh command built from the signed `ssh` block:
     `ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<temp file holding only the signed host_key> -p <port> <user>@<addr>`.
   - adssh policy must allow it, and adssh's audit chain records it.
4. **Config file:** `~/.config/sahconnect/config.toml`.
   - `systemapi_url`, `method = ["agent","ssh"]`, the pinned control-plane
     key fingerprint, and the token file path.
   - Environment variables still override.
5. **Auth.**
   - Prefer the OAuth device-login bearer token. SystemAPI already accepts
     `Bearer` (router.js), and `adssh identity device login` already obtains
     it.
   - `X-API-Key` stays for automation.
   - A long-lived scoped key in an env var is not the interactive default.
6. **Policy cache.** Signed statements are cached until `expires_at`. An
   expired or missing statement plus an unreachable SystemAPI means **error**
   (see the downgrade rule).

### 4. Host-side enforcement for B (later phase)

Signed policy keeps an honest client from downgrading. It does not stop a
hostile client that skips the policy and runs `ssh` directly. Where a host is
`agent-only`, close the SSH path on the host itself:

- sshd `AuthorizedKeysCommand` or `adssh --serve` reads the agent's cached
  policy and refuses when `ssh` is not allowed;
- or the firewall drops port 22.

## Phases

| Phase | Delivers | Depends on |
|---|---|---|
| 0 | SystemAPI deployed (miniapps1) and one enrolled test host | deploy plan (parked) |
| 1 | **A works from the CLI**: resolve, ticket, WebSocket PTY client, renewable sessions, several PTYs, exit frame, audit, target user, recording | 0 |
| 2 | **Policy**: column, signed statement, ticket enforcement, client cache, selection rules (B still disabled) | 1 |
| 3 | **B**: agent reports sshd host key and address, sahconnect B path through adssh with pinned host key | 2 |
| 4 | **Host-side enforcement** for `agent-only`; tickets in shared storage for more than one node | 3 |

Every phase updates `sah-suite.md` Wired join in the same change.

## Tests (each phase ships its negative cases)

- **Resolution:** zero, several and cross-tenant matches are refused.
- **Policy:**
  - a tampered, expired or wrong-key signature is refused;
  - an `agent-only` host never reaches B, whether A fails or SystemAPI is
    down;
  - `ssh-only` refuses A;
  - a client preference that the server forbids is refused.
- **Ticket:** single use, 60 s, host and purpose bound (exists), and refused
  when the policy forbids `agent`.
- **Session:** survives past 60 s; two sessions on one host do not take each
  other over; the hard maximum ends it; the exit code is passed through.
- **B:** in `pinned` mode, a host key mismatch fails closed, there is no
  TOFU, and nothing is written to `~/.ssh/known_hosts`. In `known_hosts` mode,
  StrictHostKeyChecking stays on.
- **Recording:** a user cannot turn off recording where an admin locked it
  on, and the effective setting appears in the audit record.

## Decisions (Ryan, 2026-10-14)

1. **Interactive auth: device-login bearer token.** API keys remain for
   automation. This edits the contract: sahconnect gains device login and a
   token file.
2. **Shell user:** a fixed non-root `pty_user` per host, with root as a
   separate, higher scope.
3. **Session recording through adssh: on by default.**
   - Configurable globally (tenant setting) and per user.
   - An admin can lock it on for a tenant or host, so a user cannot turn it
     off there.
   - The effective setting goes into the signed policy statement and the
     session audit record.
4. **Method B host keys: pinned by default, user's choice.**
   - `ssh_host_key = "pinned"` (the default) uses only the signed `host_key`.
   - `"known_hosts"` uses normal OpenSSH checking against the user's
     `~/.ssh/known_hosts`. StrictHostKeyChecking stays on; there is no
     accept-anything mode.
   - The chosen mode is recorded in the session audit.
5. **Defaults, configurable:** session maximum 8 h; signed policy lifetime
   15 min.
