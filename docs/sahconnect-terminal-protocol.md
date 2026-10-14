# Terminal protocol: sahconnect ↔ SystemAPI (phase 1)

Status: contract for phase 1 of `docs/sahconnect-connect-design.md`. Both
sides implement exactly this. Change it only by editing this file and both
implementations in the same change.

The browser terminal (`frontend/src/views/TerminalView.jsx`) uses the same
endpoint and keeps working: legacy `data` input and the existing
`pty_status` payload shape stay accepted.

## Auth

Every HTTP call accepts what `authenticate()` accepts today:

- `Authorization: Bearer <OAuth device-login token>`, from `controlplane/oauth.js`;
- `X-API-Key: <key>`.

Never pass a credential in a query string. The single-use ticket below is the
only query-string secret, and it is not a credential: it is single-use, lasts
60 s, and is bound to one host and one purpose.

## 1. Resolve a host name

```
GET /api/v1/hosts/resolve?name=<name>
```

- Matches an exact, case-insensitive `hostname`, or an exact `host_id`, within
  the caller's tenants only. No substring matching.
- `200 {"host_id": "...", "hostname": "...", "tenant": "...", "status": "online|offline"}`
- `404 {"error": "not_found"}`
- `409 {"error": "ambiguous", "matches": <n>}` when the hostname matches more
  than one host the caller can see. The client must then use the `host_id`.
- `400 {"error": "invalid_name"}` when the name is empty, longer than 253
  characters, or contains characters outside `[A-Za-z0-9._-]`.

## 2. Get a ticket

```
POST /api/v1/ws-ticket   {"host_id": "...", "purpose": "terminal:open" | "terminal:root"}
```

- `terminal:open` needs scope `terminal:open` (operator). The shell runs as
  the host's non-root `pty_user`.
- `terminal:root` needs scope `terminal:root`, a new scope granted to admin
  only. The shell runs as root.
- Response: `{"ticket": "stk_...", "expires_at": "<iso8601>"}`. The ticket is
  single-use, valid 60 s, and bound to host and purpose.
- `429 {"error": "rate_limited"}` when the caller has asked for too many
  tickets for this host in the last minute. The budget is per caller and
  host: `SYSTEMAPI_TICKET_RATE_PER_HOST` (default 20) for `terminal:open`, and
  a separate `SYSTEMAPI_TICKET_RATE_PRIVILEGED` (default 20) for
  `terminal:root` and break-glass.

## 3. Open the terminal

```
wss://<systemapi>/api/v1/systems/terminal/<host_id>?ticket=<ticket>&purpose=<purpose>&rows=<r>&cols=<c>
```

`rows` and `cols` are optional initial sizes, each 1–1000. The defaults are
24 and 80.

### Client → server: text frames, JSON

| Frame | Meaning |
|---|---|
| `{"type":"pty_input","data_b64":"<base64>"}` | Raw input bytes. `data_b64` is preferred because it is binary-safe. Legacy `{"type":"pty_input","data":"<utf8>"}` is still accepted. |
| `{"type":"pty_resize","rows":R,"cols":C}` | Window size. R and C are each 1–1000. |
| `{"type":"pty_eof"}` | Stdin closed. The server closes the PTY's input; the shell sees EOF. |

- An unknown `type` is ignored and logged.
- A frame larger than 64 KiB closes the socket with code 1009.

### Server → client

- **Binary frames:** raw PTY output bytes.
- **Text frames, JSON:**

| Frame | Meaning |
|---|---|
| `{"type":"pty_status","payload":{"status":"starting"}}` | The ticket was accepted and the agent was asked to start. |
| `{"type":"pty_status","payload":{"status":"started","session_id":"..."}}` | The shell is running. |
| `{"type":"pty_status","payload":{"error":"<code>"}}` | Failure. Codes: `ticket_invalid`, `scope_denied`, `agent_offline`, `lease_required`, `pty_user_unset`, `recording_unavailable`, `pty_start_failed`, `internal`. The socket is then closed with code 1011. |
| `{"type":"pty_exit","payload":{"session_id":"...","code":N,"reason":"exited"\|"max_duration"\|"agent_disconnected"\|"stopped"}}` | The session ended. `code` is the shell's exit status, or -1 when there is none. The server then closes with code 1000. |

## 4. Session lifetime

A session ends when the first of these happens:

- the shell exits;
- the client closes the socket (the agent then stops the PTY);
- the agent disconnects;
- the maximum duration passes: `SYSTEMAPI_PTY_MAX_SECONDS`, default 28800
  (8 h). The server enforces this, and so does the agent, using the session
  deadline it was given.

While the session is live, the server renews the agent's lease about every
30 s. If renewal stops, the agent ends the session when the last lease
expires. A dead server therefore cannot leave a shell running for long.

## 5. Recording and audit

- **Recording is on by default, and the agent does it.** The agent copies
  every input and output byte of the session into its own append-only file,
  one per session. Each line carries an HMAC-SHA256 chained to the line
  before it, keyed by a key that only the agent holds (a 0600 file made with a
  CSPRNG). On a root agent the recordings live in a root-owned 0700 directory
  (`--pty-record-dir`, default `/var/lib/systemapi/recordings`).
- The recording mode is one of `agent` (a root agent records a shell that runs
  as another user, or as root), `user_owned` (the agent runs as an ordinary
  user with `--pty-allow-agent-user`, so the shell's user can edit the
  record), or `off` (`--pty-record=false`).
- `adssh` is not needed for an ordinary session. Break-glass still runs
  `adssh` and is also recorded by the agent.
- If the record cannot be opened or written, or the recorder cannot keep up,
  the session is refused or ended. It never runs unrecorded and never drops
  bytes. A refusal at start is `recording_unavailable`, including when the
  recording filesystem has less than the configured free space (default
  1 GiB). A session that reaches its recording size cap (default 1 GiB) ends
  with `pty_exit` reason `stopped`; the audit row says `recording_size_limit`.
- Until phase 2 policy exists, a `terminal:root` session whose recording is
  not `agent` is refused with `recording_unavailable`. The agent and the
  server both enforce this.
- Nothing the client sends reaches the shell until `started` has been sent,
  which is after the start audit row is written.
- Phase 2 makes recording configurable per tenant and per user, with an admin
  lock.
- **The server writes audit-chain records for:**
  - ticket issued: who, host and purpose;
  - session started: session id, host, purpose, pty user, recording mode, and
    any privileged groups of the pty user;
  - session ended: session id, reason, exit code, duration, and the agent's
    final recording digest, record path and byte counts.
- An operator checks a recording against its audit row with
  `systemapi-agent verify-recording <file> --digest <hex>` on the host.
- Audit rows hash every column (actor, host, tenant, action, payload), so
  rewriting who did something breaks verification.
- Client frames are unchanged by recording.
