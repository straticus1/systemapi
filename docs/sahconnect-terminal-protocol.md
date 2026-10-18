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
  than one host the caller can see and the rule below does not pick one. The
  client must then use the `host_id`, or an admin retires the stale row.
- Retired hosts (`POST /api/v1/hosts/:host_id/retire`) never match, by
  hostname or by `host_id`.
- When the hostname matches several rows and exactly one of them has a
  connected agent, that row is returned if every other match is offline and
  was last seen more than `SYSTEMAPI_RESOLVE_STALE_HOURS` ago (default 24;
  0 to 8760; another value means the default). A row never seen counts as
  stale. This is the agent re-enrolled under the same hostname with a new
  state file: the old row stops answering and the name keeps working.
- `400 {"error": "invalid_name"}` when the name is empty, longer than 253
  characters, or contains characters outside `[A-Za-z0-9._-]`.

## 2. Get a ticket

```
POST /api/v1/ws-ticket   {"host_id": "...", "purpose": "terminal:open" | "terminal:root"}
```

- `terminal:open` needs scope `terminal:open` (operator). The shell runs as
  the caller's own account from the host's `--pty-user-map` (§6), or, on a
  host without a map, as the host's single non-root `pty_user`.
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

The upgrade needs no credential header; the ticket authorizes it. A request
with no `Origin` header (the CLI) is accepted. A request with an `Origin`
header (a browser) is refused with HTTP 403 unless that origin is on the
server's allowlist (`SYSTEMAPI_ALLOWED_ORIGINS`).

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
| `{"type":"pty_status","payload":{"error":"<code>"}}` | Failure. Codes: `ticket_invalid`, `scope_denied`, `agent_offline`, `lease_required`, `pty_user_unset`, `account_unmapped`, `recording_unavailable`, `root_unavailable`, `pty_start_failed`, `internal`. `root_unavailable` means the host cannot run a `terminal:root` shell: the agent is not root, or it would not record the session itself. The socket is then closed with code 1011. |
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
  not `agent` is refused with `root_unavailable`. The agent and the server
  both enforce this.
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
- The monitoring notice (§7.1) and the watch prompts and lines (§7) are
  recorded as output. Each watch request, answer and stop is also recorded
  as a `w` line holding the agent's JSON note of it. The keystrokes that
  answer a consent prompt are not recorded and never reach the shell.

## 6. One Unix account per identity

- **Server → agent.** `pty_start` carries `"actor": "<user id>"`, the
  identity that asked for the ticket. `file_open` and `xfer_grant` already
  carry `actor`. The actor rides the authenticated agent socket; it is not
  in the signed lease.
- **Agent.** `--pty-user-map <file>` maps each identity to its own Unix
  account (`identity = unixuser` lines; the file is `0600` or stricter and
  owned by root or the agent user). Terminal, file and xfer sessions resolve
  the account through one function (`resolvePTYIdentity`), so the same
  identity gets the same account on every channel.
  - With a map, an identity that has no entry is refused with
    `account_unmapped` (`pty_status`, `file_status`, or the xfer refusal),
    and `--pty-user` is never used as a fallback.
  - A map that uses `*`, repeats an identity, names `root`, or gives two
    identities one account stops the agent at startup.
  - Without a map, `--pty-user` keeps serving every identity, and the agent
    logs one warning line at startup that all identities share one account.
  - On a non-root agent (`--pty-allow-agent-user`) only the identity mapped
    to the agent's own account can open a session.
  - An xfer state record stores its actor; the sweep after a restart
    resolves that actor and runs only if it still gives the recorded uid,
    gid and groups.
- `terminal:root`, `file:root` and `xfer:root` still run as root and do not
  consult the map.

## 7. Monitoring notice and session watching

### 7.1 Notice

Every terminal session (`terminal:open`, `terminal:root`, break-glass)
starts with a notice that the agent sends as session output after
`started` and before any shell output; no client input reaches the shell
before it is sent. The default text is:

```
[systemapi] This session is recorded and may be viewed by an administrator.
[systemapi] Tenant: <tenant>
```

`--pty-notice <file>` replaces the first line's text (control characters are
stripped); the tenant line is always added. An empty notice file stops the
agent at startup. Nothing a client or a watched user sends can turn the
notice off. There is no option to silence the notice or the watch lines for
an investigation: the forced notice is the only behavior.

### 7.2 Watching

Status: the agent implements this section. The server does not have a watch
feature yet: no route asks to watch, no relay sends a session's output to a
watcher, and nothing writes the audit rows below. The server side must be
built to this contract.

**Rules.**

- View-only watching (`mode` `ro`) by support or an admin needs the watched
  user's consent, unless the actor has the `admin` scope and the request
  carries a non-empty `reason`. Only then may the server set `override`.
- Read-write watching (`mode` `rw`) always needs consent. The agent asks
  even when `override` is set.
- The watched user is told on the terminal when watching starts (by consent
  or by override) and when it stops.

**Server → agent frames.**

| Frame | Meaning |
|---|---|
| `{"type":"watch_request","session_id":"pts_…","watch_id":"wch_…","mode":"ro"\|"rw","actor":"<user id>","reason":"<text>","override":bool,"lease":{…}}` | Ask to watch. `watch_id` matches `^wch_[A-Za-z0-9_-]{16,64}$`. `reason` is at most 256 printable characters, no tabs or newlines. The lease is for the session's own action (`pty`, `pty_root` or `breakglass`) over the payload `"<session_id>\n<deadline_unix>\nwatch\n<watch_id>\n<ro\|rw>\n<true\|false>\n<reason>"`, so only the lease signer can claim an override, and a start or renew lease cannot be used. |
| `{"type":"watch_stop","session_id":"pts_…","watch_id":"wch_…"}` | The watcher left, or the server withdraws an unanswered request. |
| `{"type":"pty_input","session_id":"pts_…","watch_id":"wch_…","data_b64":"…"}` | Input typed by a watcher. The agent accepts it only while that watch has read-write consent, and drops it otherwise. |

**Agent → server frame.** One `watch_consent` per `watch_request`, and one
when a granted watch stops:

```
{"type":"watch_consent","session_id":"pts_…","payload":{
  "watch_id":"wch_…","granted":bool,"consent":bool,
  "result":"granted"|"denied"|"timeout"|"override"|"cancelled"|"session_ended"|"stopped",
  "mode":"ro"|"rw","actor":"…","reason":"…"}}
```

or, when the request is refused before anyone is asked,
`{"watch_id":"…","granted":false,"consent":false,"error":"<code>"}` with
`unknown_session`, `bad_request`, `lease_required`, `reason_required`
(override with no reason), `busy` (another prompt is open) or
`session_ended`.

- `consent` is true only when the user answered yes. An override grant is
  `granted: true, consent: false, result: "override"`.

**Consent prompt.** The agent writes one line to the user's terminal:

```
[systemapi] <actor> asks to watch this session, view only. Reason: <reason>. Allow? [y/N] (30 s)
```

(`with control (they can type into it)` for `rw`). Until it is answered,
every input byte from the client goes to the prompt: none of it reaches the
shell or the recording, and none of it is echoed. A keystroke that is
exactly `y` or `Y` (optionally with Enter) allows; `n`, `N`, Ctrl-C or
Ctrl-D anywhere refuses; anything else is dropped. No answer in 30 s is a
refusal (`timeout`). The session ending answers `session_ended`. One prompt
is open at a time per session.

**Lines the watched user always sees.**

- start by consent: `You allowed <actor> to watch this session, view only.`
- start by override: `An administrator (<actor>) started watching this session, view only. Reason: <reason>`
- refusal: `Watching refused.` / `No answer in 30 s; watching refused.`
- stop: `<actor> stopped watching this session.`

**Audit rows the server must write** (in the audit chain, actor = the
watcher):

- `watch_started`: `{session_id, host_id, watch_id, mode, actor, reason,
  consent: true|false}`, written when the agent answers `granted: true`,
  before the server relays a single byte to the watcher. `consent` is false
  for an admin override.
- `watch_refused`: `{session_id, watch_id, mode, actor, reason, result}` for
  `denied`, `timeout`, `cancelled`, `session_ended` or an `error`.
- `watch_stopped`: `{session_id, watch_id, actor, duration}`.
