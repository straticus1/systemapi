# Mesh protocol: sahmesh ↔ SystemAPI

Status: contract, phase 0, 2026-10-22. Both sides implement exactly this.
Change it only by editing this file and both implementations in the same
change, and list the call in `sah-suite.md` Wired join when it ships.
Conventions follow `sah-tcp-protocol.md` (the TCP contract). Where this file
is silent, the TCP contract applies to each stream. Owner decisions
(2026-10-22) are in §15.

## 0. Model

A mesh session is one WebSocket from sahmesh to SystemAPI for one host. It
carries many TCP streams. Each stream is a TCP session of the TCP contract:
the same target validation, server policy, signed lease, limits, caps, and
`tcp_start` / `tcp_end` audit rows. The host's agent is unchanged: it sees
one `tcp_open` per stream on its existing socket, which already multiplexes
streams with per-stream credit.

What the mesh changes is the client hop only. One ticket and one socket per
host instead of one per connection, stream ids on the frames, and credit
toward the client so one slow stream never stalls the others.

sahmesh is a SOCKS5 proxy on loopback. An application dials `NAME.sah:PORT`
and sahmesh opens a stream to agent `NAME` with target `local`. An IP literal
destination is matched against sahmesh's route table and sent as that
agent's target (the TCP contract's `--via`). Nothing else is routed (§16).

## 1. Auth, resolve, transport

Identical to TCP §1: credentials in headers only, `GET /api/v1/hosts/resolve`,
TLS 1.3 minimum, system CA pool, no insecure options, no proxy, no redirects.

## 2. Ticket

    POST /api/v1/ws-ticket
    {"host_id":"<id>","purpose":"mesh:open"}

- **Scope.** `mesh:open`. It is an operator scope, like `tcp:open`, and a
  separate one: an API key can hold either without the other.
- **Binding.** None. The ticket is bound to the host and the purpose. Each
  stream names its own target at `mesh_open` (§3). A `target` or `root` in
  the body is ignored.
- **Success.** `200 {"ticket":"stk_...","expires_at":"<iso8601>","expires_in":60,"host_id":"...","purpose":"mesh:open"}`.
  Single-use, valid for 60 s.
- **Errors:** `400 bad_purpose`, `403 scope_denied`, `404 not_found`,
  `429 rate_limited`.
- **Rate limit.** The TCP budget, `SYSTEMAPI_TICKET_RATE_TCP` (default 120
  per minute per actor and host). A mesh session costs one ticket however
  many streams it carries.

## 3. WebSocket

    wss://<systemapi>/api/v1/systems/mesh/<host_id>?ticket=<ticket>&purpose=mesh:open

- **Upgrade rules** are TCP §3: the ticket alone authorizes the upgrade;
  `api_key` in the query is HTTP 401; no `Origin` (a CLI) is accepted; an
  `Origin` outside `SYSTEMAPI_ALLOWED_ORIGINS` is HTTP 403; the ticket is
  consumed on its first upgrade even when the host or purpose does not match.
- **Setup.** After the upgrade the server consumes the ticket, re-checks the
  actor's `mesh:open` scope, needs a signer, a live agent, and the agent's
  `tcp` capability, checks the per-actor session cap, and writes the
  `mesh_start` audit row. Any failure sends a session error (below) and
  closes with 1011. Success sends:

      {"type":"mesh_ready","payload":{"session_id":"msh_...","window":262144}}

  `session_id` matches `^msh_[A-Za-z0-9_-]{16,64}$`. `window` is the
  per-stream credit window in bytes for each direction (§6). A client
  accepts a window from 4 KiB through 1 MiB and ends the session with
  `protocol_error` outside that range, so its memory is bounded by its own
  rule and not by the server.
- **The client sends nothing before `mesh_ready`.** A frame before it is
  `protocol_error`.

### 3.1 Frames

Text frames are JSON of at most 64 KiB. Binary frames are
`[4-byte big-endian stream id][bytes]` with at most 64 KiB of bytes, so a
binary frame is at most 65 540 bytes. A larger frame closes with 1009.

Stream ids are integers from 1 through 2^32-1, chosen by the client. Each
`mesh_open` must carry an id strictly greater than every id the session has
seen. An id is never reused.

**Client → server:**

| Frame | Meaning |
|---|---|
| `{"type":"mesh_open","stream":N,"target":{"host":"local"\|"<ip>","port":<n>}}` | Open stream N to the target. The target rules are TCP §2 and §4. |
| binary for N | Bytes for the target. Only after `connected` for N, never after `mesh_eof` for N, and only inside the client's send credit for N. |
| `{"type":"mesh_eof","stream":N}` | The local side sent FIN. The agent calls `shutdown(SHUT_WR)` on the target. |
| `{"type":"mesh_close","stream":N}` | The client abandoned stream N (its local socket closed or reset). The server ends the stream with audit reason `client_closed` and sends nothing more for N. |
| `{"type":"mesh_credit","stream":N,"bytes":<n>}` | The client handed n bytes of N to the local socket; the server may send that much more (§6). |

**Server → client:**

| Frame | Meaning |
|---|---|
| `{"type":"mesh_status","stream":N,"payload":{"status":"connecting"}}` | The stream passed the server checks; the agent was asked to dial. A stream refused by validation, policy, or a cap gets only its error frame, never `connecting`. |
| `{"type":"mesh_status","stream":N,"payload":{"status":"connected","session_id":"tcs_...","peer":"<addr>"}}` | The dial worked and `tcp_start` is written. Bytes may flow. `session_id` is the stream's TCP session id. |
| `{"type":"mesh_status","stream":N,"payload":{"error":"<code>"}}` | Stream N failed (§7). It is closed; no `mesh_close` follows. Usually before `connected`; a connected stream can also end this way with `internal` (an unexpected peer, agent data outside the stream, a queue over its cap). |
| binary for N | Bytes from the target, inside the server's send credit for N. |
| `{"type":"mesh_eof","stream":N}` | The target sent FIN. The client calls `shutdown(SHUT_WR)` on the local socket. |
| `{"type":"mesh_close","stream":N,"payload":{"session_id":"tcs_...","reason":"<reason>","bytes_in":<n>,"bytes_out":<n>}}` | Stream N ended (§7). Counts are from the client's view. |
| `{"type":"mesh_credit","stream":N,"bytes":<n>}` | The server forwarded n bytes of N to the agent; the client may send that much more. |
| `{"type":"mesh_status","payload":{"error":"<code>"}}` (no `stream`) | The session failed (§7). The server then closes with 1011. |
| `{"type":"mesh_end","payload":{"session_id":"msh_...","reason":"<reason>","streams":<n>}}` | The session ended in order (§7). Every live stream got `mesh_close` first. The server then closes with 1000. `streams` is the number of `mesh_open` frames the server accepted, including streams that then failed policy or the dial; an id refused with `protocol_error` is not counted. |

### 3.2 Rules

Each of these ends the session with `protocol_error` (every live stream is
closed with reason `protocol_error`, then the session error, then 1011):

- any frame before `mesh_ready`;
- a text frame that is not a JSON object;
- `mesh_open` whose `stream` is not an integer in range, or not greater than
  every id seen in the session;
- a frame of any kind (binary, `mesh_eof`, `mesh_close`, `mesh_credit`) for an
  id the session never accepted a `mesh_open` for, including a skipped id;
- a binary frame for a live stream before `connected` or after `mesh_eof`;
- a binary frame that exceeds the client's send credit for its stream;
- `mesh_credit` that is not a positive integer, or that returns more credit
  than the server could owe for that stream.

These are tolerated, because the client may have sent them before it saw
the stream end: a binary frame, `mesh_eof`, `mesh_close`, or `mesh_credit`
for an id that was accepted and has since closed is ignored. A text frame
over 64 KiB closes with 1009 like a binary one over 65 540 bytes. An unknown
`type` is ignored and logged.

A `mesh_open` whose `target` fails validation does not end the session: the
stream fails with `bad_target` or `target_forbidden` (§7).

## 4. Target policy

TCP §4, applied to every `mesh_open`: the always-refused classes, no DNS
names, loopback only as `"local"`, the host's `tcp_policy` else the tenant
default, deny by default, and the agent's own allowlist. The server check
runs at `mesh_open` and again at every lease renewal.

## 5. Lease, lifetime, limits

- **Per stream.** Identical to TCP §5: a `tcp` lease over
  `"<tcs id>\n<deadline_unix>\n<start|renew>\n<target.host>\n<port>"`,
  TTL 60 s, renewed every 30 s, each renewal after re-checking membership,
  key state, the server policy, and the **`mesh:open`** scope. A denial ends
  the stream with `stopped`. `SYSTEMAPI_TCP_MAX_SECONDS`,
  `SYSTEMAPI_TCP_IDLE_SECONDS`, and `SYSTEMAPI_TCP_MAX_BYTES` apply to each
  stream.
- **Per stream open.** The server re-checks the actor's membership, key
  state, and `mesh:open` scope at every `mesh_open`, as a `tcp:open`
  upgrade does, not only at the 30 s session re-check. Opens still waiting
  on their checks count toward the per-actor cap.
- **Per session.** `SYSTEMAPI_MESH_MAX_SECONDS` (default 28800) ends the
  session with `max_duration`. `SYSTEMAPI_MESH_IDLE_SECONDS` (default 3600)
  ends a session that has had no live stream for that long with
  `idle_timeout`. Every 30 s the server re-checks the session's grant
  (membership, key state, `mesh:open`); a denial closes every stream with
  `stopped` and ends the session with `stopped`. A session end sends
  `mesh_end` and 1000. The client reconnects with a new ticket on its next
  stream.
- **Caps.** Mesh streams and `tcp:open` sessions share the TCP caps:
  `SYSTEMAPI_TCP_MAX_PER_ACTOR` (default 32) per actor and 64 per agent,
  counted together. Over a cap, the stream fails `cap_reached`. Mesh
  sessions per actor: `SYSTEMAPI_MESH_MAX_PER_ACTOR`, default 16; over it the
  upgrade fails `cap_reached`.
- **Frames.** At most 64 KiB of payload on every hop.

## 6. Backpressure (every hop; nothing is ever dropped)

- **Client ↔ server.** Per-stream credit in both directions, the same
  ledger as the server ↔ agent hop (`controlplane/credit.js`). Each
  direction of each stream starts with `window` bytes (256 KiB). A sender
  stops at zero credit. The receiver returns credit as it forwards bytes
  onward: the server when bytes are handed to the agent socket (which may
  be at once, so a client can only overrun once the agent's window is also
  full), the client when bytes are written to the local socket. Credit is returned in batches of at
  least a quarter window. A peer that sends past its window, or returns more
  than it could owe, has broken the protocol (§3.2).
  - The server also sends to the client only while the socket's
    `bufferedAmount` is under 1 MiB, and returns agent credit for a stream
    only under that line.
  - sahmesh always reads its WebSocket. It never needs to pause the socket,
    because every stream's inbound bytes are bounded by the credit it gave.
  - sahmesh stops reading a local socket while that stream's send credit is
    zero. One stalled application stalls only its own stream.
- **Server ↔ agent** and **agent ↔ target** are TCP §6, unchanged.

## 7. Errors, close reasons, close codes

- **Stream errors** (`mesh_status` with `stream`): the TCP §7 codes
  (`scope_denied`, `agent_offline`, `agent_unsupported`, `lease_required`,
  `cap_reached`, `target_denied`, `target_denied_agent`, `target_forbidden`,
  `connect_refused`, `connect_timeout`, `host_unreachable`, `internal`) plus
  `bad_target` for a target that fails validation at `mesh_open`.
- **Session errors** (`mesh_status` without `stream`, then 1011):
  `ticket_invalid`, `scope_denied`, `agent_offline`, `agent_unsupported`,
  `lease_required`, `cap_reached`, `protocol_error`, `internal`.
- **Stream close reasons** (`mesh_close`): the TCP §7 reasons (`closed`,
  `reset`, `idle_timeout`, `byte_cap`, `max_duration`, `agent_disconnected`,
  `stopped`) plus `protocol_error` when the session is ending for that
  reason. A stream the client abandoned with `mesh_close` or by closing the
  socket is audited `client_closed` and gets no frame.
- **Session end reasons** (`mesh_end`, then 1000): `idle_timeout`,
  `max_duration`, `stopped`, `agent_disconnected`. The `mesh_end` audit row
  may also read `client_closed`, `frame_too_large`, or `protocol_error`,
  which send no `mesh_end` frame.
- **Pending streams at session end.** A stream still waiting on its checks
  when the session ends gets `mesh_status` with an error before `mesh_end`.
- **Close codes:** 1000 after `mesh_end`; 1011 after a session error; 1009
  for an oversized frame.

## 8. Half-close

TCP §8 per stream, with `mesh_eof` in place of `tcp_eof`. After FIN both
ways the stream gets `mesh_close` with reason `closed`. After `mesh_close`
or a stream error the id is finished; the client may open the next id.

## 9. Audit

Rows in the server's audit chain, every column hashed:

- **`ticket_issued`:** actor, host, purpose `mesh:open`, no target.
- **`mesh_start`:** `session_id`. Written before `mesh_ready`; a failed
  write fails the session with `internal`.
- **`tcp_start`** and **`tcp_end`** per stream, exactly as TCP §9, with two
  more payload fields: `mesh` (the `msh_` session id) and `stream` (the
  client's stream id).
- **`mesh_end`:** `session_id`, reason, `streams` (opened), `duration_s`.
  Retried the way `tcp_end` is.
- Content is not recorded (TCP §9, owner-accepted).

## 10. Reverse forwards: still out of scope

No frame here opens a listener on a host. `mesh_open` from the host side
does not exist.

## 11. Agent ↔ server frames

Unchanged from TCP §11. The agent does not know which client socket a
`tcp_open` came from and does not need to.

## 12. Threats

**Defended:**
- Everything TCP §12 defends, per stream: SSRF pivots (policy at every
  `mesh_open` and renewal, refused classes, no DNS names), ticket replay,
  streams outliving their lease or grant, memory growth (credit windows in
  both directions on every hop, bufferedAmount gate, caps), browser pages
  (Origin), API keys in URLs.
- One stream starving the others on the client socket: per-stream credit
  both ways; the server never pauses the whole socket for one stream.
- A client that lost `mesh:open` keeping a mesh up: the session re-check
  every 30 s, and every stream's renewal checks the mesh scope.
- A mesh ticket used to open single TCP channels, or the reverse: purposes
  do not cross; the scopes are distinct.
- A stream id replayed to confuse accounting: ids are strictly increasing
  and never reused.

**Not defended:**
- What flows through an allowed stream. Not inspected or recorded.
- An allowed target that is itself a proxy.
- A hostile local process using sahmesh's SOCKS listener. It binds
  loopback only and has no authentication (§16); the account that can reach
  loopback can already run sahmesh.
- Reverse forwards.

## 13. Conformance

**Client MUST:**
- send credentials in headers only, and use TLS 1.3;
- get one ticket per session and send nothing before `mesh_ready`;
- use strictly increasing stream ids and never reuse one;
- send bytes for a stream only after `connected`, never after its
  `mesh_eof`, and only inside its send credit;
- return credit as bytes reach the local socket;
- send `mesh_eof` on local EOF and honour `mesh_eof` with `SHUT_WR`;
- send `mesh_close` when it abandons a stream;
- keep binary payloads at 64 KiB or less;
- bind local listeners to loopback only;
- never log a ticket or a WebSocket URL.

**Server MUST:**
- check scope at ticket issue, at the upgrade, and every 30 s;
- check the target policy and refused classes at every `mesh_open` and
  renewal;
- consume the ticket on first use and apply the Origin rule;
- write `mesh_start` before `mesh_ready` and `tcp_start` before
  `connected`;
- sign and renew a lease per stream;
- enforce every per-stream limit, the session limits, and the shared caps;
- apply credit in both directions and never drop bytes;
- write `tcp_end` per stream and `mesh_end` per session;
- never log ticket values.

**Agent:** unchanged.

## 14. Tests (negative cases ship with phase 0)

- A reused ticket fails; a host-A ticket cannot open host B; a `tcp:open`
  ticket cannot open a mesh and the reverse.
- An actor with `tcp:open` but not `mesh:open` gets `scope_denied` at
  ticket issue and at the upgrade; the reverse opens a mesh but no TCP.
- Two streams on one socket carry bytes both ways without mixing.
- A stream denied by policy fails alone; the other stream keeps flowing.
- A stream id equal to or below the last one is `protocol_error`.
- A binary frame for a never-opened id is `protocol_error`; one for a
  closed id is ignored.
- Bytes before `connected` are `protocol_error`.
- Bytes past the client's credit window end the session.
- Credit returned past the window ends the session.
- A stream's `tcp_start` and `tcp_end` rows carry `mesh` and `stream`.
- Losing `mesh:open` ends every stream and the session within a renewal.
- Mesh streams and TCP sessions share the per-actor and per-agent caps.
- An oversized frame closes with 1009.
- The session idle timeout fires with no live stream and not with one.
- After one FIN, data still flows the other way.

## 15. Owner decisions (2026-10-22)

- **Scope.** `mesh:open` is its own operator scope, not `tcp:open`.
- **Surface.** sahmesh is a loopback SOCKS5 proxy; `NAME.sah` names an
  agent; routes map CIDRs to a `--via` agent.
- **Agent.** No agent change in phase 0.
- **Reverse.** Out of scope, as in TCP §10.

## 16. sahmesh name and route rules

These are client rules. The server never sees a name.

- A SOCKS5 CONNECT to domain `NAME.sah` opens a stream to agent `NAME` with
  target `{"host":"local","port":PORT}`. `NAME` must match the suite host
  name rule (`sahconnect` `ValidHostName`). Any other domain, including
  `localhost`, a bare `NAME`, or a public DNS name, is refused with SOCKS
  reply `0x02` (not allowed by ruleset). sahmesh resolves no DNS.
- A SOCKS5 CONNECT to an IPv4 or IPv6 literal is matched against the route
  table, longest prefix first. A match opens a stream to the route's agent
  with that literal as the target, which the server validates as TCP §4.
  No match is reply `0x02`.
- Routes come from `--route CIDR=AGENT` flags and from
  `~/.config/sahmesh/routes.toml` (`[[route]] cidr = "10.0.0.0/24" via =
  "gw1"`), which is read with the same owner, mode, and symlink checks as
  the sahconnect config. A flag and the file may both be given; a duplicate
  CIDR is a startup error.
- SOCKS5 methods: no authentication only. Commands: CONNECT only; BIND and
  UDP ASSOCIATE are reply `0x07`. The listener is `127.0.0.1` or `::1`
  only; any other bind address is refused.
- Contract errors map to SOCKS replies: `target_denied`,
  `target_denied_agent`, `target_forbidden`, `bad_target`, `scope_denied`
  → `0x02`; `host_unreachable` → `0x04`; `connect_refused` → `0x05`;
  `connect_timeout` → `0x06`; everything else → `0x01`.
