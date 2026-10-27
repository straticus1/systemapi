# TCP-forward protocol: sahlink ↔ SystemAPI

Status: contract, phase 0, not yet implemented. Both sides implement exactly
this. Change it only by editing this file and both implementations in the same
change. List the call in `sah-suite.md` Wired join when it ships. Conventions
follow `sahconnect-terminal-protocol.md` (the PTY contract). **(rec)** marks a
recommendation that is not yet in the code. Owner decisions (2026-10-14) are
folded in: see §15.

## 0. Model

sahlink accepts a local TCP connection. For each connection it gets a ticket and
opens one WebSocket. SystemAPI asks the host's agent to dial the target and
relays the bytes. The host needs no inbound port. One WebSocket carries exactly
one TCP connection, with no multiplexing on the client socket. The
multiplexed form, one socket per host carrying many streams, is
`sah-mesh-protocol.md`; each of its streams is a session of this contract.

## 1. Auth, resolve, transport

- HTTP auth is the same as PTY §Auth: `Authorization: Bearer <device-login
  token>` or `X-API-Key`.
- Never put a credential in a query string. The ticket is the only
  query-string secret.
- Resolve the host with `GET /api/v1/hosts/resolve?name=`, exactly as PTY §1.
- TLS 1.3 minimum, system CA pool, no insecure-skip options.

## 2. Ticket

    POST /api/v1/ws-ticket
    {"host_id":"<id>","purpose":"tcp:open","target":{"host":"<host>","port":<n>}}

- **Scope.** Needs `tcp:open`, held by operators **(rec)**.
- **`target.port`.** An integer from 1 to 65535.
- **`target.host`, in phase 0, is exactly one of:**
  - `"local"`: the agent dials `127.0.0.1`. This is the only way to reach
    loopback.
  - An IPv4 dotted-quad, or an IPv6 literal with no brackets and no zone id.
    IPv4-mapped IPv6 is normalized to IPv4 before any check. Loopback literals
    (`127.0.0.0/8`, `::1`) are refused with `bad_target`, because `"local"` is
    the only spelling for loopback.
  - **DNS names are refused in phase 0 with `bad_target`.** This removes the
    DNS-rebinding surface. Names come in a later contract revision.
- **`--via`.** `sahlink --via gw1 10.0.0.7:3389` sends `host_id`=gw1 and
  `target={"host":"10.0.0.7","port":3389}`. The target is reached from inside
  gw1's network. Without `--via`, sahlink sends `"local"`.
- **Binding.** The ticket is bound to host, purpose **and target**. The
  WebSocket URL does not repeat the target, so a client cannot swap it.
- **Success.** `200 {"ticket":"stk_...","expires_at":"<iso8601>","expires_in":60,"host_id":"...","purpose":"tcp:open"}`.
  The ticket is single-use and valid for 60 s.
- **Errors:**
  - `400 {"error":"bad_purpose"}`;
  - `400 {"error":"bad_target"}`;
  - `403 {"error":"scope_denied"}`;
  - `403 {"error":"target_denied"}` (server policy, §4);
  - `403 {"error":"target_forbidden"}` (an always-refused class, §4);
  - `404 {"error":"not_found"}`;
  - `429 {"error":"rate_limited"}`.
- **Rate limit.** Per actor and host, with its own budget:
  `SYSTEMAPI_TICKET_RATE_TCP`, default 120 per minute. One RDP or HTTP session
  opens several connections. This budget is separate from the terminal and
  privileged budgets.

## 3. WebSocket

    wss://<systemapi>/api/v1/systems/tcp/<host_id>?ticket=<ticket>&purpose=tcp:open

- **Upgrade rules** are the same as PTY §3:
  - the ticket alone authorizes the upgrade;
  - `api_key` in the query gets HTTP 401;
  - no `Origin` header (a CLI) is accepted;
  - an `Origin` not in `SYSTEMAPI_ALLOWED_ORIGINS` gets HTTP 403;
  - the ticket is consumed on its first upgrade, even when the host or purpose
    does not match.

### Client → server

- **Binary frame.** Raw bytes for the target, at most 64 KiB. Larger closes
  with 1009.
- **`{"type":"tcp_eof"}`.** The local side sent FIN, so the agent calls
  `shutdown(SHUT_WR)` on the target.
- **Rules.** Each of these ends the session with `protocol_error`:
  - a binary frame before `connected`;
  - a binary frame after `tcp_eof`;
  - a text frame that is not JSON.

  An unknown `type` is ignored and logged.

### Server → client

- **Binary frame.** Raw bytes from the target, at most 64 KiB.
- **Text frames:**

| Frame | Meaning |
|---|---|
| `{"type":"tcp_status","payload":{"status":"connecting"}}` | Ticket accepted; the agent was asked to dial. |
| `{"type":"tcp_status","payload":{"status":"connected","session_id":"tcs_...","peer":"10.0.0.7:3389"}}` | The dial worked and the start audit row is written. Bytes may flow. `peer` is the address actually dialed; IPv6 is written `[addr]:port`. |
| `{"type":"tcp_status","payload":{"error":"<code>"}}` | Failure (§7). The server then closes with 1011. |
| `{"type":"tcp_eof"}` | The target sent FIN. The client calls `shutdown(SHUT_WR)` on its local socket. |
| `{"type":"tcp_close","payload":{"session_id":"tcs_...","reason":"<reason>","bytes_in":N,"bytes_out":N}}` | The session ended (§7). The server then closes with 1000. Counts are from the client's view: `bytes_out` is client→target, `bytes_in` is target→client. |

## 4. Target policy

All of these must pass.

1. **Always-refused classes.** Checked on every address:
   - unspecified: `0.0.0.0/8`, `::`;
   - link-local: `169.254.0.0/16`, `fe80::/10`;
   - multicast: `224.0.0.0/4`, `ff00::/8`;
   - `255.255.255.255`;
   - `240.0.0.0/4`;
   - cloud metadata and host agents: `100.100.100.200`, `fd00:ec2::254`, and
     the Azure WireServer `168.63.129.16`;
   - the IPv6 ranges that embed an IPv4 address, refused whole so no refused
     IPv4 class is reachable through them: IPv4-compatible `::/96` (which
     also covers `::` and `::1`), NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`,
     and 6to4 `2002::/16`;
   - loopback reached any way other than `"local"`.

   The server (`controlplane/channels.js`) and the agent
   (`systemapi-agent/tcp_policy.go`) keep identical lists, and their tests
   share the same vectors.

   A match gives `target_forbidden`. No policy can override this.
2. **Server policy.** Per host, falling back to a tenant default
   **(rec: a `tcp_policy` column)**:
   `{"allow":[{"local":true,"ports":[5432]},{"cidr":"10.0.0.0/24","ports":[3389,"8000-8099"]}]}`.
   - The default is `{"allow":[]}`, which denies everything.
   - It is checked at ticket issue and again at the upgrade.
   - A failure gives `target_denied`.
3. **Agent allowlist.** A LOCAL agent flag, kept independent of the server on
   purpose:
   `--tcp-allow local:5432,10.0.0.0/24:3389,10.0.0.0/24:8000-8099`.
   - The default is empty, which refuses everything.
   - The agent checks the exact address it will dial.
   - A failure gives `target_denied_agent`.

## 5. Lease, lifetime, limits

- **Lease.** A new action `tcp`. The signed payload is
  `"<session_id>\n<deadline_unix>\n<start|renew>\n<target.host>\n<port>"`, and
  the agent dials only what was signed.
  - The session id matches `^tcs_[A-Za-z0-9_-]{16,64}$`.
  - The lease TTL is 60 s, and the server renews it every 30 s.
  - Every renewal re-checks the grant first, as the upgrade does: the actor's
    membership and scopes, an API key still active (not revoked, locked or
    expired), and the target policy. A denial ends the stream with `stopped`
    and no new lease is signed. A failed lookup only skips that renewal, so
    the stream ends at the agent when the last lease lapses.
  - The agent ends the stream when the lease lapses or at the deadline.
- **Limits.** Each one is enforced by both the server and the agent. Settings:
  - `SYSTEMAPI_TCP_MAX_SECONDS`: default 28800 (8 h).
  - `SYSTEMAPI_TCP_IDLE_SECONDS`: default 900. Idle means no byte in either
    direction.
  - `SYSTEMAPI_TCP_MAX_BYTES`: default 10 GiB, counting `bytes_in` plus
    `bytes_out`.
  - The agent's dial timeout is 10 s. The server's start timeout is 30 s.
- **Caps.** Over a cap gives `cap_reached`.
  - Live TCP sessions per actor: `SYSTEMAPI_TCP_MAX_PER_ACTOR`, default 32,
    at most 63. It is always below the per-agent cap, so one actor can never
    take every stream of an agent; a value of 64 or more is refused and the
    default applies.
  - Streams per agent: 64. These are separate from PTY slots, so TCP can never
    starve the reserved break-glass and root slots.
- **Frames.** At most 64 KiB on every hop.

## 6. Backpressure (every hop; nothing is ever dropped)

- **Client ↔ server.**
  - The server stops reading the client socket while the agent has granted no
    send credit.
  - It sends to the client only while `bufferedAmount` is under 1 MiB, and
    stops granting the agent credit above that.
  - A client that stops reading stalls only its own stream. The idle timeout or
    the byte cap then ends it.
- **Server ↔ agent.** One shared socket with per-stream credit.
  - Each direction starts with a 256 KiB window. The receiver returns credit as
    it drains.
  - An agent that exceeds its window is disconnected.
  - The agent sends round-robin, at most 64 KiB per stream per turn, so bulk
    traffic cannot starve a PTY.
- **Agent ↔ target.** The agent stops reading the target while its credit is
  zero. Writes to the target block only that stream's own writer.

## 7. Errors, close reasons, close codes

- **`tcp_status` error codes:**

| Code | Meaning |
|---|---|
| `ticket_invalid` | The ticket is missing, used, expired, or for another host, purpose or target. |
| `scope_denied` | The caller lacks `tcp:open`. |
| `agent_offline` | No live agent connection for the host. |
| `agent_unsupported` | The agent does not advertise the `tcp` capability. |
| `lease_required` | No signer on the server. |
| `cap_reached` | A per-actor or per-agent cap is full. |
| `target_denied` | Refused by the server policy. |
| `target_denied_agent` | Refused by the agent allowlist. |
| `target_forbidden` | An always-refused class (§4). |
| `connect_refused` | The target refused the connection. |
| `connect_timeout` | The dial took longer than 10 s. |
| `host_unreachable` | No route to the target. |
| `protocol_error` | The client broke a framing rule (§3). |
| `internal` | Any other failure. |

- **`tcp_close` reasons:**

| Reason | Meaning |
|---|---|
| `closed` | FIN was seen in both directions. |
| `reset` | The target sent RST, or a socket error occurred. |
| `idle_timeout` | No byte in either direction for the idle period. |
| `byte_cap` | The byte cap was reached. |
| `max_duration` | The maximum duration passed. |
| `agent_disconnected` | The agent's connection dropped. |
| `stopped` | The server or an admin ended the stream, the grant was withdrawn at a renewal (§5), or renewal was rejected. |

- **Client close.** When the client closes its socket, the agent closes the
  target. The audit reason is then `client_closed`; no frame is sent.
- **Close codes:**
  - 1000 after `tcp_close`;
  - 1011 after a `tcp_status` error;
  - 1009 for an oversized frame.

## 8. Half-close

- **Client FIN.** sahlink reads EOF locally and sends `tcp_eof`, and the agent
  calls `shutdown(SHUT_WR)` on the target. Bytes from the target keep flowing.
- **Target FIN.** The agent reads EOF, the server sends `tcp_eof`, and sahlink
  calls `shutdown(SHUT_WR)` on its local socket.
- **Both seen.** The server sends `tcp_close` with reason `closed`.
- **RST on either side.** The stream ends at once with reason `reset`.

## 9. Audit and recording

The rows below go in the server's audit chain, with every column hashed:

- **`ticket_issued`:** actor, host, purpose, target.
- **`tcp_start`:** `session_id`, target, `peer`, and `via` (true when the
  target is not `local`).
  - It is written BEFORE `connected`, and no byte flows before it.
  - If the write fails, the session ends with `internal`.
- **`tcp_end`:** `session_id`, reason, the server's `bytes_in` and
  `bytes_out`, the agent's byte counts, `duration_s`. It is retried the way
  `terminal_end` is.
- **Content is not recorded (owner-accepted, 2026-10-14).**
  - The intended traffic (RDP, TLS to databases, HTTPS) is end-to-end
    encrypted between the user's tool and the target, so a recording would be
    ciphertext with no review value.
  - It would also be a liability if session keys leaked later.
  - Accountability comes from who, which target, when, how long and how many
    bytes, plus a deny-by-default target policy.
  - **Known gap:** a plaintext protocol forwarded through this channel isn't
    recorded either. A recorded RDP gateway is a separate future design.

## 10. Reverse forwards (`ssh -R`): future, out of scope

No frame, purpose or scope here opens a listener on a host. A request for one
gets `bad_purpose`.

## 11. Agent ↔ server frames (internal to systemapi.io)

- **Server → agent:**
  - `{"type":"tcp_open","session_id","target":{"host","port"},"deadline_unix","idle_s","max_bytes","lease"}`
  - `{"type":"tcp_renew","session_id","lease"}`
  - `{"type":"tcp_eof","session_id"}`
  - `{"type":"tcp_stop","session_id"}`
  - `{"type":"tcp_credit","session_id","bytes":N}`
- **Agent → server:**
  - `tcp_status`, with `{"status":"connected","peer"}` or `{"error"}`
  - `tcp_eof`
  - `tcp_credit`
  - `{"type":"tcp_closed","session_id","payload":{"reason","bytes_in","bytes_out"}}`
- **Data.** Binary in both directions, shaped
  `[1-byte id length][session id][bytes]`. This is the existing PTY output
  format.

## 12. Threats

**Defended:**
- An SSRF pivot into the host's network or cloud metadata. §4 is deny by
  default, with two independent allowlists, refused address classes, and no DNS
  names in phase 0.
- A ticket replayed, or used for another host, purpose or target.
- A stream outliving its lease.
- One stream starving the others, or the agent's memory (credit windows and
  caps).
- A browser page opening a tunnel (the Origin check).
- An API key in a URL.

**Not defended:**
- What flows through an allowed tunnel. Content is not inspected or recorded.
- An allowed target that is itself a proxy.
- A hostile local process using sahlink's listener. sahlink binds 127.0.0.1
  only.
- Reverse forwards, which are not implemented.

## 13. Conformance

**Client MUST:**
- send credentials in headers only, and use TLS 1.3;
- get one ticket per TCP connection;
- send no bytes before `connected`;
- send `tcp_eof` on local EOF, and honour `tcp_eof` with `SHUT_WR`;
- keep frames at 64 KiB or less;
- bind local listeners to loopback only;
- stop reading its local socket while its WebSocket send is blocked;
- exit non-zero on any `tcp_status` error, and print the code.

**Server MUST:**
- check scope, policy and refused classes at ticket issue and at the upgrade;
- consume the ticket on first use;
- apply the Origin rule;
- write `tcp_start` before any byte flows;
- sign and renew the lease;
- enforce the deadline, idle timeout, byte cap and caps;
- apply backpressure and never drop bytes;
- write `tcp_end` with byte counts;
- never log ticket values.

**Agent MUST:**
- verify the lease, including its target;
- apply its own allowlist and the refused classes;
- dial by IP only;
- deny by default;
- honour credit;
- end the stream at lease lapse, the deadline, the idle timeout or a cap.

## 14. Tests (negative cases ship with phase 0)

- A reused ticket fails.
- A host-A ticket cannot open host B.
- A `terminal:open` ticket cannot open TCP, and the reverse.
- A target-X ticket cannot dial target Y.
- An empty server policy gives `target_denied`.
- An empty agent allowlist gives `target_denied_agent`.
- `169.254.169.254` gives `target_forbidden`.
- `127.0.0.1` gives `bad_target`.
- A DNS name gives `bad_target`.
- The idle timeout, byte cap and max duration each fire.
- After one FIN, data still flows the other way.
- A slow client stalls without growing server memory.
- An agent that overruns its credit is disconnected.

## 15. Owner decisions (2026-10-14)

- **Content.** Not recorded, accepted (§9).
- **Ticket budget.** TCP has a separate budget of 120 per minute.
- **Targets.** No DNS names in phase 0.
- **Agent allowlist.** Stays a local flag, as an independent second key.
- **Defaults.** As listed in §5.
