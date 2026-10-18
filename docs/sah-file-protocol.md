# File protocol: sahsync ↔ SystemAPI

Status: contract, phase 0, not yet implemented. Both sides implement exactly
this. Change it only by editing this file and both implementations in the same
change. List the call in `sah-suite.md` Wired join when it ships. Conventions
follow `sahconnect-terminal-protocol.md` (the PTY contract). **(rec)** marks a
recommendation that is not yet in the code. Owner decisions (2026-10-14) are
folded in: see §13. The choices the implementation made where this text was
silent or ambiguous are in §14.

## 0. Model

**One WebSocket is one session.** It carries **strictly sequential**
request/response operations under one ticket, one root and one identity.

A session, rather than one WebSocket per operation, because:
- A `sync` touches thousands of paths, so one ticket per operation would hit
  the ticket rate limit.
- It would also cost a TLS handshake and a lease every time.

Sequential, because:
- Every response is unambiguous.
- The audit order equals the execution order.
- Throughput comes from pipelined chunks *inside* a read or write (§6).
- A client that wants parallel work opens more sessions, up to its per-actor
  cap.

## 1. Auth, resolve, transport

The same as PTY:
- the bearer token or `X-API-Key`, in a header only;
- `GET /api/v1/hosts/resolve`;
- TLS 1.3 with the system CA pool.

## 2. Scopes and ticket

| Purpose | Scopes required | Ops allowed | Runs as |
|---|---|---|---|
| `file:read` | `file:read` (operator) | stat, list, read, hash | the host's `pty_user` |
| `file:write` | `file:read` + `file:write` (operator) | all | the host's `pty_user` |
| `file:root` | `file:root` (admin only, like `terminal:root`) | all | root |

`file:root` uses the privileged ticket budget.

    POST /api/v1/ws-ticket
    {"host_id":"<id>","purpose":"file:read"|"file:write"|"file:root","root":"/srv/app"}

- **`root`** is either:
  - an absolute host path: 1–4096 bytes, starting with `/`; no `.` or `..`
    component; no empty component; no trailing `/` (except `/` itself); no NUL
    or control characters;
  - or `"~"`, the `pty_user`'s home directory. `"~"` is refused for
    `file:root`.
- **Server policy** **(rec: a `file_policy` column, per host, with a tenant
  default)**: `{"roots":[{"path":"/srv/app","read":true,"write":true}]}`.
  - The default is `{"roots":[]}`, which denies everything.
  - The requested `root` must equal an allowed `path` or sit beneath one, on a
    path-component boundary.
  - The matching entry must permit the mode.
  - `file:root` also needs `"root":true` on the entry.
- **Binding.** The ticket is bound to host, purpose **and root**.
- **Success.** `200 {"ticket":"stk_...","expires_at":"<iso8601>","expires_in":60,"host_id":"...","purpose":"..."}`.
  The ticket is single-use and valid for 60 s.
- **Errors:**
  - `400 bad_purpose`;
  - `400 bad_root`;
  - `403 scope_denied`;
  - `403 root_denied`;
  - `404 not_found`;
  - `429 rate_limited`.

## 3. WebSocket and session frames

    wss://<systemapi>/api/v1/systems/file/<host_id>?ticket=<ticket>&purpose=<purpose>

- **Upgrade rules** are identical to PTY §3: the ticket only, `api_key` gets
  401, and the Origin allowlist applies.
- **Server → client session frames:**
  - `{"type":"file_status","payload":{"status":"starting"}}`
  - `{"type":"file_status","payload":{"status":"ready","session_id":"fls_...","root":"/srv/app","user":"deploy","limits":{"chunk_max":1048576,"read_max":8388608,"write_window":8,"file_max":17179869184,"list_max":1000}}}`
    - `root` is the canonical path the agent opened.
    - A request before `ready` is a `protocol_error`.
  - `{"type":"file_status","payload":{"error":"<code>"}}`, then the server
    closes with 1011.
  - `{"type":"file_close","payload":{"session_id":"fls_...","reason":"<reason>","ops":N,"bytes_read":N,"bytes_written":N}}`,
    then the server closes with 1000.
- **Frame size.** Text frames are capped at 64 KiB, binary frames at
  `chunk_max`. Larger closes with 1009.

## 4. Requests and responses

- **Request shape.** Every request is a JSON text frame with `type`,
  `request_id` and `op` (both spellings of `type` are in §14).
  - `request_id` matches `^[A-Za-z0-9_-]{1,64}$` and is unique per session. A
    reused id is a `protocol_error`. The one exception is a write: its
    chunks, commit and abort carry the `write_open`'s `request_id` (§14).
- **Response shape.** Exactly one response per operation:

      {"type":"file_result","request_id":"r7","op":"<op>","status":"ok"|"error","error":null|"<code>", ...op fields}

- **Field formats.**
  - `sha256` is 64 lowercase hex characters.
  - `mtime_ns` is integer nanoseconds since the epoch, a signed 64-bit
    integer (-2^63 ≤ v < 2^63). It exceeds 2^53, so a client in JavaScript
    MUST parse and send it exactly (not as a double). An `if_match` whose
    `mtime_ns` is outside that range is `bad_request`.
  - An entry is
    `{"name":"<component>","type":"file"|"dir"|"symlink"|"other","size":N,"mode":"0644","mtime_ns":N}`.
    A symlink's target is never returned.
- **Sequencing.** A new request before the previous `file_result` is a
  `protocol_error`. The only exception is `write_chunk`, `write_commit` and
  `write_abort` for the open write.
- **Unknown `op`.** Gets a `bad_request` result. The session stays open.

| op | Request fields | ok-response fields |
|---|---|---|
| `stat` | `path` | `entry` |
| `list` | `path`, `cursor` (string or null), `limit` (1–1000, default 500) | `entries` (sorted bytewise by name), `next_cursor` (null at the end) |
| `read` | `path`, `offset` ≥ 0, `length` (1–`read_max`), optional `if_match` `{"size","mtime_ns"}` | `bytes`, `eof`, `size`, `mtime_ns` (after the data frames, §6) |
| `hash` | `path`, optional `if_match` | `sha256`, `size`, `mtime_ns` |
| `write_open` | `path`, `size`, `sha256`, `overwrite` (bool), optional `mode` (octal string `0600`–`0777`, no setuid/setgid/sticky), `resume` (bool) | `upload_id` (`upl_...`), `offset`, `prefix_sha256` (when `offset` > 0) |
| `write_chunk` | the write's `request_id`, `offset`, `length` (1–`chunk_max`), then one binary frame | `write_ack` (§6), not a `file_result` |
| `write_commit` | the write's `request_id` | `sha256`, `size`, `path` |
| `write_abort` | the write's `request_id` | none |
| `mkdir` | `path`, `parents` (bool), optional `mode` | `entry` |
| `remove` | `path` | none |

- **`remove`** deletes one regular file, one symlink (the link itself, never
  its target) or one EMPTY directory.
  - There is no recursive remove.
  - A non-empty directory gives `not_empty`.
- **`read` and `hash`** work only on regular files.
  - They open with `O_NONBLOCK`, `fstat`, and check the type, so a FIFO can
    never block.
  - If `if_match` is given and the size or `mtime_ns` differs, the result is
    `changed`.

## 5. Paths: the exact rules

1. **Shape.**
   - `path` is relative to the session root: UTF-8, 1–4096 bytes, separated by
     `/`. Each component is 1–255 bytes.
   - `"."` alone means the root.
   - These are refused with `bad_path`:
     - a leading `/`;
     - an empty component (`a//b`) or a trailing `/`;
     - a component that is `.` (other than the whole path) or `..`;
     - NUL, the bytes 0x01–0x1F and 0x7F, or `\`;
     - invalid UTF-8.
   - Nothing is decoded: `%2e%2e` is a literal file name. There is no Unicode
     normalization.
2. **Reserved names.** A component matching `.sahsync-*.part` gives
   `reserved_name`.
3. **Root.**
   - At session start the agent opens the root with
     `openat2(AT_FDCWD, root, O_PATH|O_DIRECTORY, RESOLVE_NO_SYMLINKS)`.
   - Any symlink component, or a root that is not a directory, gives
     `root_invalid`.
   - The fd is held for the whole session.
4. **Resolution.**
   - Every operation uses
     `openat2(rootfd, path, ..., RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`.
   - **`openat2` is required (Linux 5.6 or later).** A kernel without it gives
     `agent_unsupported`; there is no fallback in phase 0.
   - **No symlink below the root is ever followed**, for reads or writes,
     whether it points inside or outside the root. Meeting one gives
     `symlink_refused`.
   - `stat`, `list` and `remove` act on a final symlink itself (`lstat`
     semantics, `unlinkat`).
5. **Writes.**
   - The temp file is `.sahsync-<upload_id>.part`, in the target's parent
     dirfd. It is opened `O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY` with mode 0600.
   - Commit is `renameat2(RENAME_NOREPLACE)` when `overwrite` is false.
     Otherwise it is `renameat` onto an existing **regular file** only. A
     directory or symlink in the way gives `not_a_file`.
   - All of this works through dirfds, never by resolving path strings again.
6. **Known gap.** A hard link inside the root to a file outside it cannot be
   detected. The kernel's permissions for the identity running the operation
   limit what it can reach.

## 6. Data transfer, backpressure, integrity, resume

- **Read.**
  - The server sends zero or more pairs: a
    `{"type":"read_chunk","request_id":"r7","offset":N,"length":L}` text frame,
    then exactly one binary frame of exactly L bytes (L ≤ `chunk_max`).
  - Then it sends the `file_result`.
  - The client pulls one range at a time (`length` ≤ `read_max`).
- **Write.**
  - After `write_open`, the client sends pairs: a
    `{"type":"write_chunk","request_id":"r9","offset":N,"length":L}` text frame,
    then one binary frame of L bytes.
  - `offset` must equal the next expected offset, or the result is
    `offset_mismatch`.
  - After each chunk is written to the temp file, the server sends
    `{"type":"write_ack","request_id":"r9","offset":<next>}`.
  - At most `write_window` (8) chunks may be unacknowledged.
  - Data beyond the declared `size` gives `too_large`.
- **Commit** (atomic, with integrity checked end to end):
  1. Check that `offset == size`.
  2. fsync the temp file.
  3. **Re-read it from disk** to compute its sha256.
  4. Compare that with the declared sha256. A mismatch deletes the temp file
     and returns `sha256_mismatch`.
  5. Apply `mode`, rename (§5.5), and fsync the parent directory.
  6. Only then return `ok`.

  A partial or corrupt upload is never visible at the target path.
- **Abort.** `write_abort` deletes the temp file and its record. With no open
  write, the result is `upload_not_found`.
- **Kept or discarded.** A write that ends without a commit either keeps its
  temp file and record for resume, or discards both:
  - **discarded**: `write_abort`; `sha256_mismatch`; the client's own faults,
    which a resume could not repair: a chunk at the wrong offset or a commit
    before the last byte (`offset_mismatch`), data past the declared size
    (`too_large`), a malformed chunk (`bad_request`);
  - **kept**: the session ending or the connection dropping mid-write, and a
    host fault on a chunk or the commit (`no_space`, `permission_denied`,
    `io_error`, ...). A `write_open` whose audit row cannot be written is
    answered `internal` and its upload is kept.
- **Chunks after the write ended.** Chunks the client sent before it saw the
  write end are read and dropped, at most `write_window` per write; one more
  is a `protocol_error`.
- **Resume an upload.**
  - The client sends `write_open` with `resume:true` and the same path, size
    and sha256.
  - If there is a live upload for the same actor, host, root, path, size and
    sha256, the server returns its `upload_id`, `offset` (the bytes durably
    written) and `prefix_sha256`.
  - The client MUST compare `prefix_sha256` with its own local prefix. On a
    mismatch, abort and restart.
  - Interrupted uploads are kept for 24 h. Where each part lives (this
    settles §5.5 against the line above it in earlier drafts):
    - the **record** (actor hash, root, path, size, sha256, creation time)
      lives in the agent's state directory, as
      `<state dir>/file-uploads/<upload_id>.json` (0600, in a 0700
      directory), never in the target tree;
    - the **bytes** stay in `.sahsync-<upload_id>.part` beside the target,
      in its parent directory (§5.5), because the commit must be an atomic
      rename within one directory.
  - Expired uploads (temp file, then record) are swept at every session
    start and hourly while the agent runs.
  - **Upload cap.** One actor holds at most 16 live uploads (open or
    interrupted) under one root on one agent. A new `write_open` past that is
    `no_space`; a resume that reopens an existing upload's temp file is not
    a new upload. A resume whose temp file cannot be reopened (gone,
    replaced, or not a regular file) starts a new upload: the agent first
    removes the stale temp file and record, then applies the cap as to any
    new upload. The check and the new record are serialized per actor and
    root across sessions, so concurrent `write_open`s cannot overshoot it.
    The client frees a slot by resuming and committing or aborting, or by
    letting an upload expire. Only the agent can see the records, so only
    the agent enforces this cap.
- **Download.**
  1. `stat` the file.
  2. `read` it in ranges, with `if_match`, into a local temp file.
  3. Finish with `hash` (with `if_match`) and compare the sha256 with the local
     temp file.
  4. Rename locally.

  To resume, continue from the local partial length. `changed` means restart
  from zero.
- **Agent hop.**
  - There is an 8 MiB credit window per session.
  - Binary data is shaped `[1-byte id length][session id][bytes]`.
  - The server stops reading the client while credit is zero, and stops
    granting the agent credit while the client's `bufferedAmount` is above
    8 MiB.
  - Nothing is ever dropped.

## 7. Identity, lease, limits

- **Identity.**
  - `file:read` and `file:write` run as the host's `--pty-user`, with uid, gid
    and supplementary groups dropped as for PTY. They never run as the agent's
    user.
  - The agent runs each session in a child helper process
    (`systemapi-agent file-helper`), started with `SysProcAttr.Credential` as
    `pty_unix.go` does. This is an owner decision: Go cannot drop privileges
    safely per goroutine.
  - `file:root` runs the helper as root, and only on a root agent.
  - A non-root agent refuses everything unless `--pty-allow-agent-user` is set.
  - With `--pty-user-map`, the account is the `actor`'s own entry, resolved
    exactly as for `terminal:open` (`docs/sahconnect-terminal-protocol.md`
    §6); an actor with no entry is refused with `account_unmapped`.
  - Errors: `pty_user_unset`, `account_unmapped`, `root_unavailable`.
- **Lease.** Actions `file` and `file_root`.
  - The signed payload is
    `"<session_id>\n<deadline_unix>\n<start|renew>\n<read|write>\n<root>"`.
  - The agent refuses a write op on a read lease.
  - The TTL is 60 s, renewed every 30 s.
  - **Every renewal re-checks the grant** first, as the upgrade does: the
    actor's membership and scopes, an API key still active (not revoked,
    locked or expired), and the root policy. A denial ends the session with
    `stopped` and no new lease is signed. A failed lookup only skips that
    renewal: nothing is signed, and the agent ends the session when the last
    lease lapses.
  - The session id matches `^fls_[A-Za-z0-9_-]{16,64}$`.
- **Limits** (defaults; owner-accepted):

| Setting | Default |
|---|---|
| `SYSTEMAPI_FILE_MAX_SECONDS` | 28800 |
| `SYSTEMAPI_FILE_IDLE_SECONDS` | 900 |
| `SYSTEMAPI_FILE_MAX_BYTES` | 16 GiB (one file) |
| `SYSTEMAPI_FILE_SESSION_BYTES` | 64 GiB |
| `SYSTEMAPI_FILE_MAX_OPS` | 100000 |
| `SYSTEMAPI_FILE_MAX_PER_ACTOR` | 4 |

  Fixed: `chunk_max` 1 MiB, `read_max` 8 MiB, `list_max` 1000. There are no
  batch operations.
- **Per-agent cap.** 16 live file sessions per agent, enforced by the server
  and the agent. 2 of them are reserved for `file:root`: `file:read` and
  `file:write` sessions get at most 14, so an admin can always reach a host
  that operators have filled.
- **Roots the agent refuses.** Whatever the policy says, a session other than
  `file:root` is refused with `root_denied` when its root is `/` (also `"~"`
  for an account whose home is unset or `/`) or contains the agent's state
  directory (its identity seed and upload records), compared as given and
  with symlinks resolved.

## 8. Error codes

- **Session errors** (`file_status`):

| Code | Meaning |
|---|---|
| `ticket_invalid` | The ticket is missing, used, expired, or for another host, purpose or root. |
| `scope_denied` | The caller lacks the scope for this purpose. |
| `agent_offline` | No live agent connection for the host. |
| `agent_unsupported` | The agent lacks file support, or the kernel has no `openat2`. |
| `lease_required` | No signer on the server. |
| `cap_reached` | A per-actor or per-agent cap is full. |
| `root_denied` | The server policy refuses the root, or the agent refuses it (§7: `/`, or a root holding its state directory, outside `file:root`). |
| `root_invalid` | The root contains a symlink, is missing, or is not a directory. |
| `pty_user_unset` | The agent has no `pty_user` to run as. |
| `account_unmapped` | The agent has a `--pty-user-map` and the actor has no entry in it. |
| `root_unavailable` | `file:root` on an agent that cannot run as root. |
| `protocol_error` | The client broke a framing rule. |
| `internal` | Any other failure. |

- **Operation errors** (`file_result`; the session stays open):

| Code | Meaning |
|---|---|
| `bad_request` | Unknown op, or malformed fields. |
| `bad_path` | The path breaks §5.1. |
| `reserved_name` | The path names a `.sahsync-*.part` file. |
| `not_found` | No such entry. |
| `not_a_file` | Not a regular file where one is required. |
| `not_a_dir` | Not a directory where one is required. |
| `exists` | The target exists and `overwrite` is false. |
| `not_empty` | `remove` on a non-empty directory. |
| `symlink_refused` | A symlink was met during resolution. |
| `permission_denied` | The kernel refused for this identity. |
| `read_only` | A write op in a `file:read` session. |
| `too_large` | Over a size limit, or past the declared size. |
| `no_space` | The filesystem is full, or the actor already holds 16 live uploads under this root (§6). |
| `changed` | `if_match` failed. |
| `sha256_mismatch` | The committed bytes do not match the declared hash. |
| `offset_mismatch` | A chunk did not start at the next expected offset. |
| `upload_not_found` | No such upload, or no open write. |
| `io_error` | Any other I/O failure. |

- **`file_close` reasons:**
  - `idle_timeout`
  - `max_duration`
  - `byte_cap`
  - `op_cap`
  - `agent_disconnected`
  - `stopped` (also: the grant was withdrawn at a renewal, §7, or the lease
    lapsed at the agent)
  - `client_closed` (audit only)

## 9. Audit (owner decision on volume, 2026-10-14)

Every column is hashed in the chain.

- **`ticket_issued`:** actor, host, purpose, root.
- **`file_session_start`:** `session_id`, purpose, the canonical root, user,
  uid.
  - It is written before `ready`. If the write fails, the result is
    `internal`.
- **Mutating ops** (`write_commit`, `mkdir`, `remove`) get FULL rows:
  - an **intent row**, written before the op is forwarded: op, path, size, the
    declared sha256. If that write fails, the op is refused with `internal`;
  - a **result row**: op, path, size, sha256, result.
  - `write_open` and `write_abort` get one row each, including the
    `upload_id`.
- **Reads** are coalesced into `file_read` rows per path: path, bytes,
  ranges count, and the last `hash` sha256 if one was taken. The rows are
  flushed every 60 s, as soon as one path's unflushed bytes reach 1 GiB, and
  at the session end; each flush resets the counters, so a long session has
  several rows for one path and every byte is in exactly one of them.
- **`stat` and `list`** get no individual rows. They are counted in
  `file_session_end` (`stat_count` and `list_count`).
- **`file_session_end`:** reason, ops, `bytes_read`, `bytes_written`,
  `stat_count`, `list_count`, `failed_reads` (`read` and `hash` results that
  were errors, `permission_denied` say), `duration_s`. It follows every
  `file_read` row of the session.
- **File content is not recorded.** Path, size and sha256 identify exactly
  what moved. Keeping a second copy of every file would be an unbounded
  retention and breach liability.

## 10. Threats

**Defended:**
- Traversal and absolute escape (§5.1).
- Symlink escape and TOCTOU: everything resolves through held dirfds with
  `RESOLVE_BENEATH|NO_SYMLINKS`.
- A partial or corrupt file appearing at the target: temp file, fsync,
  re-hash, then atomic rename.
- A write through a read ticket: scope, ticket, lease and agent each check.
- An operator doing a root file operation.
- Operations running as the agent's own user.
- A FIFO or device file hanging the agent.
- Replayed tickets, or tickets for another host or purpose.
- Memory blow-up: credit windows and caps.

**Not defended:**
- What `pty_user` may legitimately read inside the root.
- Hard links (§5.6).
- Content inspection or DLP.
- A concurrent writer on the host changing a file between `hash` and its use.

## 11. Conformance

**Client MUST:**
- send credentials in headers only, and use TLS 1.3;
- wait for `ready`;
- send one request at a time;
- send relative paths only;
- respect `write_window` and `chunk_max`;
- declare size and sha256 before writing;
- verify `prefix_sha256` before resuming;
- verify sha256 after every download;
- write locally to a temp file, then rename;
- never overwrite a local file without `--force`.

**Server MUST:**
- check scope, the root policy and the purpose at ticket issue and at the
  upgrade;
- consume the ticket on first use;
- apply the Origin rule;
- enforce sequencing;
- write the session-start row before `ready`, and the intent rows before
  mutations;
- sign and renew the lease;
- enforce every limit;
- never drop bytes;
- never log ticket values or file content.

**Agent MUST:**
- verify the lease, including its mode and root;
- run operations in the dropped-privilege helper;
- resolve paths only as §5 says;
- refuse every symlink;
- write only through temp file, fsync, re-hash and rename;
- clean up after an abort, and expire stale uploads.

## 12. Tests (negative cases ship with phase 0)

- `../../etc/shadow`, `/etc/shadow`, `a/../../x`, `a//b` and `a/./b` give
  `bad_path`.
- A symlink inside the root that points outside gives `symlink_refused`, for
  reads and for writes.
- A symlinked root gives `root_invalid`.
- A FIFO gives `not_a_file`.
- A `file:read` ticket cannot write.
- A reused ticket fails.
- A host-A ticket cannot touch host B.
- A ticket for root `/srv/a` cannot reach `/srv/b`.
- A sha256 mismatch leaves nothing at the target and no temp file.
- A killed upload resumes at the right offset, and a wrong prefix is caught.
- `overwrite:false` gives `exists`, with no race.
- A pipelined request gives `protocol_error`.
- An operator cannot get `file:root`.

## 13. Owner decisions (2026-10-14)

- **Audit volume.** Full rows for changes; reads coalesced per path;
  `stat`/`list` counted only (§9).
- **File helper.** Operations run in a child helper process with dropped
  privileges.
- **Kernel.** `openat2` is required, with no fallback.
- **Defaults.** As listed in §7.

## 14. Implementation decisions (where §1–§12 were silent)

- **Request `type`.** A request is either
  `{"type":"file_request","request_id":...,"op":"<op>",...}` or names the op
  in `type` itself: `{"type":"<op>","request_id":...}` (`op` then omitted or
  equal to `type`). An `op` with any other `type` is a `protocol_error`; a
  request that names no known op either way gets `bad_request`. A chunk
  header is `{"type":"write_chunk",...}`.
- **Write `request_id` reuse.** `write_open` opens a write under its
  `request_id`. Its `write_chunk` headers, its `write_ack`s and its
  `write_commit` or `write_abort` all carry that same id; this is the one
  allowed reuse. While a write is open, any other request (a commit or abort
  under another id included) is a `protocol_error`; with no write open, a
  `write_commit` or `write_abort` gets `upload_not_found`.
- **Kept versus discarded temp files.** As listed in §6 ("Kept or
  discarded").
- **Exact `mtime_ns`.** The server parses every integer literal of 16 or more
  digits exactly and relays it with the same digits; the agent decodes it as
  int64. A request the agent cannot decode but whose `request_id` it can
  read is answered `bad_request` rather than dropped, so the session never
  waits on it.
- **Default modes.** A new file gets 0644 unless `mode` is given; an
  overwritten regular file keeps its current mode unless `mode` is given. A
  new directory gets 0755 unless `mode` is given. The helper runs with umask
  0, so the mode is exact.
- **`list`.** Entries named `.sahsync-*.part` (the agent's temp files) and
  names that are not valid UTF-8 (no request could address them, §5.1) are
  left out.
- **`list` cursor.** `next_cursor` is the unpadded base64url encoding of the
  last returned name; a request's `cursor` resumes after that name in
  bytewise order. Clients treat it as opaque. It is at most 1024 characters.
- **Session caps.** 16 file sessions per agent, 2 reserved for `file:root`
  (§7), plus `SYSTEMAPI_FILE_MAX_PER_ACTOR`.
- **Upload cap.** 16 live uploads per actor and root on the agent, `no_space`
  past it (§6).
- **Audit action names.** `ticket_issued`; `file_session_start`;
  `file_intent` (the intent row before `write_commit`, `mkdir` and
  `remove`); `file_op` (one row each for `write_open`, `write_commit`,
  `write_abort`, `mkdir` and `remove`, with `result`); `file_read`;
  `file_session_end`.
