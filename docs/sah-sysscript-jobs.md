# Async sysscript jobs: rollout and rollback

A sysscript job runs a script on one host while the HTTP request returns at
once. The routes are in `api_docs.md` ("Async sysscript jobs"), the CLI and
agent flags in `cli_docs.md`, and the design in
`.omc/plans/async-sysscript-jobs.md`.

A script goes as a job only when both sides allow it:

- the server runs with `SYSTEMAPI_SYSSCRIPT_JOBS` unset or `1`, and
- the host's agent advertises `sysscript_jobs` (`--sysscript-jobs`, default
  `true`, Linux and macOS only).

Anything else keeps the legacy path: `/execute`, `/fleet/execute`, playbooks,
schedules and rule playbooks answer as before, and `/jobs` answers 501
`agent_unsupported` (old or opted-out agent) or 503 `jobs_disabled` (server
switch off).

## Rollout

1. **Before you start**, run `GET /api/v1/audit/verify`. `cp_audit` may
   contain forks written before d8c8342. Record the result so a later
   failure can be told apart from an old one.
2. **Server first.** Deploy the control plane on every instance, with
   `SYSTEMAPI_SYSSCRIPT_JOBS` unset or `1`. The schema additions are applied
   on start. Agents that do not advertise the capability are unaffected.
3. **Then agents, a few hosts at a time.** A new agent advertises
   `sysscript_jobs` on its next enroll, and from then on that host's scripts
   go as jobs. Check each host:
   - `node cli/systemapi.js jobs submit <host> <file> --wait 60` exits 0;
   - a terminal session on the host still answers while a long job runs;
   - its `sysscript_job_submit` and `sysscript_job_end` audit rows exist.
4. **Windows hosts** stay on the legacy path. Their agents never advertise
   the capability.
5. **Audit consumers** that filter on `sysscript` or `command_result` must
   also read `sysscript_job_submit` and `sysscript_job_end` (`api_docs.md`).

## Rollback

**Before any agent restart** (a flag change, an upgrade or a rollback):
stopping the agent kills the scripts it is running. Each one's process
group gets SIGTERM, then SIGKILL 10 s later, including an `apt` or `dpkg`
in the middle of an install. So first look for running jobs on that host:

```bash
node cli/systemapi.js jobs list --host <host_id> --status running
node cli/systemapi.js jobs list --host <host_id> --status accepted
```

Wait for them (`jobs wait <id>`) or cancel them (`jobs cancel <id>`), then
restart. If a package install was killed anyway, see "After a killed
package install" below.

How the jobs of a stopped agent end:

- **A graceful stop** (SIGTERM or SIGINT, as `systemctl stop` sends): the
  agent kills its running jobs' process groups and reports each one
  `failed` with error `agent_stopped` before it disconnects.
- **A crash, `kill -9`, or a report lost with the connection:** the server
  never hears. It ends each job `failed`/`result_lost` at its deadline +
  60 s (the sweep runs every 30 s). If the next agent to connect is a jobs
  build, its first sync ends them `agent_lost_job` sooner.

From the narrowest rollback to the widest:

- **One host.** Restart its agent with `--sysscript-jobs=false` (after the
  check above). It stops advertising the capability, and the server sends
  its scripts the legacy way. The agent's worker pool and deadlines still
  apply.
- **Every host.** Set `SYSTEMAPI_SYSSCRIPT_JOBS=0` on every server instance
  and restart them. Every caller goes legacy and `/jobs` answers 503.
  - Jobs already submitted still run, end, and are stored and audited.
  - While the switch is off, `GET /api/v1/jobs` answers 503, so read them
    in the audit log.
  - The tick keeps expiring output after
    `SYSTEMAPI_JOB_OUTPUT_RETENTION_HOURS` (default 72), so output of jobs
    that end while the switch is off may be gone before it is turned back
    on.
- **An agent binary.** Rolling an agent back to a build without jobs stops
  the old agent first (see above), and the old build never reports jobs.

## After a killed package install

A job that times out or is cancelled kills its whole process group: SIGTERM,
then SIGKILL 10 s later. So does any agent stop or restart while the job
runs (an upgrade, a rollback, a flag change). If that group was running
`apt` or `dpkg`, the package database may be left half-configured. On that
host, run:

```bash
sudo dpkg --configure -a
```

Give package installs a `timeout_s` long enough for the slowest mirror (up to
`SYSTEMAPI_SYSSCRIPT_JOB_MAX_S`, default 1800) instead of relying on the 300 s
default.

## After any rollback or incident

Run `GET /api/v1/audit/verify` again and compare it with the result from
step 1 of the rollout. A break that appears only in rows from before d8c8342
is the known fork, not a new one.

## Desired-state locks (convergence)

The control plane boots every schema file under one session advisory lock
(`pg_locks`: `classid = 1396789321, objid = 2`), so replicas starting together
apply them one at a time; a boot that hangs is waiting for that lock. Every
enroll (each agent reconnect), retire, tag change and assignment change takes
the tenant-wide desired-state lock (`classid = 1398030676`, `objid` =
`hashtext(tenant_id)`) for its transaction to re-sync that tenant's host
states. A reconnect storm in one large tenant therefore serializes on that
lock; other tenants are not affected. The drift claim lock is
`classid = 1396789321, objid = 3`.

# Protocol reference

Sources: `playground/jobs.js` (server engine), `controlplane/registry.js`
(rows, transitions, sweeps), `controlplane/lease.js` and
`controlplane/entitlements.js` (lease and canonical entitlements),
`systemapi-agent/sysscript_jobs.go` and `systemapi-agent/lease.go` (agent),
and `controlplane/testdata/sysscript-job-lease-vectors.json`, which both
sides' tests check.

All frames are JSON text frames on the agent's WebSocket. A job id matches
`^sjb_[A-Za-z0-9_-]{22}$`.

## Frames, server to agent

**`sysscript_job`** starts a job. Signed.

```json
{
  "type": "sysscript_job",
  "job_id": "sjb_...",
  "script": "...",
  "entitlements": { "allow_exec": true },
  "deadline_unix": 1700000300,
  "timeout_s": 300,
  "lease": {
    "v": 1, "host_id": "...", "action": "sysscript_job",
    "expires_unix": 1700000060, "nonce_hex": "<32 hex>",
    "payload_sha256": "<64 hex>", "signature": "<base64 Ed25519>"
  }
}
```

The fields are exactly what was stored at submit, including the
entitlements object the lease hashed. The lease lives 60 s. Only the
instance that holds the host's socket sends it, and only when that socket's
`conn_id` is the one in `cp_hosts`. The payload is claimed once
(`markDispatched` nulls it and records `conn_id` and `sent_at`), so two
instances never both send a job.

**`sysscript_job_cancel`** `{"type", "job_id", "reason"}`. Unsigned: it can
only shorten work. The agent ignores ids it does not hold. `reason`:

- `user`: a cancel was requested through the API.
- `terminal`: the server already ended the job. Sent when a status frame
  arrives for an ended job, or a sync lists an ended job as active.
- `unknown`: a sync listed an id the server has no row for on this host.

**`sysscript_job_ack`** `{"type", "job_id"}`. Unsigned: it only frees the
agent's kept result. Sent once a result is stored, and again when a
re-sent result or a sync's `unacked` entry names a job that has already
ended.

## Frames, agent to server

Each has `type`, `payload` and, except the sync, a top-level `job_id`.

**`sysscript_job_status`**: `{"status": "accepted", "deadline_unix": N,
"queued": true}` when the job is queued, then `{"status": "running",
"started_unix": N}` when a worker picks it up. The agent's `deadline_unix`
is its effective deadline (below). The server moves the row `submitted` →
`accepted`, or `submitted`/`accepted` → `running`.

**`sysscript_job_result`**: `{"status", "error", "output",
"output_truncated", "duration_ms"}`.

- `status` is `succeeded`, `failed`, `cancelled` or `timed_out`.
  - `error` is `""` on success, `timed_out` or `cancelled` for those
    statuses, and `agent_stopped`, `internal` or the script's error text for
    `failed`.
  - The whole frame is at most 1 MiB encoded, with `error` capped at
    16 KiB. Output that does not fit is cut and `output_truncated` set.
  - The server stores it from any active status, writes the
    `sysscript_job_end` audit row (actor `agent`) and acks.
- `status: "rejected"` refuses a start frame. `error` is the code and
  `job_id` is echoed only when well formed. The server ends the row
  `failed` with that code (`agent_rejected` if it is not `^[a-z_]{1,64}$`),
  only while the row is still `submitted`. Codes:
  - frame checks: `bad_job_id`, `script_too_large`, `bad_entitlements`,
    `bad_deadline`, `bad_payload`;
  - lease checks: `malformed`, `bad_host`, `bad_action`, `bad_nonce`,
    `expired`, `expiry_too_far`, `payload_mismatch`, `bad_signature`,
    `replay`, `not_enrolled`;
  - admission: `duplicate_job`, `agent_busy`, `agent_stopped`.

**`sysscript_job_sync`** has no `job_id`. Payload:
`{"active": ["sjb_..."], "unacked": [{"job_id": "sjb_...", "status": "succeeded"}]}`.
`active` holds the jobs the agent has queued or running, sorted.
`unacked` holds finished results not yet acked, in finish order. A job is
in exactly one of the two lists. The server refuses a sync with more than
1024 ids in total.

**`sysscript_alert`** from a job: `{"type", "job_id", "payload": {"severity",
"message", "truncated"?}}`.

- `severity` is `info`, `warning` or `critical`, and `message` is at most
  4096 bytes.
- The agent sends at most 20 per run.
- The server stores one only while the row is `accepted` or `running` on
  that host, at most 20 per job (`alert_count`). It opens an alert with
  `rule_name: "sysscript"` and writes a `sysscript_alert` audit row.
- A legacy script's alert carries `request_id` instead and takes the
  legacy path.

The server drops a frame it cannot use. It logs it and counts it in
`systemapi_job_frame_rejected_total{reason}`. Reasons: `bad_job_id`,
`bad_status`, `bad_sync`, `bad_severity`, `bad_message`,
`unknown_execution`, `rate_limited`, `no_tenant`, `late_reject_<status>` and
`flood`. A frame naming another host's job, or a job id the server does not
know, also writes a `job_frame_host_mismatch` or `job_frame_unknown`
security event. Each host gets at most 10 of a kind a minute, and the next
one written carries the count suppressed; host mismatches are never
limited.

## The sysscript_job lease

The canonical lease text, signed with the control plane's Ed25519 key, is
the same as every other action's:

```
systemapi-lease-v1\n<host_id>\n<action>\n<expires_unix>\n<nonce_hex>\n<payload_sha256>\n
```

For `sysscript_job`, `payload_sha256` is the hex SHA-256 of
`"sysscript_job\n" + payload`, where payload is five lines joined by `\n`,
with no trailing newline:

```
<job_id>
<deadline_unix>
<timeout_s>            1..3600
<script_sha256>        hex SHA-256 of the script's UTF-8 bytes
<entitlements_sha256>  hex SHA-256 of the canonical entitlements text
```

The agent rebuilds the payload from the frame's own fields: it hashes the
script and the canonical text of its own parse of `entitlements`. So a
changed byte of the script, a changed deadline, timeout or job id, or one
list item added to or flag flipped in the entitlements fails as
`payload_mismatch`. The nonce is consumed on success. A replayed start
frame for a job the agent still holds (running or kept result) is answered
with that job's status or result. Otherwise it is rejected `replay`.

## Canonical entitlements (v1)

The text is the line `systemapi-entitlements-v1`, then the 17 fields in
the agent's struct order. Every line ends with `\n`.

| Kind | Fields | Line(s) |
| --- | --- | --- |
| bool | `allow_exec`, `allow_containers`, `allow_k3s`, `allow_linux`, `allow_k8s` | `<name>=true` or `<name>=false` |
| paths | `allow_fs_write`, `allow_fs_read`, `allow_net_outbound`, `allow_config_write`, `allow_service_reload` | `<name>#<n>`, then n items |
| exact | `allow_packages`, `allow_images`, `allow_k3s_namespaces`, `allow_k8s_namespaces`, `allow_net_manage`, `allow_mount_targets`, `allow_sysctl` | `<name>#<n>`, then n items |

The field order is `allow_fs_write`, `allow_fs_read`, `allow_net_outbound`,
`allow_exec`, `allow_config_write`, `allow_service_reload`,
`allow_containers`, `allow_k3s`, `allow_linux`, `allow_k8s`,
`allow_packages`, `allow_images`, `allow_k3s_namespaces`,
`allow_k8s_namespaces`, `allow_net_manage`, `allow_mount_targets`,
`allow_sysctl`.

The text is built from what the agent's JSON decoding makes of the object:

- A bool is `true` only for JSON `true`.
- A list must be an array of strings. A `null` element becomes `""`. Any
  other element, or a value that is not an array (for example `true`),
  makes the list empty.
- Exact lists drop items that are empty, longer than 256 bytes, or contain
  `*`, `..`, NUL, CR or LF, and keep the first 32 left.
  `allow_sysctl` also drops `kernel.core_pattern`, `kernel.modprobe` and
  `kernel.hotplug`.
- Items are deduplicated and sorted by UTF-8 byte order.
- The server refuses (400 `bad_entitlements`, nothing signed) a list over
  64 items, an item containing CR or LF, or a string that is not
  well-formed. The agent refuses the same as `bad_entitlements`.

Example (vector `clamped_admin`). The input has `"allow_fs_read": true`,
which is not a list, so it counts 0. `allow_packages` is
`["nginx", "curl", "nginx"]` and `allow_sysctl` includes
`kernel.core_pattern`.

```
systemapi-entitlements-v1
allow_fs_write#0
allow_fs_read#0
allow_net_outbound#0
allow_exec=true
allow_config_write#0
allow_service_reload#0
allow_containers=true
allow_k3s=false
allow_linux=true
allow_k8s=false
allow_packages#2
curl
nginx
allow_images#1
nginx:1.27
allow_k3s_namespaces#0
allow_k8s_namespaces#1
default
allow_net_manage#1
eth0
allow_mount_targets#1
/mnt/data
allow_sysctl#2
net.ipv4.ip_forward
vm.swappiness
```

## Server state machine

Statuses: `submitted`, `accepted`, `running` (active), then `succeeded`,
`failed`, `cancelled`, `timed_out` (terminal).

Every agent-driven change goes through `transitionJob`. It updates the row
only when the row belongs to the frame's host and is in an allowed `from`
status. `from` may only hold active statuses, and nothing moves back to
`submitted`, so an ended row never changes again. When the guard fails,
the call returns nothing and the row is untouched.

| Change | Caused by | Notes |
| --- | --- | --- |
| (none) → `submitted` | submit: the API, `/execute`, `/fleet/execute`, playbooks, the scheduler, rule playbooks | `createJob` checks the caps (8 active per host, 64 per tenant) and writes the row, the `sysscript_job_submit` audit row and a `dispatch` event in one step. |
| `submitted`, dispatch claimed | the instance holding the presence socket | `markDispatched`: status unchanged; `conn_id` and `sent_at` set, payload removed. |
| `submitted` → `accepted` | agent status `accepted`; or a sync listing the job | The sync case: `reconcileHostJobs` moves listed active rows to the new `conn_id` and treats a listed `submitted` row as acknowledged. |
| `submitted`/`accepted` → `running` | agent status `running` | |
| active → terminal | agent result | End audit row with actor `agent`, then ack. |
| `submitted` → `failed[<code>]` | agent `rejected` result | |
| active, `cancel_requested_at` set | `POST /jobs/:id/cancel` by the submitter or a tenant admin | `sysscript_job_cancel` audit row and a `cancel` event. The job ends when the agent reports `cancelled`. A second request changes nothing. |
| `submitted` (never sent) → `cancelled[cancelled_before_dispatch]` | the same cancel, before dispatch | Cancel and end audit rows (end actor `system`). |
| `submitted` → `failed[dispatch_timeout]` | sweep | Payload still unclaimed 60 s after creation. |
| `submitted` → `failed[agent_no_ack]` | sweep | Sent more than 15 s ago on a connection held by the sweeping instance. A host whose job chain has been busy for less than 15 s is skipped. |
| active → `failed[result_lost]` | sweep | Deadline passed more than 60 s ago. |
| active → `failed[agent_lost_job]` | sync (`reconcileHostJobs`) | A row of this host sent on another connection that the new sync does not list. |

The sweep runs on every instance in the 30 s tick and ends at most 500 rows
per run, each with its end audit row (actor `system`). The same tick also
expires output and prunes old rows (retention, `api_docs.md`).

Every stored error is cut to 1024 characters, and output to 1 MiB of UTF-8
(`output_truncated` set). NUL becomes U+FFFD. The end audit row carries
only a code-shaped `error_code` (`agent_error` otherwise), never free text.

## Ordering, acks and sync

**Server side.**

- Each host has one ordered chain (`enqueue`). It runs the host's job frames
  from the agent, presence writes, and the server's own dispatch and cancel
  deliveries, one at a time.
- Agent frames count against the host's agent queue caps (4096 items,
  16 MiB). Over them the agent is disconnected (`flood`). Work the server
  starts is never refused.

**Events between instances.**

- `createJob` emits `dispatch`, a cancel request emits `cancel`, and every
  status change written with a notification emits `state`.
- With PostgreSQL they are `pg_notify` on channel `cp_sysscript_jobs`
  inside the writing transaction, so listeners see them only after COMMIT.
  MemoryRegistry delivers them in-process.
- `dispatch` and `cancel` are acted on only by the instance holding the
  host's socket. `state` wakes `wait_s` waiters.
- If a notification is lost, each tick's scan (`pendingForHosts`) delivers
  the pending dispatches and cancels for the hosts held there, counted in
  `systemapi_job_notify_fallback_total`.

**Acks.**

- The agent keeps each finished result until it is acked, at most 64
  results or 16 MiB; past that the oldest is dropped (logged).
- A kept result is sent when the job ends, and again after the sync on
  every new connection.
- The server writes a result once, because the transition guard refuses a
  second one. It acks every copy whose row has ended.

**Sync, on each connection.**

1. Once a connection has enrolled, the agent drops any frames still queued
   for the old connection.
2. It queues `sysscript_job_sync` on the control lane, then every kept
   result on the bulk lane. Frames emitted later queue behind them, so
   nothing overtakes the sync.
3. The server handles the sync on the host's chain:
   - an id it does not have for this host gets a cancel (`unknown`) and
     one `job_unknown_on_sync` security event per sync;
   - an ended job gets an ack if it is in `unacked`, and a cancel
     (`terminal`) if it is in `active`;
   - a job with a pending cancel gets the cancel again;
   - then `reconcileHostJobs` runs, and the pending dispatches and cancels
     are delivered.

**Lost frames.** A status or rejection emitted while the agent is
disconnected, or still queued when the connection drops, is lost. The
server learns of an accepted or running job from the next sync. It learns
of a refusal only through its own timeouts (`agent_no_ack`,
`dispatch_timeout`).

## Agent: workers, deadline, writer

- **Workers.** A fixed pool (`--sysscript-workers`, default 4, at most 16)
  plus a queue of 8 runs every script, jobs and legacy alike, off the read
  loop. When both are full, a script is refused `agent_busy` at once.
- **Deadline.** The effective deadline is the earliest of the signed
  `deadline_unix`, receipt + `timeout_s`, and receipt +
  `--sysscript-max-seconds`. It is measured on the monotonic clock from
  receipt, so clock skew can only shorten it. A deadline already past at
  receipt is rejected `bad_deadline`.
- **Duplicates.** A job id seen in the last 10 minutes is refused
  `duplicate_job`, unless the agent still holds that job; then it answers
  with the job's status or kept result.
- **Stopping a job.** Cancel or deadline: SIGTERM to the script's process
  group, then SIGKILL after 10 s. Shutdown ends every job `failed`
  `agent_stopped`.
- **Writer.** One writer goroutine sends every frame the job manager emits,
  one at a time. The read loop never writes. A job's frames are never
  reordered.
  - Two lanes share one queue. The control lane carries sync, `accepted`,
    `running` and rejections. The bulk lane carries results, alerts and the
    legacy `command_result`/`sysscript_alert` frames. The control lane is
    always written first, so a backlog of results cannot delay a new job's
    `accepted`.
  - The queue holds at most 512 frames and 24 MiB. Over that cap, a frame
    for the current connection closes the connection, and the next sync
    restores the state. A legacy frame, which is tied to the connection it
    came on, is dropped. Both are logged.
