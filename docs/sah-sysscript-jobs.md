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

From the narrowest to the widest:

- **One host.** Restart its agent with `--sysscript-jobs=false`. It stops
  advertising the capability, and the server sends its scripts the legacy
  way. The agent's worker pool and deadlines still apply.
- **Every host.** Set `SYSTEMAPI_SYSSCRIPT_JOBS=0` on every server instance
  and restart them. Every caller goes legacy and `/jobs` answers 503. Jobs
  already submitted still run, end, and are stored and audited. While the
  switch is off, read them in the audit log; `GET /api/v1/jobs` answers 503.
- **An agent binary.** Rolling an agent back to a build without jobs ends
  the jobs it was running when it stopped. The old build never reports
  them, so the server ends each one `failed`/`result_lost` at its deadline +
  60 s (the sweep runs every 30 s). Rolling forward again instead ends them
  `agent_lost_job` at the new agent's first sync.

## After a killed package install

A job that times out or is cancelled kills its whole process group: SIGTERM,
then SIGKILL 10 s later. If that group was running `apt` or `dpkg`, the
package database may be left half-configured. On that host, run:

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
