# SAH test harness — design

Status: proposal 2026-10-23, for review (Christian Schreiber). Not implemented.
Author: Claude. Reviewer: Codex (first pass), then Christian.

## Where we are

Unit coverage is real: `systemapi.io` has ~19 `node --test` files (17 in the
`npm test` list; `bootstrap-pg` and `registry-pg` need a live Postgres and are
left out). The agent has ~10 Go `_test.go` files; `opensah` has `go test`.

But every channel test (`tcp`, `file`, `mesh`, `terminal`, `xfer`, `watch`,
`host-retire`) independently: mounts the control plane in-process
(`controlplane/router` `mount` + express + `MemoryRegistry` + `TEST_SEED`), and
reimplements its **own fake agent** in JavaScript to answer the wire frames the
way the Go agent would. Three gaps follow.

1. **No shared harness.** The server boot and the fake agent are copy-pasted per
   file. The JS fake agent is a hand-written model of the Go agent's protocol,
   and nothing keeps the copies — or the model and the real agent — in step.
2. **No real-agent end-to-end lane.** The server is only ever tested against the
   JS fake agent. A divergence between the Go binary and the JS model is
   invisible. The one real end-to-end check today is `sah-finish.sh`: a manual
   shell script that needs a human device login and a live host.
3. **No failure injection and no CI.** Network loss, an agent wedge, a lease
   expiring mid-session, and an audit sink that cannot write are not driven as a
   reusable facility, and nothing runs any of this automatically.

## Design

### Layer 1 — shared in-process harness (`tests/harness/`)
- `startControlPlane({registry, signer, now})` -> `{app, url, close}`: the
  express + `router.mount` + `MemoryRegistry` + `TEST_SEED` setup the channel
  tests duplicate, extracted once.
- One canonical `FakeAgent`, consolidated from the per-file copies, driven by a
  per-channel scripted response table (`tcp_open`->connected, file ops, mesh
  streams, sys verbs). Single source, so the model cannot drift between tests.
- `connectClient(purpose, binding)`: issues the ticket, opens the WebSocket,
  returns a framed client.
- Audit-chain assertions: row presence, order, and HMAC-chain continuity.

### Layer 2 — real-agent conformance lane (`tests/e2e/`, gated on a Go toolchain)
- `go build ./systemapi-agent`, enroll it against the in-process control plane
  over loopback, run the SAME scripted scenarios `FakeAgent` runs, assert
  identical observable behavior. This is the contract test that catches
  Go-vs-JS divergence — the thing the current split can't see.
- File channel needs Linux `openat2`: on macOS assert `agent_unsupported` (the
  contract), on Linux assert a real put/get/compare. This is `sah-finish.sh`
  step 6 turned into hermetic code.

### Layer 3 — failure injection (the network-down acceptance test, in software)
- Harness knobs: `killAgentSocket()`, `wedgeAgent()` (stop answering),
  `expireLease()`, `failAuditSink()`.
- Assert the fail-closed contract: a session ends on `recording_unavailable`;
  leases expire within `MAX_TTL_S` (300s); the agent redials with jittered
  backoff (`connection.go`); no access after a socket drop.
- This is the software half of the `sah-os-management` acceptance test
  ("simulate an agent wedge"). The `sah-service` recovery drill (Phase 3) layers
  on top once that daemon exists.

### Layer 4 — CI (none exists today)
- GitHub Actions: a Node job runs `npm test` + the Layer-1/3 harness; a Postgres
  service container runs the `-pg` tests; a Go job runs the agent `go test` and
  the Layer-2 conformance lane. Red blocks merge.

## Non-goals
- Not a replacement for the unit tests; the harness sits above them.
- Not a load or performance harness.

## Open for review
- Harness location (`tests/harness/` vs a small internal package).
- Layer-2 in CI on every push vs nightly (Go build cost).
- Audit-chain fixture: in-memory vs a throwaway Postgres.

## Revisions after Codex review (2026-10-23)

Codex endorsed the layered approach and the real-Go lane, and sharpened what the
layers must actually assert:

1. **Conformance is against independent golden vectors, not "the two impls
   agree."** Consolidating the fakes removes duplication, not shared
   misconceptions. Define the vectors once (frames, signatures, audit rows) and
   run BOTH the JS fake agent and the real Go agent against them. Cover the
   negative paths: signature rejection, lease replay, expiry, renewal binding,
   filesystem confinement (`openat2`/`RESOLVE_BENEATH`), and real process + socket
   cleanup -- not matching happy-path replies. A small Linux conformance suite
   runs on every PR; the wide fault matrix runs nightly.
2. **Socket closure is not a network-down test.** Add silent blackholes, one-way
   partitions, control-plane death, audit-DB loss while the WebSocket stays up,
   and a genuinely paused (SIGSTOP) agent. Assert: bounded shutdown on the host,
   no stale-session resurrection after reconnect, rejection of queued/expired
   commands after resume, and that the harness distinguishes agent failure from
   shared-network failure so a future watchdog does not restart-storm.
3. **Clock injection is explicit.** `startControlPlane({now})` alone does not
   control `Date.now()`, interval timers, or the Go agent's clock; inject a
   clock/scheduler on both sides for deterministic boundary tests plus a few
   real-process timing tests. `expireLease()` cannot retroactively invalidate an
   already-signed lease on another process -- deadlines are measured from the last
   accepted lease.
4. **`failAuditSink()` is split into two distinct faults:** agent PTY recording
   failure (-> `recording_unavailable`) and control-plane audit-chain failure.
   Test initial recording refusal, mid-session recording failure, and failed
   mutation-intent persistence independently, and assert no shell exec or mutation
   happens before its required durable record. Transaction-rollback and concurrent
   chain-append tests run against Postgres, not the memory registry.
5. **Add a deployed-system lane.** A disposable Linux VM running the real systemd
   units and the shipped hardening config: sshd off, agent wedged, sah-service
   restart/rollback, recovery verified by a real operation; recovery-daemon
   crash/reboot mid-break-glass; central audit unavailable. Loopback enrollment
   cannot catch systemd-sandbox regressions -- the openat2/`RestrictSUIDSGID` bug
   is the proof. Every scenario is pinned to the suite Wired join: a partially
   wired or unsupported channel has an explicit expected outcome (e.g.
   `agent_unsupported`), never fake-agent success counted as conformance.
