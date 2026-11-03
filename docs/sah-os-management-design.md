# SAH OS-management design

Status: 2026-10-22, draft. This is a design, not a wired-state record. `docs/sah-suite.md` is the authority on what is actually wired; where this file and that one disagree about what exists today, that one wins. This file describes where the OS-management surface is going.

## Mission

Re-engineer the fleet for a web-first, agentic era. Operations run over HTTP and WebSocket through SystemAPI and the SAH tools, driven by agents and by humans through a web UI and CLIs, not over an operator's ssh session. The end state is that sshd can be turned off on a fleet host and nothing is lost.

## North star and acceptance test

ssh-off, zero capability loss. `--failback=ssh` is a migration crutch, not the destination.

Acceptance test for the whole program: pick one fleet host, disable sshd, and run a full ops day on it through SAH and the API alone, including a simulated agent wedge and a recovery that never touches ssh. If that passes, ssh-off is real.

## Two design centers

- **SystemAPI** is the agent-first, large-team and organization platform. Agents and ops teams drive it at scale through its own controls: operator scopes, purpose-scoped single-use tickets, Ed25519-signed leases, per-host and per-tenant policy, the PostgreSQL audit hash chain, and tenant/member/role RBAC. It does not depend on the farm door.
- **Farm tools** (vpscfgfarm, farmops) are the hybrid layer where agents and humans work together. The door's plan/approve/journal is the human-operations safety gate. It exists because the checking belongs in the door, not the operator, and it protects humans and agents alike.

The farm door is the human gate; SystemAPI carries the agent and team controls. `--connect=api` rides SystemAPI's governance directly. When a human operates through farmops, the farm tool adds its door gate on top. `--connect=api` never launders around the door for the human case; it changes the transport under the gate, not the gate.

## The ssh inventory (gap analysis organizing principle)

The design question is "what does the fleet do over ssh today, and what is the SAH equivalent," not "what OS verbs do we add." Current mapping:

| ssh use | SAH equivalent | State |
|---|---|---|
| interactive shell | `sahconnect` (recorded agent PTY) | wired |
| file transfer | `sahsync` (file channel), `sahxfer` (bulk UDP) | file wired; xfer half-wired |
| port access / forwarding | `sahlink`, `sahmesh` | wired |
| config / service / package / tweak | this work (Sysscript modules today, API next) | partial, Linux-centric |
| ad-hoc command across hosts | the farm door `vpsexec`, over raw ssh | **ssh-only today** |
| recovery when the agent is down | ssh shell | **no SAH answer (Phase 3)** |

Every row with no SAH answer is the real roadmap. The last two are the hard ones.

## Design principles (web-first, agentic)

- **Discoverable, not documented.** An agent enumerates a host: advertised capabilities, allowed operations, active policy, result schemas. Capability advertisement plus a catalog/schema endpoint are first-class.
- **Machine-first semantics.** Idempotent operations, structured per-host results, stable error codes, selector-based fleet actions. A human web UI is a view on the same calls, not a separate path.
- **Every action attributable.** Each call carries a principal (`oidc:<sub>`, `ak_live_…`) into a lease and the audit chain.
- **Guardrails are the enabling tech.** Scopes, leases, policy, and audit are what let an agent run the fleet without a human watching each call. The door is the human gate for the hybrid case.
- **The agent must be unwedgeable.** With ssh off, the agent is the only door. It must self-heal, survive its own upgrades, never apply a config that removes its own reachability, and advertise and health-check its capabilities so a missing channel is loud, not silent. The openat2/`RestrictSUIDSGID` incident (2026-10-22) is the cautionary tale: a hardening flag silently deleted the file channel. With ssh in place that is a nuisance; with ssh off it is a lockout.

## Current surface (grounded)

The agent exposes OS operations as Starlark Sysscript builtins, each gated by per-run entitlements and run under a signed lease with an audit-chain row: `sys.config.write`/`template` (atomic write via `config_manager.go`, `AllowConfigWrite` prefix list), `sys.packages.*` (install only, fixed argv, no shell, name regex plus exact grant), `sys.host`, `sys.net_proc`, `sys.containers`, `sys.k3s`, software inventory, `service`/`systemctl`. Capabilities `pty`, `file`, `tcp`, `xfer`, `service`, `config`, `package`, `tweak`, `sysscript_jobs` and `converge` are registered (`systemapi-agent/capabilities.go`, `platform.go`); most probes check presence, not function (planned: `.omc/plans/sah-fleet-readiness.md` P1).

Gaps: package support is `apt-get` and `dnf` only (no `yum`, `zypper`, `brew`); services assume systemd; deep paths are Linux (`file_helper_linux.go`, `host_linux.go`); macOS is PTY plus inventory; Windows is PTY only. OS management is reachable only by running a Sysscript, not as first-class API endpoints.

## Phases

**Phase 0 — platform abstraction in the agent (the floor).** A `platform/` package that detects OS family (`os-release` `ID`/`ID_LIKE` on Linux, darwin, windows) and exposes four backend interfaces: ServiceManager (systemd, launchd, openrc), PackageManager (apt, dnf, yum, zypper, brew), ConfigStore (atomic write, validate, reload), Tweaks (sysctl, resource limits, unit/launchd overrides). The existing `sys_*` modules call through it instead of hardcoding apt/dnf/systemctl. New probed capabilities `service`, `config`, `package`, `tweak` are advertised like `file`/`tcp`. Tests per backend, including the non-supported-platform path.

**Phase 1 — the API footprint (fleet-grade).** A new `sys` channel alongside tcp/file/mesh, with REST resources for the common verbs: services (status/start/stop/restart/enable/disable), packages (query/install/remove/upgrade), config (read/write/reload), tweaks (get/set). Fleet-grade from the start: bulk and selector-targeted operations (a service across a tagged group), idempotent machine-first results per host, per-team scoping and rate controls. Each operation rides a purpose-scoped lease, a per-host/tenant policy allowlist (the `file_policy` pattern extended to services, paths, packages), an intent row before every write, and audit rows after. A catalog/schema endpoint makes the surface discoverable.

**Phase 2 — farm connect and the door's API transport.** A `connect` interface in vpscfgfarm/farmops with two backends, `ssh` (today's door/executor) and `api` (SystemAPI REST), driving `--connect=ssh|api` and `--failback`. The door's plan/approve/journal runs over the API transport too, so ssh can be turned off while the human gate stays. A shared verb set maps to both transports; failback crosses between the agent-grade API path and the human-door path.

**Phase 3 — recovery and break-glass without ssh.** The precondition for ever disabling sshd. Options to design and choose among: a minimal independent watchdog/recovery agent that can restart or re-enroll the main agent; console/IPMI as the true last resort; a signed break-glass that re-enables sshd for a bounded window. Must be designed before sshd is disabled anywhere.

## Security

Config, service, package, and tweak writes are root-equivalent. `~/development/ads-fable-utils/SECURITY-RULES.md` is binding. Every mutation needs a Threats note and negative tests (rejects tampered, expired, oversized, wrong-key, out-of-policy input; fails closed). Policy allowlists are tightening-only. No write path lifts a `deny_extra`.

## Decisions (2026-10-22, reversible)

1. OS families first: RHEL (Rocky/CentOS/dnf+yum) and Debian (Ubuntu/apt). macOS second (launchd, brew). Windows deferred.
2. Tweaks v1: sysctl, resource limits, unit/launchd overrides. Kernel modules and firewall rules stay door-only until Phase 3 is solid.
3. API shape: REST resources for the common verbs; Sysscripts for complex multi-step logic.

## Finding 2026-10-23: the sysctl-set sandbox paradox, and the mutation helper

The agent is hardened with `ProtectKernelTunables=yes`, which makes `/proc/sys`
read-only for the agent process. That is correct for an unwedgeable agent (a
compromised agent must not be able to rewrite kernel tunables at will). But it
also means the agent **cannot** satisfy `sys:tweak sysctl-set` by writing
`/proc/sys` itself: the write fails closed inside its own sandbox. The same
tension will recur for any verb that mutates a resource the agent's sandbox
protects.

Options considered:

1. **Widen the agent's own sandbox** (drop `ProtectKernelTunables`). Rejected:
   it hands every agent code path — terminal, file, package, Starlark — the
   power to write any kernel tunable. One hardening knob would protect nothing.
2. **Privilege-separated mutation helper (chosen).** A separate, minimally
   scoped helper does the write. Its sandbox is the agent's **minus exactly the
   one protection the verb needs**, and that sandbox lives in a **committed
   per-verb systemd unit**, not constructed by the agent at runtime. The agent
   gates the request (lease + policy) exactly as before, then triggers the
   helper through systemd's manager (the same `StartUnit`/job-wait access it
   already uses to restart a service) passing only a request id. The helper
   re-validates the request independently and performs the write. Both the
   confinement and the re-validation are outside the agent's trust in the
   caller.
3. A long-lived privileged side-process. Rejected for v1: a persistent
   privileged daemon is a larger standing target than a one-shot unit that
   exists only for the duration of a single write.

**Spike (2026-10-23), sysctl-set.** Implemented for the ONE verb first to prove
the mechanism; `sysctl-get` is a read and still calls the Phase 0 backend.

- Agent side: `systemapi-agent/sysctl_helper.go` `sysctlSetViaHelper` writes a
  `{key,value}` request (0600, `O_EXCL`, `O_NOFOLLOW`) under
  `/var/lib/systemapi-agent/sysctl-helper/<id>.req`, triggers the unit, reads
  `<id>.res`, and cleans both up. One request per invocation, fresh random id.
- Helper side: the hidden `systemapi-agent __sysctl-helper <id>` subcommand
  re-checks the key against the same `sysctlKeyOK` shape (dot-separated
  non-empty segments, so `kernel.core_pattern.` or `kernel..core_pattern` can
  never clean onto a denied file) and `sysctlDenied` list the channel uses and
  the value against `sysctlValueOK`, resolves the `/proc/sys` path
  (traversal-checked, then mapped back to a dotted key that must equal the
  input and is deny-checked again), writes, and records `{ok,error,errno}`. It
  trusts nothing from the caller and fails closed.
- Sandbox: committed in `systemd/sah-sysctl-helper@.service`. It is the agent's
  hardening **minus `ProtectKernelTunables`** and nothing else:
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths` limited to the
  handoff dir, no network, a short `TimeoutStartSec` (`RuntimeMaxSec` is ignored for
  `Type=oneshot`), a `CAP_NET_ADMIN
  CAP_SYS_ADMIN` bounding set. `PrivateNetwork` is deliberately **off** so
  `net.*` sysctls land on the host namespace, not a private one.

**Extended (2026-10-23) to the other bounded write verbs**, following the sysctl
spike as the exact template, under the SAME unverified host assumption (below):

- `sys:config write` — `systemapi-agent/config_helper.go` `configWriteViaHelper`
  writes a `{target,content,lease}` request, triggers `sah-config-helper@.service`,
  reads the result, cleans up. The hidden `systemapi-agent __config-helper <id>`
  subcommand re-validates the target against the same `rootShapeOk` the channel
  uses, independently refuses the agent/server self-roots (`configSelfRoots`, the
  Go copy of the control plane's `CONFIG_SELF_ROOTS`, so the config channel can
  never rewrite the agent's own config; it also covers the helpers' replay store
  `/var/lib/sah-helper`, the trust file, the agent's unit, `/etc/ld.so.preload`,
  `/etc/systemd/system.conf(.d)` and, by pattern, the
  `sah-*-helper@` units and any drop-in dir under `/etc/systemd/system` or
  `system.control` that applies to them; `controlplane/testdata/config-self-vectors.json`
  keeps the Go and JS lists in parity), verifies the signed lease itself (see
  below), and does an atomic write (temp file, fsync, rename relative to a
  parent opened with `openat2(RESOLVE_NO_SYMLINKS)`, so no symlinked parent). Its sandbox is the agent's with the ONE relaxation `ReadWritePaths=/etc`
  (`ProtectSystem` stays strict; `ProtectKernelTunables` stays `yes`), caps
  `CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE`.
- `sys:tweak resource-limit-set` and `unit-override-set` — both write a drop-in
  at `/etc/systemd/system/<unit>.d/<name>.conf`, so ONE helper
  (`systemapi-agent/systemd_override_helper.go`, unit
  `sah-systemd-override-helper@.service`) serves both. The hidden
  `systemapi-agent __systemd-override-helper <id>` subcommand re-validates the
  unit (`serviceNameRE`) and, per kind, the resource-limit directive/value
  (rebuilding the body itself) or the override name/body (bound by its SHA-256
  in the lease, which the helper verifies itself), refuses the agent's and the
  helpers' own units and any top-level or prefix drop-in that applies to them
  (`configSystemdSelfEntry`; `--tweak-unit` refuses the same names), pins the
  path under `/etc/systemd/system`, and writes atomically. Its
  sandbox's ONE relaxation is `ReadWritePaths=/etc/systemd/system`, same caps as
  the config helper, `ProtectKernelTunables` stays `yes`. It does NOT run
  `systemctl daemon-reload` — the Phase 0 backend did not either; activating the
  drop-in is a separate step and a follow-up.

Package install/remove, the reads, and `config reload` are deliberately left on
their existing paths.

**Helper-side lease check (2026-10-26).** The first cut above had each helper
re-check only shape and a content hash the agent itself supplied, so a
compromised agent could ask a helper to write any shape-valid target (e.g.
`/etc/sudoers`). Each helper now authorizes the write on its own
(`systemapi-agent/helper_auth.go`): the request carries the original signed
lease; the helper loads the control-plane public key and host id from
`/etc/systemapi-agent/helper-trust.json` (root-owned, not group/other writable,
no symlink, in a root-owned non-writable dir; read-only to the agent under
`ProtectSystem=strict`; NOT the agent-writable `agent.json`), rebuilds the
payload from the exact target/key/unit and the hash it computes over the
content, runs `verifyLease` (signature, host, action, expiry/skew, payload),
and consumes the nonce once in `/var/lib/sah-helper/consumed`, a durable,
bounded store in the helpers' own `StateDirectory` that survives a restart.
Every failure is a recorded result code (`lease_missing`, `lease_<reason>`,
`trust_unavailable`, `replay`, `replay_store`). The trust file is an install
step, `scripts/provision-helper-trust.sh --pubkey <key> --host-id <id>` (see
the helper units); until it exists every helper write fails closed. The
control-plane key it installs is the trust anchor for every helper write, so it
must be an out-of-band pinned value (the install bundle, or read by the
operator from the control plane), never copied from `agent.json`, which the
agent can write. The script cross-checks the pinned key and the (required,
also pinned) `--host-id` against `agent.json`, refuses on a mismatch, refuses a symlinked trust
file, trust dir or state file, and writes `0644 root:root` through a same-dir
temp file and rename. `loadHelperTrust` checks only the trust file and its
immediate directory, so `/etc` itself must stay root-owned and not
group/other writable.
This boundary holds only with the hardened agent unit: an unsandboxed root
agent can edit `/etc` and the replay store directly.

**Limit: not a boundary against a compromised agent today (security review
finding 1, open owner design decision).** The sandbox confines the agent's OWN
file operations only. The agent runs as root with access to systemd's manager
over D-Bus (that is how it restarts services and triggers the helpers), and
PID 1 is outside every sandbox. A compromised agent can therefore start or
create a unit with no sandbox (for example a transient unit through
`StartTransientUnit` / `systemd-run`) and act as unconfined root, bypassing the
helpers, their lease check, the trust file and the replay store entirely. So
while the agent is root with systemd bus access, the mutation helpers are NOT a
security boundary against a compromised agent: they keep every legitimate write
lease-checked and confine bugs and an attacker limited to the agent's request
files, nothing more. Making them a real boundary needs the agent's manager
access narrowed (for example a non-root agent with a polkit rule that allows
only `StartUnit` of the `sah-*-helper@` instances and the service verbs it
needs, or an equivalent bus filter); that choice is the owner's and is not made
here.

In the same vein, the self-root deny list is not a complete fence around the
agent: a config-write grant under `/etc` can still reach the agent and helpers
indirectly, for example through `/etc/systemd/system.conf.d` (manager-wide
`DefaultEnvironment` and friends), `/etc/ld.so.preload` (loaded into every
dynamically linked process) or a unit placed in a `*.wants` directory. The two
cheap, clearly agent-affecting ones, `/etc/ld.so.preload` and the system
manager config (`/etc/systemd/system.conf`, `/etc/systemd/system.conf.d`), are
now self-roots on both sides (shared vectors); `user.conf(.d)` is left alone
because user managers run neither the agent nor a helper. Paths like
`*.wants`, `ld.so.conf.d`, PAM, cron and sudoers stay reachable by any `/etc`
grant that covers them, so a `--config` grant must be treated as root-equivalent
for the subtree it names, consistent with the finding-1 decision above.

**Unverified host assumption these helpers exist to test:** that the agent, under
its own sandbox (`NoNewPrivileges`, a restricted capability set), is actually
permitted to `StartUnit` a privileged helper unit over D-Bus. If PID 1's
policy refuses, the handoffs + helpers + committed units stay correct and only the
trigger edge needs another mechanism.

**Wiring follow-up (separate branch):** `deploy/.../install-agent.sh` must
install `systemd/sah-sysctl-helper@.service`,
`systemd/sah-config-helper@.service` and
`systemd/sah-systemd-override-helper@.service`, run `systemctl daemon-reload`,
and reconcile each unit's hardening set and `ExecStart` path with the agent's own
hardened unit.

## Open questions

- The Phase 3 recovery path (which option, or combination).
- Whether the `sys` channel is one multiplexed channel or per-resource, mirroring tcp/file/mesh.
- Team/org RBAC granularity for OS operations (per-resource scopes vs a single `sys:operator` scope).

## Phase 2 — transport seam and the exec decision (recon 2026-10-22)

The ssh transport is a single seam: `vpscfg/executor.py`, `subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, cmd], ...)` at ~line 160 and ~203. `--connect=ssh|api --failback=...` abstracts that into a transport interface with two backends: `ssh` (today) and `api` (a SystemAPI sys-channel client). farmops is an F0 skeleton (catalog loader + journal only; the runner, scheduler and CLI are later workstreams), so the transport belongs in vpscfgfarm's executor, consumed by farmops once its runner exists.

THE DECISION that gates ssh-off: the sys channel exposes structured verbs (service/package/config/tweak), not an arbitrary shell. vpsexec's core use is running an arbitrary, gated command string. So `--connect=api` naturally covers only operations that map to a sys verb. vpsexec's arbitrary-command path has no API equivalent. Two ways to close it:
  (a) add a general `sys:exec` verb — an arbitrary command run under a signed lease and a per-host command allowlist. Powerful, and the security crux of the whole program: it is the one surface that can do anything, so it must be the most tightly policy-bound.
  (b) express every door operation as a structured verb or a committed runbook, and keep ssh only for break-glass.
Recommendation: (b) as the default, plus a narrow, deny-by-default `sys:exec` scoped to the exact committed runbook commands that cannot be expressed as a structured verb — decided per command, never a blanket shell. This keeps the "checking in the door" thesis: the API transport runs only what policy named, the same as the door.

## Phase 3 — recovery without ssh (options for decision 2026-10-22)

The precondition for ever disabling sshd. With ssh off the agent is the only door, so a wedged agent must have a way back that does not need the thing that is wedged. Options:
1. Watchdog / recovery agent: a second, minimal, independently-supervised process (its own systemd unit and key) that can restart or re-enroll the main agent, and under a signed grant re-enable sshd for a bounded window. In-band, no hardware; cost is another privileged surface, and if both wedge you are stuck.
2. Out-of-band console (provider KVM / IPMI / serial): the true last resort, survives total software failure; depends on what the VPS provider offers, and is manual and slow. NEED TO KNOW: what console does the provider give these hosts.
3. Signed, time-boxed sshd break-glass: the agent (or the watchdog) accepts a signed, expiring command that turns sshd back on for a window. Reuses the lease model; useless if the agent itself is the wedged thing.
Recommendation: build 1 (watchdog) + 3 (signed sshd break-glass) as the in-band pair, and document 2 (provider console) as the true last resort. Do not disable sshd anywhere until this is built and drilled (the acceptance test includes a simulated wedge + recovery).

## Decisions 2026-10-22 (night): exec model and recovery

- Phase 2 exec: option (b). Structured verbs cover `--connect=api`; a narrow, deny-by-default `sys:exec` is bound to the exact committed runbook commands that cannot be expressed as a structured verb, decided per command. No blanket shell over the API.
- Phase 3 recovery: option 1, realized as a dedicated **sah-service**. This replaces the dependency on a provider console (option 2); option 2 (provider KVM/IPMI/serial) stays documented only as the absolute last resort for when both the agent AND sah-service are dead. Option 3 (signed sshd break-glass) becomes a capability sah-service exposes, not a separate thing.

## sah-service — the recovery daemon (Phase 3)

A second, minimal daemon on each host, independent of the main `systemapi-agent`, whose only job is to keep a way in when the agent is wedged and ssh is off. Ryan's idea, 2026-10-22.

Properties (all load-bearing — this is the thing that must not fail when everything else does):
- Its own systemd unit, its own enrollment key, and the fewest dependencies possible (prefer a static binary with no shared surface with the agent, so a bad agent build or a hardening-flag regression like the openat2 one cannot take it down too).
- More conservative than the agent it guards: it does not self-update in any way that can brick it, and it never applies a config that could remove its own reachability.
- Watchdog role: detect the main agent crashed, wedged, or un-enrolled, and restart or re-enroll it.
- Recovery role, each a narrow signed capability (not a general runner): roll the agent back to its `.prev` binary; pull and install a fresh agent build; re-enable sshd for a signed, time-boxed window (the former option 3); report its own and the agent's health.
- Security: its own scopes (e.g. `recovery:*`), signed grants, audit rows, deny by default. It must be strictly less capable than a shell — recovery verbs only, no arbitrary exec — so it is a smaller attack surface than the agent, not a bigger one. SECURITY-RULES.md binds it.
- It is SAH's own out-of-band lifeline, so the fleet does not depend on a provider console. The provider console is the last resort only if both the agent and sah-service are dead.

Open for Ryan to shape: the name (`sah-service`), whether it rides the existing control plane on its own channel or a separate minimal endpoint, and how its key is provisioned so it survives an agent re-key.

## Finding 2026-10-23: the agent sandbox blocks the write verbs (and the mutation-helper decision)

Deploying the full verb set to miniapps1 and testing it live surfaced the real constraint. The agent's systemd unit is hardened for its original read/PTY/file/tcp role:
```
ProtectSystem=strict     # whole FS read-only except ReadWritePaths
ReadWritePaths=/var/lib/systemapi-agent /var/tmp/sah-filetest /home/sahuser
ProtectKernelTunables=yes  # /proc/sys read-only
```
Live results against that sandbox:
- Work: `sys:service` all actions (systemd over D-Bus, not an FS write — restart proven), and every read (`sysctl-get`, `config read`, `package query`).
- Blocked: `sys:tweak sysctl-set` (writes /proc/sys), `sys:config write` to a real path like /etc (ProtectSystem=strict), `sys:tweak` resource-limit / unit-override (write /etc/systemd), `sys:package install`/`remove` (write /var/lib/dpkg, /usr).

The channels, leases, policy allowlists and audit all work; the agent's own sandbox blocks the mutations. That is defense-in-depth working, not a bug. The verbs are built and policy-correct but their write paths cannot execute until this is resolved.

DECISION (Ryan, 2026-10-23): option 2, a privilege-separated mutation helper. NOT option 1 (loosening the always-on agent's sandbox), which would turn the agent into an unhardened root process with only the lease as a gate.

Architecture subtlety: a forked child does NOT help. ProtectSystem=strict and ProtectKernelTunables are mount-namespace properties the agent's children inherit, so a child is as walled off as the agent (the existing file-helper only writes inside ReadWritePaths; it never escapes). The mutation helper must therefore be privilege-SEPARATED: a distinct unit created by pid 1 (the agent asks systemd, as it already does for service control and as sah-finish.sh did via `systemd-run`), with its own write-capable but tightly-scoped sandbox, that performs exactly one lease-bound mutation and exits. The agent never holds the broad write capability; NoNewPrivileges on the agent does not stop this, because pid 1 does the spawning.

Shape (to settle before building):
- Per-verb FIXED sandboxes, committed and reviewed, NOT sandboxes the agent constructs at runtime (an agent that can choose a transient unit's sandbox is itself an escape surface). Each verb's helper gets only what it needs: sysctl-set → a unit without ProtectKernelTunables running `sysctl -w <key>=<value>`; config-write → ReadWritePaths scoped to the one allowed dir; unit-override/resource-limit → ReadWritePaths=/etc/systemd/system; package install/remove → the package manager's required paths. Fixed argv, no shell, the lease binds the exact parameters, the per-host deny-by-default policy is unchanged.
- Open choice: one committed helper unit per verb (most auditable) vs the agent calling `systemd-run` with a per-verb fixed parameter set (fewer moving parts, but the parameter construction must be constrained so it cannot be widened). Recommendation: committed per-verb helpers, so the sandbox lives in the door/repo and not in agent-constructed arguments.
- Must confirm the agent is allowed to StartTransientUnit / reach the helper over D-Bus under its current scoping (service restart working suggests manager access, but creating units is a separate permission to verify on the host).

## sah-service — detailed spec (Phase 3 recovery daemon), 2026-10-23

Build-ready spec written during the autonomous run. Two shape calls (marked DECISION) are deliberately left for Ryan; everything else is settled here.

### Purpose and the one hard requirement
sah-service is the independent way back into a host when the main agent is wedged and sshd is off. Its one hard requirement: it must not share a failure mode with the agent. A bad agent build, a hardening regression (the openat2/ProtectKernelTunables class), a crash loop, or a lost enrollment must leave sah-service standing and able to recover the agent. Everything below serves that.

### Independence
- Its own binary (not a subcommand of systemapi-agent — a shared binary shares a bad build). Small, statically linked, few deps.
- Its own systemd unit, its own enrollment key and host identity row, its own StateDirectory. It does NOT read the agent's config, key, or state.
- Conservative to a fault: it never self-updates in a way that can brick it (an update installs beside the running one and is adopted only after it proves healthy), and it never applies a config that could remove its own reachability.
- Minimal, fixed sandbox. It is strictly less capable than a shell: recovery verbs only, no arbitrary exec. Smaller attack surface than the agent, never bigger.

### Capabilities (all narrow, signed, deny-by-default, audited)
1. health — report its own and the agent's status (unit state, last enrollment, last heartbeat). A read.
2. agent-restart — `systemctl restart systemapi-agent`. 
3. agent-rollback — restore the agent's `.prev` binary and restart (the mutation-helper deploys already keep `.prev`).
4. sshd-break-glass — re-enable sshd for a signed, time-boxed window, then auto-disable. THE risky one; see gating below.
It is NOT a general runner. No config/package/sysctl writes, no shell. If a recovery needs more than these verbs, that is a human-at-console event, not a sah-service action.

### Watchdog
sah-service watches the agent: systemd unit state plus a liveness signal (the agent writes a heartbeat file, or sah-service probes the agent's health). On "wedged" (crash-looping, or enrolled-but-not-reconnecting past a threshold), it escalates: restart, then if that fails rollback, then raise an alert. Thresholds and backoff are committed config, not runtime-tunable by the agent.

### The sshd break-glass (the sharp edge)
Re-enabling sshd is the capability that makes ssh-off safe to attempt, and the one most worth abusing. Gating: a signed, short-TTL grant (minutes), single-use, that names the host; sah-service enables sshd, starts a timer, and disables it again at expiry even if nothing else happens (fail-safe to closed). Every enable/disable is an audit-chain row. The grant is issued the same way a lease is, from the control plane, under an admin scope distinct from the operator scopes (`recovery:sshd`). Losing the control plane must not leave sshd stuck open: the auto-disable timer is local to sah-service.

### DECISION 1 (Ryan): transport
Does sah-service ride the existing control plane on its own recovery channel, or stand on a separate minimal endpoint? Recommendation: its own channel on the existing control plane (reuses enrollment, lease signing, audit chain, RBAC — less new surface), but with its own key and its own scopes so a compromised agent credential cannot drive recovery. A separate endpoint only if we want recovery to survive the main control plane being down, which argues for a second, tiny control surface — more robust, more to build and secure.

### DECISION 2 (Ryan): key provisioning across an agent re-key
sah-service's key must survive an agent re-key (the agent's key was retired once already this project). Options: (a) provisioned once at host bring-up and never tied to the agent's lifecycle; (b) a sub-identity the control plane mints for the host that both the agent and sah-service derive from but hold separately. Recommendation: (a) — a standalone enrollment minted at install, rotated on its own schedule, with zero coupling to the agent's key, so retiring/rekeying the agent never touches recovery.

### Build phases (once the two decisions land)
0. The daemon skeleton: own binary, own unit, enrollment, health verb, heartbeat/watch of the agent (no mutations yet). Deployable and observable first.
1. agent-restart + agent-rollback verbs (reuse the .prev convention).
2. sshd break-glass with the local auto-disable timer and the `recovery:sshd` scope.
3. The acceptance test: disable sshd on one host, simulate an agent wedge, and recover through sah-service alone.

Until phase 3 passes and is drilled, sshd stays on everywhere.
