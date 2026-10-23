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

The agent exposes OS operations as Starlark Sysscript builtins, each gated by per-run entitlements and run under a signed lease with an audit-chain row: `sys.config.write`/`template` (atomic write via `config_manager.go`, `AllowConfigWrite` prefix list), `sys.packages.*` (install only, fixed argv, no shell, name regex plus exact grant), `sys.host`, `sys.net_proc`, `sys.containers`, `sys.k3s`, software inventory, `service`/`systemctl`. Capabilities `file`, `tcp`, `xfer` are probed and advertised; `service`/`config`/`package`/`tweak` are not yet capabilities.

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

**Spike (2026-10-23), sysctl-set only.** Implemented for the ONE verb to prove
the mechanism; the other tweak verbs (`sysctl-get` is a read and works;
`resource-limit-set` and `unit-override-set` still call the Phase 0 backend
directly) are intentionally left un-helper'd until the mechanism is validated on
a host.

- Agent side: `systemapi-agent/sysctl_helper.go` `sysctlSetViaHelper` writes a
  `{key,value}` request (0600, `O_EXCL`, `O_NOFOLLOW`) under
  `/var/lib/systemapi-agent/sysctl-helper/<id>.req`, triggers the unit, reads
  `<id>.res`, and cleans both up. One request per invocation, fresh random id.
- Helper side: the hidden `systemapi-agent __sysctl-helper <id>` subcommand
  re-checks the key against the same `sysctlKeyRE` and `deniedSysctl` set the
  channel uses and the value against `sysctlValueOK`, resolves the `/proc/sys`
  path (traversal-checked), writes, and records `{ok,error,errno}`. It trusts
  nothing from the caller and fails closed.
- Sandbox: committed in `systemd/sah-sysctl-helper@.service`. It is the agent's
  hardening **minus `ProtectKernelTunables`** and nothing else:
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths` limited to the
  handoff dir, no network, a short `RuntimeMaxSec`, a `CAP_NET_ADMIN
  CAP_SYS_ADMIN` bounding set. `PrivateNetwork` is deliberately **off** so
  `net.*` sysctls land on the host namespace, not a private one.

**Unverified host assumption this spike exists to test:** that the agent, under
its own sandbox (`NoNewPrivileges`, a restricted capability set), is actually
permitted to `StartUnit` the privileged helper unit over D-Bus. If PID 1's
policy refuses, the handoff + helper + committed unit stay correct and only the
trigger edge needs another mechanism.

**Wiring follow-up (separate branch):** `deploy/.../install-agent.sh` must
install `systemd/sah-sysctl-helper@.service` and run `systemctl daemon-reload`,
and reconcile its hardening set and `ExecStart` path with the agent's own
hardened unit.

## Open questions

- The Phase 3 recovery path (which option, or combination).
- Whether the `sys` channel is one multiplexed channel or per-resource, mirroring tcp/file/mesh.
- Team/org RBAC granularity for OS operations (per-resource scopes vs a single `sys:operator` scope).
