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
