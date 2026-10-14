# Project Research Summary

**Project:** SystemAPI.io v2.0 - Next-Gen Systems Management
**Domain:** Fleet systems management platform (Ansible/Terraform alternative)
**Researched:** 2026-04-28
**Confidence:** HIGH

---

## Executive Summary

SystemAPI.io v2.0 transforms an already-working WebSocket-agent-plus-Starlark-engine into a credible Ansible/Chef/Puppet replacement by adding nine new `sys.*` modules (packages, services, process, network, fs-extended, containers, events, security, alerts) and a declarative convergence engine backed by a per-host BoltDB state store. The foundation is sound: pure-Go static binary, entitlement-sandboxed Starlark, outbound-only WebSocket - no inbound ports, no Python, no control node. The v2.0 scope is executable in seven ordered phases without changing that architecture.

The single hardest constraint is CGO. YARA scanning is the only capability that requires CGO (via `github.com/hillu/go-yara/v4`), and that constraint breaks the static-binary cross-compilation build for all five targets. The correct resolution is a split-binary strategy: the base agent stays `CGO_ENABLED=0` pure-Go; a separate `systemapi-agent-security` variant is compiled with `-tags yara_full CGO_ENABLED=1` and distributed only where YARA is needed. Every other new capability (containers, packages, services, events, process, network, state store) is pure Go and preserves the single-binary constraint.

Before a single line of v2.0 feature code is written, four prerequisites must land: (1) a serialized WebSocket write goroutine (concurrent writes corrupt frames), (2) build-tag isolation for YARA so `CGO_ENABLED=0` CI continues to pass, (3) a redesigned Entitlements struct that covers all nine new module gates, and (4) the `changed: bool` return contract on every new builtin. These are retrofitting disasters if deferred.

---

## Key Findings

### Stack Additions

All new capabilities except YARA are pure Go. Seven new library additions plus one upgrade:

**New dependencies (pure Go):**
- `github.com/docker/docker/client` v28.5.2 - Docker lifecycle via Unix socket/named pipe. Note: 2 known CVEs at research time; run `go vuln` before Phase 5 ships.
- `github.com/google/go-containerregistry` v0.21.5 - OCI registry pull/push without a running daemon.
- `github.com/coreos/go-systemd/v22/dbus` v22.7.0 - systemd control via D-Bus. Import ONLY the `dbus` subpackage. `sdjournal` is CGO and must never be imported.
- `github.com/godbus/dbus/v5` v5.2.2 - transitive dep of go-systemd; may be needed directly for subscription/watch.
- `github.com/fsnotify/fsnotify` v1.9.0 - inotify/kqueue/ReadDirectoryChangesW. No native recursive watch; must manually add subdirs.
- `go.etcd.io/bbolt` v1.4.3 - embedded ACID key/value store for per-host state. Chosen over mattn/go-sqlite3 (CGO) and JSON files (no atomicity).

**Upgraded dependency:**
- `gopsutil/v3` -> `gopsutil/v4` v4.26.3 - covers telemetry, sys.process, sys.network, and platform detection. Same pure-Go, no-CGO guarantee. Import paths change from `.../v3/...` to `.../v4/...`.

**CGO-gated (security binary only):**
- `github.com/hillu/go-yara/v4` v4.3.4 - wraps libyara C library. No pure-Go YARA engine exists. `gyp` parses YARA rules but cannot execute them. Requires GCC + libyara headers at build time. Windows requires MSYS2/MinGW.

**Two-binary decision:** Base agent (`systemapi-agent`) builds with `CGO_ENABLED=0`, passes all five cross-compilation targets. Security agent (`systemapi-agent-security`) builds with `-tags yara_full CGO_ENABLED=1`, initially Linux/amd64 only. These are separate release artifacts.

**No library needed:** Package management (os/exec to dnf/apt/brew/winget), macOS service management (os/exec to launchctl), Windows service management (x/sys/windows/svc/mgr - already indirect dep via gopsutil).

### Expected Features

**Must have (table stakes for Ansible replacement):**
- `sys.alerts.push` as real WebSocket push - foundational; every feature that emits events depends on this. Currently logs to stdout.
- `sys.packages` - install/remove/check/list across dnf, apt, brew, winget with non-interactive flags and 5-minute context deadlines.
- `sys.services` - start/stop/enable/disable/status/list across systemd, launchd, Windows SCM.
- `sys.fs` extended - stat, glob, mkdir, rm, chmod, chown, diff (stdlib only, low effort).
- Declarative convergence mode - idempotent execution, dry-run preview, per-item `changed: bool` report, execution diff output.
- Drift detection - record desired state in BoltDB, compare on schedule, alert on divergence, one-click convergence.

**Should have (competitive differentiators):**
- `sys.process` - list, kill, signal, info (gopsutil already in go.mod, minimal effort).
- `sys.containers` - run, stop, list, exec, logs, pull, rm, images (Docker socket, pure Go, existing frontend stub).
- `sys.security` - YARA file scan + CVE matching via OSV API. Memory scanning deferred to v2.1.
- `sys.events` - real inotify/kqueue watcher replacing the current stub (enables reactive automation without polling).

**Defer to v2.1:**
- Firewall rule mutations (read-only query for v2.0).
- Memory scanning on macOS/Windows (requires code signing / privilege configuration).
- ETW-level process/network tracing on Windows.
- Kubernetes / pod management (out of scope per PROJECT.md).

### Architecture Approach

The extension model is additive: new `.go` files per capability, build-tag isolation for platform splits and CGO, extension of existing structs, new cases in existing dispatch switch. No v1.0 code paths broken. Key structural additions:

**Major new components:**
1. `state_store.go` - BoltDB wrapper. `SaveConvergenceState`, `GetConvergenceState`, `SaveDriftReport`, `GetPendingDriftReports`. Flushes pending drift on WebSocket reconnect.
2. `convergence.go` - wraps `SysscriptEngine.Execute()` with pre/post state snapshot, diff computation, BoltDB write. Dispatched by `sysscript_convergent` command type.
3. Platform-split service files - `sys_services_linux.go` / `sys_services_darwin.go` / `sys_services_windows.go`. Same function signatures, different backends.
4. Build-tag-split security files - `sys_security_stub.go` (build `!yara_full`) / `sys_security_yara.go` (build `yara_full`).
5. WebSocket write serializer - single writer goroutine with buffered channel. All output paths funnel through it. This is a prerequisite fix for v1.0 architectural debt.
6. FleetManager extensions - new message handlers, `pushCommand` generalization, new REST routes (`routes/convergence.js`, `routes/security.js`, `routes/containers.js`).

**New wire protocol types:**
- Server -> Agent: `sysscript_convergent`, `security_scan`, `containers_op`
- Agent -> Server: `convergence_result`, `drift_report`, `security_scan_result`, `containers_result`, `service_op_result`, `package_op_result`, `event_notification`

**New PostgreSQL tables:** `host_convergence_state`, `host_drift_reports`, `host_security_scans`.

### Critical Pitfalls

Full analysis in `.planning/research/PITFALLS.md` (15 pitfalls, 7 critical).

**Top 5 most dangerous:**

1. **WebSocket concurrent write corruption** - gorilla WebSocket allows one concurrent writer. Telemetry ticker + any async Sysscript goroutine writing simultaneously corrupts the frame stream. Fix: single write goroutine + buffered channel. Must be fixed BEFORE any async feature ships. This is v1.0 architectural debt.

2. **YARA CGO breaks all cross-compilation** - `CGO_ENABLED=0` is global to the entire build. One CGO import fails all five target builds. Fix: `//go:build yara_full` / `//go:build !yara_full` tag isolation in separate files before writing a single line of YARA code. Decide Windows YARA scope upfront.

3. **Docker socket is a host root escalation path** - `/var/run/docker.sock` write access lets a Sysscript mount `/` inside a container. Fix: Entitlements must include image allowlist and `Privileged: false` enforcement before implementing `sys.containers.*`. Probe socket path from `DOCKER_HOST` -> rootless -> default; never hardcode.

4. **`changed: bool` missing causes destructive convergence reruns** - without this contract, convergence engine re-applies every time (restarts intentionally stopped services, overwrites hotfixes). Fix: establish the contract before building the state store. Retrofitting after five modules are built requires touching every builtin.

5. **Package manager blocks on interactive prompts** - `apt-get` without `-y` waits for Y/n; brew refuses to run as root; winget requires elevation. A blocking subprocess hangs the WebSocket goroutine. Fix: non-interactive flags, `exec.CommandContext` with 5-minute deadline, privilege detection before invocation.

---

## Implications for Roadmap

Seven phases derived from the dependency graph across all four research files:

### Phase 1: Prerequisites and Foundation
**Rationale:** Four global prerequisites must exist before any feature code - the WebSocket write serializer (affects every async feature), Entitlements redesign (affects every new builtin), build-tag scaffold for YARA (affects CI for the entire project), and `changed: bool` return contract (affects every new module and the state store). None can be retrofitted cheaply.
**Delivers:** Serialized WebSocket write goroutine; expanded `Entitlements` struct (all v2.0 gate fields); `CommandMessage` / `ResponseMessage` struct additions; YARA build-tag scaffold (`!yara_full` stub); `changed: bool` return type convention; `state_store.go` BoltDB wrapper; new PostgreSQL schema tables; `pushCommand` generalization in FleetManager; `sys.alerts.push` real WebSocket push.
**Avoids:** Pitfalls 6, 7, 10, 13 (entitlement model, destructive reruns, CGO build breakage, WebSocket corruption).

### Phase 2: Pure-Go System Primitives
**Rationale:** gopsutil is already in go.mod. These four modules use `os/exec` patterns established in `software.go`. Zero new CGO risk. No inter-dependencies. Delivers `sys.process`, `sys.fs` extended, `sys.network`, and `sys.packages` in one phase.
**Delivers:** `sys.process` (list/kill/signal/info via gopsutil/v4); `sys.fs` extended (stat/glob/mkdir/rm/chmod/chown/diff - stdlib); `sys.network` (interfaces/connections/listening ports - gopsutil + os/exec for firewall read); `sys.packages` (install/remove/check/list - dnf/apt/brew/winget with non-interactive flags and context deadlines).
**Uses:** gopsutil/v4 upgrade (same effort benefits both telemetry and all new modules).
**Avoids:** Pitfall 3 (package manager blocking), Pitfall 15 (PATH-only package manager detection - probe absolute paths).

### Phase 3: Service Management (Platform-Split Pattern)
**Rationale:** Establishes the `sys_services_*.go` multi-file build-tag pattern that security scanning also needs. go-systemd/dbus and godbus/dbus are new pure-Go dependencies; cross-compile verification required before the CGO security variant is attempted.
**Delivers:** `sys.services` across systemd (D-Bus), launchd (os/exec), Windows SCM (x/sys/windows/svc/mgr); D-Bus unavailability fallback to `systemctl` subprocess; `GOOS=windows go build` cross-compile verification.
**Uses:** go-systemd/v22 dbus subpackage, godbus/dbus/v5.
**Avoids:** Pitfall 4 (D-Bus unavailable on minimal distros - fallback path required).

### Phase 4: Declarative Convergence Engine and Drift Detection
**Rationale:** Depends on Phase 1 (state store, `changed: bool` contract, Entitlements) and Phases 2-3 (system primitives it converges over). This is the core Ansible-replacement feature. Cannot precede the primitives it operates on.
**Delivers:** `convergence.go` (pre/post snapshot wrapper, diff computation); `sysscript_convergent` command dispatch; dry-run mode; `convergence_result` message; drift detection scheduler; `drift_report` message; FleetManager drift storage; `POST /converge` + `GET /drift` REST endpoints; `SysscriptsView.jsx` mode toggle and drift indicator badge.
**Avoids:** Pitfall 7 (destructive reruns - uses `changed: bool` from Phase 1), Pitfall 11 (concurrent script state corruption - serialized convergence execution).

### Phase 5: Container Management
**Rationale:** Pure Go, existing `ContainersView.jsx` frontend stub already in place (lowest-friction UI integration of any v2.0 feature). Container entitlement design (image allowlist, no `Privileged: true`) must precede implementation.
**Delivers:** `sys_containers.go` (run/stop/list/exec/logs/pull/rm/images); `containers_op` / `containers_result` wire protocol; `GET /systems/:hostId/containers` REST endpoint; `ContainersView.jsx` real implementation.
**Uses:** docker/docker/client v28.5.2, go-containerregistry v0.21.5.
**Avoids:** Pitfall 2 (Docker socket privilege escalation - image allowlist, `Privileged: false`, lazy socket connection, dynamic socket path probe).

### Phase 6: File System Event Streaming
**Rationale:** fsnotify is pure Go, but the async event architecture requires the Phase 1 serialized write goroutine to be stable first. The register-and-return (non-blocking) pattern must be designed before implementation: events deliver as async `event_notification` WebSocket frames, not via Starlark callback invocation (callbacks are not goroutine-safe in go.starlark.net).
**Delivers:** `sys_events.go` replacing `eventsListen` stub; `events_start` / `events_stop` command types; background watcher goroutines tracked by `sync.Map` keyed on `request_id`; `event_notification` frames; debounce/rate-limiting for high-frequency directories; `ErrEventOverflow` handling.
**Uses:** fsnotify v1.9.0.
**Avoids:** Pitfall 8 (blocking Starlark goroutine - register-and-return, not callback), inotify overflow crash.

### Phase 7: Security Scanning (CGO-gated)
**Rationale:** CGO dependency and split-binary build pipeline are the highest-risk items in v2.0. All pure-Go capabilities proven in Phases 1-6 first. Phase 1 build-tag scaffold makes this a safe, isolated addition. Memory scanning is Linux-only in v2.0 (macOS `task_for_pid` requires signed binary; Windows `SeDebugPrivilege` requires explicit privilege grant).
**Delivers:** `sys_security_stub.go` (build `!yara_full`) + `sys_security_yara.go` (build `yara_full`, CGO); `sys_security_memory.go` (Linux `/proc/pid/mem`, stubs elsewhere with `available: false` + reason); startup capability probe; `security_scan` / `security_scan_result` wire protocol; Makefile `build-standard` / `build-security` targets; `SecurityView.jsx` (new view); `GET /systems/:hostId/security/scan-results` REST endpoint; CVE matching via OSV API (pure Go, base binary).
**Uses:** go-yara/v4 v4.3.4 (CGO, security binary only).
**Avoids:** Pitfalls 1, 9, 10 (CGO isolation, platform privilege honesty, build pipeline separation).

### Phase Ordering Rationale

- Phase 1 before all: wire protocol, Entitlements, write serialization, and `changed: bool` are global. Retrofitting is a cross-module rewrite.
- Phase 2 before Phase 4: convergence reads actual state from packages, processes, files. Those primitives must exist first.
- Phase 3 before Phase 4: service convergence requires the service module.
- Phases 5-6 after Phase 4: independent of convergence but benefit from stable state store and write serializer.
- Phase 7 last: CGO is the highest-risk build change. Prove `CGO_ENABLED=0` is stable across all five targets before introducing the exception.

### Research Flags

**Needs deeper research before phase starts:**
- **Phase 7 (Security):** Windows YARA build pipeline (MSYS2/MinGW exact requirements), macOS `task_for_pid` entitlement signing process, OSV API rate limits and offline behavior.
- **Phase 3 (Services):** Polkit policy for non-root D-Bus system bus access on Rocky 9, Ubuntu 22.04, Debian 12. Distro variation is underdocumented.
- **Phase 6 (Events):** Starlark Thread goroutine safety - the register-and-return architecture avoids calling Starlark from Go goroutines but needs explicit test coverage to verify.

**Standard patterns (skip additional research):**
- **Phase 2 (Primitives):** gopsutil API well-documented; os/exec package manager patterns well-established.
- **Phase 5 (Containers):** Docker Engine API extensively documented; docker/docker/client has 12,000+ importers.

---

## Key Differentiators vs Ansible/Chef/Puppet

1. **WebSocket vs SSH** - Agent connects outbound; no inbound ports, no SSH keys, works behind NAT/firewall. Ansible requires a reachable SSH port on every managed host.
2. **Single static Go binary** - No Python, no pip, no virtualenv on managed hosts. Ansible requires Python on every managed node. Chef requires ruby. Puppet requires ruby + puppet agent.
3. **Starlark sandbox** - Deterministic, Python-readable, no YAML indentation bugs. Each execution declares exactly what capabilities it needs via Entitlements. Ansible has no per-playbook sandbox.
4. **No control node** - Convergence runs inside the agent on the managed host. Ansible requires a control machine with SSH access to all managed hosts.
5. **Real-time WebSocket streaming** - Watch each step converge live. Ansible shows output only after completion. Puppet/Chef have no real-time execution visibility without Tower/Satellite.

---

## Open Questions

Unresolved decisions requiring explicit answers before or during their respective phases:

1. **YARA binary strategy** - Two distributed binaries (`systemapi-agent` + `systemapi-agent-security`) or subprocess call to system `yara` CLI if present? Split binary is cleaner but doubles release artifacts. Decision required before Phase 7.

2. **Windows YARA scope** - MSYS2/MinGW cross-compilation for Windows YARA is significant CI complexity. In scope for v2.0 or deferred to v2.1? If deferred, Windows ships with the `!yara_full` stub from day one.

3. **macOS memory scanning** - `task_for_pid` requires either a provisioning profile / entitlement (code-signing infrastructure not currently in place) or running as root. Acceptable for server agents? Scope for v2.0 or defer?

4. **Privilege escalation for package installs** - Does the agent run as root (simplest for sys.services and sys.packages) or as a non-root user invoking sudo? On macOS, `brew install` refuses to run as root. This determines whether sys.packages needs a privilege-escalation path or assumes root context. Required answer before Phase 2.

5. **creack/pty on Windows CGO status** - Must be audited: does the existing PTY implementation require CGO on Windows (ConPTY path)? If yes, the base Windows binary already has a CGO dependency and the split-binary strategy scope widens. Audit required in Phase 1 before CI matrix is locked.

6. **Convergence script serialization scope** - Serialize ALL Sysscript execution (one at a time per agent) or only convergence-mode scripts? Concurrent imperative scripts during convergence could cause state inconsistencies. Design decision required before Phase 4.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All libraries verified on pkg.go.dev with version and publish dates. CGO constraints verified from Go toolchain docs. |
| Features | HIGH | Based on direct codebase inspection of stubs + domain knowledge of Ansible/Chef/Puppet ecosystem. |
| Architecture | HIGH | Based on direct inspection of main.go, sysscript.go, sys_advanced.go, fleet.js, go.mod. Extension points clearly identified. |
| Pitfalls | HIGH | 15 pitfalls with prevention strategies. CGO, Docker socket, D-Bus, and Starlark thread-safety verified against library docs. |

**Overall confidence:** HIGH

### Gaps to Address

- **creack/pty Windows CGO:** Not confirmed during research. Audit before Phase 1 CI matrix is locked.
- **docker/docker v28.5.2 CVEs:** Two known vulnerabilities at research time (GO-2026-4883, GO-2026-4887). Run `go vuln` before Phase 5 ships; pin to latest patched version.
- **OSV API offline behavior:** CVE matching via OSV API assumed to work online. Behavior without outbound internet access not researched. May need server-side proxy for fleet-wide CVE queries.
- **gopsutil v3 -> v4 import path changes:** All callers in `telemetry.go` and `software.go` need path updates. Low risk but non-trivial mechanical change.

---

## Sources

### Primary (HIGH confidence - pkg.go.dev verified)
- `pkg.go.dev/github.com/hillu/go-yara/v4` - CGO requirements, yara_static tag, Windows MSYS2 requirement, static linking
- `pkg.go.dev/github.com/docker/docker/client` - pure Go status, socket path, CVE list
- `pkg.go.dev/github.com/coreos/go-systemd/v22/dbus` - dbus pure Go, sdjournal CGO, Linux scope
- `pkg.go.dev/github.com/godbus/dbus/v5` - ConnectSystemBus permissions
- `pkg.go.dev/github.com/fsnotify/fsnotify` - ErrEventOverflow, no recursive watch
- `pkg.go.dev/go.etcd.io/bbolt` - ACID, Windows file locking, pure Go
- `pkg.go.dev/github.com/shirou/gopsutil/v4` - process API, memory_maps Linux-only, no CGO
- `pkg.go.dev/go.starlark.net` - Thread.Load behavior, thread safety
- Go toolchain docs - CGO_ENABLED=0 global scope, no per-package toggle

### Primary (HIGH confidence - direct codebase inspection)
- `systemapi-agent/main.go`, `sysscript.go`, `sys_advanced.go`, `telemetry.go`, `software.go`, `go.mod`
- `playground/fleet.js`, `playground/playground_fleet_schema.sql`, `server.js`
- `frontend/src/views/ContainersView.jsx`

### Secondary (MEDIUM confidence - domain knowledge)
- Ansible/Chef/Puppet/Terraform ecosystem design patterns - feature completeness expectations, anti-patterns
- Docker rootless and Desktop socket path variations

---
*Research completed: 2026-04-28*
*Ready for roadmap: yes*
