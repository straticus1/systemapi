# Domain Pitfalls: SystemAPI.io v2.0

**Domain:** Go WebSocket agent — adding YARA scanning, container management, package management, service control, process/event primitives
**Researched:** 2026-04-28
**Confidence:** HIGH (verified against go-yara v4 docs, moby/moby client, fsnotify, gopsutil, go.starlark.net, Docker official docs)

---

## Critical Pitfalls

Mistakes that cause binary distribution failure, security bypasses, or production rewrites.

---

### Pitfall 1: YARA via go-yara/v4 Breaks the Static Binary Constraint

**Problem:** go-yara/v4 is a CGO binding to libyara. CGO is incompatible with the project's requirement for a single static executable with no runtime dependencies. Cross-compilation for `windows/amd64` and `linux/arm64` requires a matching GCC toolchain and the target platform's libyara headers available on the build machine. On Windows, MSYS2/MinGW with pkg-config is required — the standard `GOOS=windows go build` workflow does not work.

**Why it happens here:** The project constraint says "Agent binary must be single static executable, no runtime deps." go-yara requires `yara_static` build tag plus `-extldflags "-static"` plus libyara static libraries on the build host — but libyara itself links against libcrypto and optionally libmagic, which must also be statically available. On macOS CI building for Linux targets, this requires musl-libc toolchains. Each target platform needs its own libyara cross-compiled.

**Verified from go-yara docs:** `yara_static` build tag makes pkg-config pass `--static`, but `CGO_LDFLAGS` still needs `-extldflags "-static"` manually. If libyara was linked against libcrypto or libmagic, those must be added to `CGO_LDFLAGS`. Windows requires GCC + MSYS2, not the standard Windows toolchain.

**Consequences:** CI pipeline fails silently for non-native targets. The Windows agent build either requires a MSYS2 environment or cannot support YARA at all. Static binary size grows by 5-15 MB per platform due to embedded libyara+libcrypto.

**Prevention:**
- Gate YARA behind a build tag (`//go:build yara`). Ship agent with YARA disabled by default. Enable it only for platforms/targets where libyara can be statically linked.
- Alternative: Implement YARA scanning as a subprocess call to a separately-distributed `yara` binary or use pure-Go rule matching (e.g., `github.com/blacktop/go-yara` patterns via regex) for the subset of rules that map to simple patterns.
- Decide before Phase 1: accept that Windows YARA requires special build pipeline, or defer YARA to Linux-only initially.

**Which phase:** Must be decided in the security scanning phase before writing a single line of YARA integration code.

---

### Pitfall 2: Docker Socket Access Grants Effective Root on the Host

**Problem:** The Docker daemon socket (`/var/run/docker.sock`) is a privilege escalation path. Any process that can write to the socket can mount the host filesystem, exec as root inside a container, and escape. The agent runs with `sys.containers` entitlement — if that entitlement is too coarse, a Sysscript can trivially escape the Starlark sandbox by mounting `/` inside a container and writing to it.

**Why it happens here:** The `containersRun` stub accepts only an `image` string today. When implemented, the Docker API's `/containers/{id}/exec` endpoint accepts a `Privileged: true` flag and an arbitrary `User` field. A Sysscript that calls `sys.containers.exec(container_id, ["chroot", "/host"])` with no further validation achieves a full breakout.

**Verified from moby/moby client docs:** `DefaultDockerHost = "unix:///var/run/docker.sock"`. On macOS (Docker Desktop), the socket is at `$HOME/.docker/desktop/docker.sock` or under `$XDG_RUNTIME_DIR`. On rootless Docker, the path is `$XDG_RUNTIME_DIR/docker.sock`. Hardcoding `/var/run/docker.sock` silently fails on Docker Desktop for macOS/Linux and rootless installs — no useful error, just connection refused.

**Consequences:** If the agent runs as root (common for sys.services and sys.packages operations), Docker socket access = unrestricted root. Even if agent runs as a non-root user in the docker group, it still has effective root via Docker.

**Prevention:**
- The Entitlements struct must be extended with container-specific restrictions: allowed images (allowlist), prohibited bind mount targets, forbidden exec commands, `Privileged: false` enforcement.
- When connecting to the Docker daemon, probe socket paths in order: `DOCKER_HOST` env var → rootless path → `/var/run/docker.sock`. Never hardcode.
- Never expose `Privileged: true` in the exec API through Starlark builtins. Mark it as a prohibited parameter.
- Consider whether the agent should connect to Docker at all on hosts where no `allow_containers` entitlement is granted — the connection itself should be lazy/deferred.

**Which phase:** Container management phase. The entitlement schema for containers must be designed before implementing `sys.containers.*`.

---

### Pitfall 3: Cross-Platform Package Management Blocks on Interactive Prompts and Privilege Requirements

**Problem:** `apt`, `dnf`, `brew`, and `winget` each have different privilege models, interactive prompt behaviors, and lock file locations. When called from a non-interactive agent process, they can block indefinitely (waiting for user confirmation), fail due to lock contention (another package manager running), fail because sudo is not available, or produce different exit codes for "already installed" vs "failed to install."

**Why it happens here:** The current `packagesInstall` stub runs `exec.Command(...)` through the existing `sys.exec.run` path. `apt-get install nginx` on Debian will prompt "Do you want to continue? [Y/n]" if not passed `-y`. `brew install` refuses to run as root — the agent may run as root for other operations but brew install must run as the admin user. `winget` on Windows requires either user context or an elevation prompt. `dnf` acquires a lockfile at `/var/cache/dnf/...`; concurrent installs deadlock.

**Verified from gopsutil docs:** Process ownership tracking shows `uids`/`gids` are not available on Windows — determining which user context is running requires WMI/COM calls.

**Consequences:** A Sysscript that runs `sys.packages.install("nginx")` hangs the agent's WebSocket goroutine indefinitely if the subprocess blocks on stdin. The package manager lock persists if the agent is killed during a hung install.

**Prevention:**
- Always pass non-interactive flags per package manager: `-y` / `--assumeyes` for apt/dnf, `--noninteractive` for some snap operations.
- Wrap package manager invocations with a context deadline (default 5 minutes). Use `exec.CommandContext` not bare `exec.Command`.
- Detect the running user and package manager's privilege requirements before invoking — fail fast with a clear error rather than hanging.
- For brew: detect if running as root and re-invoke as the owner of `/usr/local` using `sudo -u <admin>`.
- Check and report lock file presence before attempting install; surface it as a retryable error to the dashboard, not a hang.
- Return structured results: `{installed: bool, already_present: bool, error: string}` — not just `true/nil`.

**Which phase:** Package management phase. Non-interactive flag handling and context deadline must be implemented from day one, not retrofitted.

---

### Pitfall 4: systemd via D-Bus Requires System Bus — Not Available Headlessly on All Distros

**Problem:** Managing systemd services (start/stop/enable/disable/status) requires D-Bus calls to `org.freedesktop.systemd1` on the **system bus**, not the session bus. The system bus is accessible only to root or via polkit policy grants. Many minimal server images (container-based distros, stripped RHEL) do not run a full D-Bus daemon, making the system bus unavailable entirely.

**Why it happens here:** `godbus/dbus` has two connection methods: `ConnectSystemBus()` and `ConnectSessionBus()`. The `sys.services` module needs the system bus (`systemd1` lives there). On minimal distros, `dbus-daemon --system` may not be running. In containers without `--privileged`, the system bus is inaccessible. On macOS, systemd does not exist — `sys.services` must call launchd via `launchctl`. On Windows, it must call the Service Control Manager (SCM) via the `golang.org/x/sys/windows/svc` package.

**Verified from godbus/dbus docs:** `ConnectSystemBus()` establishes connection to system bus requiring appropriate permissions. The session bus (`ConnectSessionBus()`) is for user-scoped applications and cannot control system services.

**Consequences:** If the agent attempts `ConnectSystemBus()` on a system where dbus is not running or the agent lacks permission, it gets a connection refused error — but the Starlark builtin would return this as a generic error, making diagnosis hard from the dashboard. On macOS the code silently does nothing if written for Linux only.

**Prevention:**
- Implement `sys.services` as a platform-dispatched interface: `serviceBackend` with `Linux_systemd`, `macOS_launchd`, `Windows_scm` implementations selected at compile time or runtime.
- On Linux, probe whether D-Bus system socket is available before connecting; fall back to `systemctl` subprocess if D-Bus is unavailable (slower but functional on minimal images).
- On macOS, use `launchctl` subprocess — no CGO required, no special permissions beyond the running user.
- On Windows, use `golang.org/x/sys/windows/svc/mgr` (pure Go, no CGO) to connect to SCM.
- Surface missing D-Bus as a specific error type that the dashboard can display as "Service management unavailable on this host — D-Bus not running."

**Which phase:** Service management phase. Platform dispatch architecture must be established first; don't write Linux-only code and plan to port later.

---

### Pitfall 5: Starlark Load() Statement Opens a Module Injection Path

**Problem:** The current `SysscriptEngine.Execute()` sets no `Thread.Load` handler. Starlark's `load()` statement allows importing external modules. If a `Thread.Load` callback is ever added (for Sysscript libraries/helpers), without strict path validation it becomes a local file read exploit — `load("/etc/passwd", "data")` would attempt to load and parse `/etc/passwd` as Starlark source.

**Why it happens here:** The `buildSysModule` correctly gates `sys.fs.read` behind the `AllowFSRead` entitlement prefix list. But `Thread.Load` bypasses `sys.fs` entirely — it is called directly by the Starlark interpreter before user code runs, using the interpreter's own file loading path.

**Verified from go.starlark.net docs:** The `Thread.Load` callback is invoked when a `load()` statement is encountered. If `Thread.Load` is nil, `load()` raises an error — so the current code is safe. The risk is introduced the moment a Load handler is added.

**Consequences:** If a future developer adds a `Thread.Load` to support shared Sysscript libraries, without checking the path against `AllowFSRead` entitlements, any script can exfiltrate arbitrary files from the host filesystem.

**Prevention:**
- Document explicitly in `SysscriptEngine`: "Do not set Thread.Load unless the loader validates paths against AllowFSRead entitlements."
- If shared libraries are added, restrict load paths to an in-memory registry (e.g., a `map[string]string` of approved modules), never to the host filesystem.
- Add a test that verifies `load("/etc/passwd", "x")` raises an error with the default engine configuration.

**Which phase:** Foundational — add the test and documentation in the first phase that touches the Starlark engine (security scanning phase touches sys.security which means touching the engine).

---

### Pitfall 6: sys.exec.run Entitlement Is Binary — No Command Allowlisting

**Problem:** The current `AllowExec bool` entitlement grants unrestricted command execution. Once a Sysscript declares `allow_exec: true`, it can run any binary on the host — `rm -rf /`, `dd if=/dev/random of=/dev/sda`, or a reverse shell. For a platform replacing Ansible, this is intentional for power users, but it means the entitlement model has a single coarse knob where a fine-grained one is needed for security scanning and package management.

**Why it happens here:** `sys.packages.install` and `sys.security.yara_scan` will internally call `exec.Command` — they do not go through the Starlark `sys.exec.run` builtin, so the `AllowExec` check does not gate them. A Starlark script that only declares package or security entitlements gets those builtins' full subprocess capabilities for free, bypassing `AllowExec: false`.

**Consequences:** The entitlement model shown to users in the dashboard ("this script needs exec access") is misleading. A script with only `allow_packages: true` can trigger arbitrary subprocess execution through the package manager's pre/post-install scripts.

**Prevention:**
- Add entitlement fields per capability: `AllowPackages []string` (package names), `AllowContainers []string` (image names), `AllowSecurity bool`.
- Document that package management and container ops implicitly include subprocess execution — make this explicit in the security model.
- For higher-risk operations, consider running the internal subprocess with a restricted set of environment variables (no `$HOME`, no `$PATH` beyond known safe paths).
- Audit every new `sys.*` builtin: does it call `exec.Command`? If yes, is that subprocess capability reflected in the entitlements the dashboard presents?

**Which phase:** This audit must happen at the start of v2.0 — before implementing any new builtins — because retrofitting the entitlement model after five new modules are built is a rewrite.

---

### Pitfall 7: Declarative Convergence Without Idempotency Checks Causes Destructive Reruns

**Problem:** Declarative state (Ansible-replacement mode) requires that applying the same Sysscript twice produces the same result as applying it once. Without explicit idempotency checks in each builtin, a convergence rerun can uninstall and reinstall packages (causing service downtime), restart services that are already running, or overwrite configuration files that were manually modified since last apply.

**Why it happens here:** The current stub builtins return `true` for success. In a convergence loop, the FleetManager compares desired state vs last-applied state and triggers re-execution if drift is detected. Without `already_installed: true` returns from `sys.packages.install` or `is_running: true` from `sys.services.start`, the convergence engine has no way to distinguish "applied successfully" from "no change needed" — so it re-applies every time.

**Consequences:** Every 5-second telemetry tick that shows a service down triggers a convergence run that calls `service.start()` which restarts a service that another admin just intentionally stopped for maintenance. Or a rerun of a `sys.fs.write` overwrites a hotfix applied directly on the host.

**Prevention:**
- All `sys.*` builtins must return structured results with a `changed: bool` field — the Ansible convention that distinguishes "did work" from "already in desired state."
- The state store (last-applied state per host) must record the full desired state hash, not just "last successful run timestamp."
- Implement a dry-run mode (`check_mode: true`) that reports what would change without executing.
- Drift detection should compare current state to desired state, not current state to last-run state — these differ if someone makes a manual change while a convergence is in-flight.

**Which phase:** State management / declarative convergence phase. The `changed: bool` return contract must be established before the state store is built — changing it later requires updating every builtin.

---

### Pitfall 8: Event Streaming (sys.events.listen) Cannot Block the WebSocket Goroutine

**Problem:** The `eventsListen` stub accepts a callback and returns. The real implementation must subscribe to inotify (Linux), kqueue (macOS), or ETW (Windows) and call the Starlark callback for each event. But Starlark execution is single-threaded and blocking — a callback loop inside Starlark would block the goroutine running the script, preventing the agent from processing other WebSocket messages (telemetry, PTY input, other Sysscripts).

**Why it happens here:** The current agent architecture runs Sysscripts synchronously inside `processIncomingMessage`. A blocking event listener inside a Sysscript would freeze the entire agent. Even if moved to a goroutine, the Starlark `Thread` is not goroutine-safe — concurrent calls into the same thread will corrupt the interpreter state.

**Verified from fsnotify docs:** `ErrEventOverflow` occurs on inotify when `fs.inotify.max_queued_events` is exceeded (Linux) or when the Windows buffer is too small for a burst. High-frequency filesystem events (log rotation, busy temp directories) will overflow default buffers.

**Consequences:** A Sysscript with `sys.events.listen("fs", callback)` either hangs the agent indefinitely, or if run in a goroutine with concurrent Starlark execution, causes data races and interpreter panics.

**Prevention:**
- `sys.events.listen` must be non-blocking. The Starlark builtin registers interest (path, event type, filter) and returns a handle ID immediately.
- Events are delivered back over the WebSocket to the FleetManager as async `ResponseMessage` frames with `type: "event"`, not by calling a Starlark callback.
- The Sysscript that registers a listener terminates; the agent's event subsystem continues running as a background goroutine that uses its own separate `ResponseMessage` write path.
- Handle `ErrEventOverflow` by dropping events with a logged warning — never let overflow crash the agent.

**Which phase:** Event streaming phase. This architectural separation (register-and-return vs blocking callback) must be decided before implementing the first event source.

---

### Pitfall 9: Memory Scanning Requires Elevated Privileges That Are Platform-Dependent and Unavailable by Default

**Problem:** Reading another process's memory (for `sys.security.scan_memory(pid)`) requires platform-specific elevated privileges: `CAP_SYS_PTRACE` on Linux (or running as root), `task_for_pid` entitlement on macOS (blocked by SIP for non-Apple-signed binaries, requires `SecTaskAccess` entitlement or running as root), and `SeDebugPrivilege` on Windows. These are not available by default and cannot be granted via a Sysscript entitlement alone.

**Why it happens here:** The agent is distributed as a downloaded binary without code signing (macOS) or a Windows driver certificate. On macOS with SIP enabled, `task_for_pid()` will return `KERN_FAILURE` for any process not owned by the agent's user, regardless of the agent running as root. On Windows, `SeDebugPrivilege` must be enabled in the process token — it is not enabled by default even for Administrator accounts.

**Verified from gopsutil docs:** `memory_maps` (which reads `/proc/PID/maps` — a prerequisite for memory scanning) is Linux-only in gopsutil. macOS and Windows process memory access is not covered by gopsutil at all.

**Consequences:** `sys.security.scan_memory(pid)` will silently return "clean" (as the stub does today) or crash with a permissions error on every platform except Linux root. Shipping this as a real feature without surfacing the privilege requirement will confuse operators and create false confidence in security scan results.

**Prevention:**
- At agent startup, probe memory scanning capability: attempt `ptrace(PTRACE_ATTACH, self_pid)` on Linux, check `task_for_pid` on macOS, check `SeDebugPrivilege` on Windows. Cache result.
- If capability is unavailable, `sys.security.scan_memory` returns `{available: false, reason: "CAP_SYS_PTRACE not granted"}` rather than a fake clean result.
- Documentation for the agent install must include instructions for granting the required capability on each platform (setcap on Linux, entitlement signing on macOS, privilege configuration on Windows).
- Consider restricting memory scanning to Linux-only in v2.0 and deferring macOS/Windows to a future milestone with proper code signing infrastructure.

**Which phase:** Security scanning phase. Capability probing must be implemented at the same time as the feature, not deferred to "polish."

---

### Pitfall 10: CGO-Enabled Build Breaks `CGO_ENABLED=0` Cross-Compilation for All Targets

**Problem:** Introducing any CGO dependency (e.g., go-yara) into the agent module means that `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build` no longer produces a working binary for the whole agent — CGO code cannot be excluded per-package when CGO is disabled globally. The entire build fails, not just the YARA-dependent packages.

**Why it happens here:** The project ships five cross-compilation targets: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`. Currently the agent uses only pure-Go dependencies (gorilla/websocket, creack/pty, gopsutil, go.starlark.net) which all support `CGO_ENABLED=0`. Adding go-yara changes this constraint for the entire binary.

**Verified from Go docs:** `CGO_ENABLED=0` disables CGO for all packages in the build graph. There is no per-package CGO toggle. If any package uses CGO and CGO is disabled, the build fails. Android and iOS targets explicitly require CGO for some operations.

**Consequences:** The CI pipeline must either (a) maintain separate build scripts per platform with different CGO settings and cross-toolchain setups, or (b) ship separate "yara-enabled" and "yara-disabled" agent variants. This doubles the distribution complexity.

**Prevention:**
- Isolate any CGO code behind a build tag (`//go:build yara`) in a separate file. Provide a pure-Go stub with the same function signature and `//go:build !yara` tag.
- The default build (`go build ./...`) must succeed with `CGO_ENABLED=0` — YARA is an opt-in variant.
- CI matrix: build and test the `!yara` variant with `CGO_ENABLED=0` for all five targets; build and test the `yara` variant only on Linux/amd64 natively (where libyara is available in CI).
- Verify that `creack/pty` builds on Windows with `CGO_ENABLED=0` — pty on Windows uses the Windows ConPTY API which may require CGO; this should be audited before v2.0 starts.

**Which phase:** Before any new dependency is added — this is a build system constraint to establish in Phase 1 of v2.0.

---

### Pitfall 11: Drift Detection State Store Gets Out of Sync with Reality Under Concurrent Sysscript Execution

**Problem:** The planned "Sysscript state store — track last-applied state per host, detect drift" feature must handle the case where two Sysscripts modify overlapping resources concurrently. Without a per-resource lock or serialization, both scripts can read stale desired state, both apply changes, and both write to the state store — resulting in the store reflecting only one script's view of the world while the host is in the other's desired state.

**Why it happens here:** The agent currently processes all WebSocket messages in `processIncomingMessage` via a single goroutine for reads, but Sysscripts are launched in separate goroutines (implied by the architecture). Multiple scripts could run concurrently. The state store (presumably PostgreSQL on the server side, synced back from the agent) has no row-level locking per resource.

**Consequences:** State store shows nginx enabled, but the second script that ran disabled it — drift detection then fires immediately after convergence, causing a loop. Or the store shows last-applied hash X when the host is actually at state Y because a concurrent script's write to the store raced with the first script's read.

**Prevention:**
- The agent must serialize Sysscript execution — one script at a time, queued. Concurrent PTY sessions are fine (they are interactive, not convergence scripts), but convergence scripts must be strictly sequential.
- The state store must use optimistic locking: store a `state_version` integer per host per resource; each update increments it; a concurrent writer that reads stale `state_version` must retry.
- Drift detection must compare actual host state (probed live) against desired state (from the store), not against last-applied state — the distinction matters when convergence is in-flight.

**Which phase:** State management phase. The serialization constraint on convergence scripts must be designed into the agent before state store integration begins.

---

## Moderate Pitfalls

### Pitfall 12: gopsutil v3 vs v4 API Incompatibility

**Problem:** The agent currently uses `gopsutil/v3`. The v4 release (2024) changed the process API and context handling. Mixing v3 and v4 in the same binary (if a new dependency pulls in v4 transitively) causes compilation errors due to package path conflicts.

**Prevention:** Pin `gopsutil/v3` explicitly and audit all new dependencies for v4 transitive imports before adding them. Do not upgrade to v4 mid-milestone without a full API compatibility audit.

**Which phase:** Any phase adding new sys.process or sys.memory features.

---

### Pitfall 13: WebSocket Write Concurrency — Multiple Goroutines Writing Simultaneously

**Problem:** The current `processIncomingMessage` passes the `*websocket.Conn` directly to PTY handlers and Sysscript engines. Gorilla WebSocket docs state that connections support one concurrent reader and one concurrent writer — concurrent writes from the telemetry ticker goroutine and a Sysscript result goroutine will corrupt the WebSocket frame stream.

**Prevention:** Serialize all WebSocket writes through a single write goroutine with a buffered channel. The telemetry ticker, Sysscript results, PTY output, and async event messages all send to this channel; one goroutine performs all `c.WriteJSON` / `c.WriteMessage` calls. This is a prerequisite for any feature that produces async output (events, alerts, long-running package installs).

**Which phase:** This is a v1.0 architectural debt that must be fixed before any async feature (events, async package installs) is added in v2.0.

---

### Pitfall 14: sys.net.http_get Hostname-Only Allowlist Is Bypassable via DNS Rebinding

**Problem:** The current `AllowNetOutbound` check compares `u.Hostname()` against the allowlist. This is bypassable: a script can be granted access to `downloads.example.com`, which DNS-resolves to `10.0.0.1` (an internal service) at runtime via DNS rebinding. The Go HTTP client resolves DNS at request time, after the hostname check passes.

**Prevention:** Add IP-range denylisting after DNS resolution (using `net.Dial` hooks or a custom `http.Transport`) to block requests to RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopback — regardless of what hostname was granted. This is a defense-in-depth measure for SSRF prevention.

**Which phase:** Should be fixed in the same phase that implements sys.alerts push (which makes the agent an outbound communication channel), not deferred.

---

### Pitfall 15: Package Manager Detection Must Not Rely on PATH Alone

**Problem:** Detecting the platform package manager by checking `which apt` / `which dnf` / `which brew` is unreliable in restricted environments. Some distros have both `apt` and `dpkg-based` tools but `apt` is not in the agent's `PATH`. Some Debian-based systems have `apt` but `dnf` also installed as a compatibility shim.

**Prevention:** Use a priority list that checks both `PATH` and known absolute paths: `/usr/bin/apt-get`, `/usr/bin/dnf`, `/opt/homebrew/bin/brew`, `/usr/local/bin/brew`. Prefer the distro's canonical tool over any compatibility shim. On Windows, check both `winget.exe` presence and `HKLM\SOFTWARE\Microsoft\Winget` registry key.

**Which phase:** Package management phase.

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|---|---|---|
| YARA / security scanning | CGO breaks static binary (Pitfall 1 + 10) | Build tag isolation before writing any CGO; decide Windows/arm64 scope upfront |
| Container management | Docker socket privilege escalation (Pitfall 2) | Entitlement schema with image allowlist before implementing containersRun |
| Package management | Blocking prompts hang agent goroutine (Pitfall 3) | exec.CommandContext with deadline from day one; non-interactive flags |
| Service management (sys.services) | D-Bus unavailable on minimal distros (Pitfall 4) | Platform dispatch + dbus-unavailable fallback to systemctl subprocess |
| Starlark engine extensions | load() module injection (Pitfall 5) | No Thread.Load unless paths validated against AllowFSRead; add test now |
| Any new sys.* builtin | Entitlement model mismatch (Pitfall 6) | Audit subprocess usage; update Entitlements struct before building |
| Declarative convergence | Non-idempotent builtins cause destructive reruns (Pitfall 7) | changed: bool contract established before state store |
| Event streaming | Blocking callback locks WebSocket goroutine (Pitfall 8) | Register-and-return architecture; events delivered as async WebSocket frames |
| Memory scanning | Platform privilege unavailability (Pitfall 9) | Capability probe at startup; return available: false, not fake clean |
| Build pipeline | CGO added to any target breaks all cross-compilation (Pitfall 10) | CGO_ENABLED=0 gate in CI for all five targets; yara as build tag |
| State store / drift detection | Concurrent script execution corrupts state (Pitfall 11) | Serialize convergence scripts; optimistic locking in state store |
| Async output (events, alerts) | Concurrent WebSocket writes corrupt frames (Pitfall 13) | Single write goroutine with channel before any async feature ships |

---

## Sources

- go-yara/v4 official docs: https://pkg.go.dev/github.com/hillu/go-yara/v4 (HIGH confidence — verified build tag behavior, CGO requirements, Windows MSYS2 requirement, static linking requirements)
- moby/moby client docs: https://pkg.go.dev/github.com/moby/moby/client (HIGH confidence — verified DefaultDockerHost constant, socket path variations, exec API Privileged flag)
- Docker official docs on rootless / Desktop socket paths (HIGH confidence — verified per-platform socket location differences)
- go.starlark.net docs: https://pkg.go.dev/go.starlark.net (HIGH confidence — verified Thread.Load behavior, thread.Cancel, SetMaxExecutionSteps)
- fsnotify docs: https://pkg.go.dev/github.com/fsnotify/fsnotify (HIGH confidence — verified ErrEventOverflow, inotify queue overflow, Windows buffer behavior)
- gopsutil/v3 README: https://github.com/shirou/gopsutil (HIGH confidence — verified per-platform process capability matrix, memory_maps Linux-only)
- godbus/dbus docs: https://pkg.go.dev/github.com/godbus/dbus/v5 (MEDIUM confidence — verified ConnectSystemBus vs ConnectSessionBus, permission requirements)
- Go toolchain docs on CGO_ENABLED (HIGH confidence — verified that CGO_ENABLED=0 is binary/global, no per-package toggle)
- Codebase analysis: sysscript.go, sys_advanced.go, main.go, go.mod (HIGH confidence — direct inspection of current entitlement model, stub implementations, dependency versions)
