# Architecture Patterns: SystemAPI.io v2.0 Integration

**Domain:** Fleet systems management platform — next-gen capabilities
**Researched:** 2026-04-28
**Confidence:** HIGH (based on direct codebase inspection + verified library docs)

---

## Current Architecture Baseline

### Wire Protocol (CommandMessage / ResponseMessage)

The WebSocket JSON protocol is the seam between every layer. Current message types:

**Server → Agent (CommandMessage):**
- `sysscript` — execute Starlark script
- `pty_start` / `pty_input` / `pty_resize` / `pty_stop` — terminal session

**Agent → Server (ResponseMessage):**
- `telemetry` — 5s push of CPU/memory/disk/network/software
- `command_result` — sysscript execution output
- `pty_status` — PTY lifecycle events
- Binary frames — raw PTY keystroke bytes

### Agent Dispatch (processIncomingMessage in main.go)

Single switch statement dispatches on `cmd.Type`. Adding new command types means adding cases here. This is the primary extension point for new server-to-agent operations.

### Starlark Engine (sysscript.go)

`SysscriptEngine.buildSysModule()` assembles `sys.*` sub-modules from `starlark.StringDict`. Adding a new module (e.g. `sys.packages`) means building a new StringDict and registering it in `sysDict`. Entitlements struct controls which builtins fire or return security errors.

### FleetManager (playground/fleet.js)

`handleConnection` dispatches on `msg.type`. Adding new agent-initiated message types (drift reports, scan results) means adding cases here. `pushSysscript` is the only server-to-agent push method — it needs a parallel `pushCommand` that accepts arbitrary CommandMessage types.

---

## New Capabilities: Integration Map

### 1. Starlark State Convergence Engine (Declarative Mode)

**What it is:** Script execution that tracks expected vs. actual state, reports drift, and converges idempotently.

**Agent layer — new components:**
- `convergence.go` — new file. Wraps `SysscriptEngine.Execute()` with a pre/post state snapshot comparison. Reads last-applied state from BoltDB (see drift store below), computes diff, writes new state.
- `state_store.go` — new file. BoltDB-backed key/value store at `~/.systemapi/state.db`. Buckets: `applied_scripts`, `resource_snapshots`. Pure embedded, no runtime deps, compiles for all targets.

**Agent layer — modified components:**
- `sysscript.go` (SysscriptEngine): Add `ExecuteConvergent(script, stateKey string) (ConvergenceResult, error)` method alongside existing `Execute()`. Does not break existing imperative path.
- `main.go` (processIncomingMessage): Add `sysscript_convergent` case dispatching to convergence engine. Pass `convergence_id` field from CommandMessage.
- `main.go` (CommandMessage struct): Add fields `ConvergenceID string`, `Mode string` (values: `"imperative"` | `"convergent"`).

**Server layer — new components:**
- New REST endpoint `POST /api/v1/systems/:hostId/converge` — triggers convergent execution, stores last-applied hash per host.
- New PostgreSQL table `host_convergence_state` — columns: `host_id`, `script_id`, `convergence_id`, `applied_at`, `state_hash`, `drift_detected`.

**Server layer — modified components:**
- `playground/fleet.js` (FleetManager.handleConnection): Add case for `convergence_result` message type from agent. Stores state hash, evaluates drift.
- `playground/fleet.js` (FleetManager): Add `pushConvergentScript(hostId, script, entitlements, convergenceId)` method.

**Wire protocol additions:**
```
Server → Agent: { type: "sysscript_convergent", script, entitlements, convergence_id, request_id }
Agent → Server: { type: "convergence_result", request_id, convergence_id, payload: { output, drift_detected, diff, state_hash } }
```

**Frontend — modified components:**
- `SysscriptsView.jsx`: Add "Mode" toggle (Imperative / Convergent), show drift indicator badge on last-run result.

---

### 2. YARA + Memory Scanning (sys.security)

**CGO constraint — critical:** `github.com/hillu/go-yara/v4` requires CGO and the system `libyara` C library. This breaks the single-static-binary requirement for cross-platform compilation.

**Resolution:** Use a build-tag gate. Compile two agent variants:
- `agent` (default, pure Go) — `securityYaraScan` returns `"security module not available in this build"`.
- `agent-security` (CGO enabled, Linux/macOS only) — full YARA via build tag `yara_full`.

Memory scanning (`securityScanMemory`) reads `/proc/<pid>/mem` on Linux. macOS requires `vm_read` mach call (needs entitlement). Windows requires `ReadProcessMemory` via CGO. Flag as Linux-primary for v2.0.

**Agent layer — new components:**
- `sys_security_stub.go` (build tag `!yara_full`) — current stub behavior.
- `sys_security_yara.go` (build tag `yara_full`) — real YARA implementation with CGO.
- `sys_security_memory.go` — pure Go memory read via `/proc/pid/mem` (Linux), with stubs for macOS/Windows.

**Agent layer — modified components:**
- `sys_advanced.go` (securityYaraScan, securityScanMemory): Split into stub vs. implementation files via build tags. Remove current stub body from sys_advanced.go.
- `sysscript.go` (buildSysModule): Add `sys.security.cve_match` builtin (pure Go — calls back to server via WebSocket event, or queries local CVE DB if offline).

**Entitlements — new fields:**
```go
AllowSecurityScan  bool     `json:"allow_security_scan"`
AllowMemoryScan    bool     `json:"allow_memory_scan"`
YaraRules          []string `json:"yara_rules"` // inline rule strings
```

**Server layer — new components:**
- New REST endpoint `GET /api/v1/systems/:hostId/security/scan-results` — returns latest scan results for a host.
- New PostgreSQL table `host_security_scans` — columns: `host_id`, `scan_type` (yara/memory), `target`, `findings JSONB`, `scanned_at`.

**Server layer — modified components:**
- `playground/fleet.js` (handleConnection): Add case for `security_scan_result` message type.

**Wire protocol additions:**
```
Server → Agent: { type: "security_scan", scan_type: "yara"|"memory", target: "/path or pid", rules: [...], request_id }
Agent → Server: { type: "security_scan_result", request_id, payload: { findings: [...], clean: bool } }
```

**Frontend — new components:**
- `SecurityView.jsx` — new view: show per-host scan results, trigger scan button, YARA rule editor.

---

### 3. Docker/OCI Management (sys.containers)

**Library:** `github.com/docker/docker/client` (import path `github.com/docker/docker/client`, v28+). Pure Go — no CGO. Uses Docker daemon socket: Unix socket on Linux/macOS (`/var/run/docker.sock`), named pipe on Windows (`npipe:////./pipe/docker_engine`). The client auto-negotiates via `DOCKER_HOST` env var.

**Entitlement gate needed:** `AllowContainers bool` in Entitlements.

**Agent layer — new components:**
- `sys_containers.go` — new file replacing stub in `sys_advanced.go`. Implements: `containers.run`, `containers.stop`, `containers.list`, `containers.exec`, `containers.logs`, `containers.pull`, `containers.rm`, `containers.images`.
- Connects to local Docker daemon via `client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())`.

**Agent layer — modified components:**
- `sysscript.go` (buildSysModule, sysContainers dict): Expand from single `run` to full set of operations.
- `sys_advanced.go`: Remove `containersRun` stub, it moves to `sys_containers.go`.
- `sysscript.go` (Entitlements struct): Add `AllowContainers bool`.

**Server layer — new components:**
- New REST endpoint `GET /api/v1/systems/:hostId/containers` — returns live container list (triggers `containers_list` command and awaits result).

**Wire protocol additions:**
```
Server → Agent: { type: "containers_op", operation: "list"|"run"|"stop"|"pull"|"rm"|"logs", params: {...}, request_id }
Agent → Server: { type: "containers_result", request_id, payload: { containers: [...] | logs: "..." | error: "..." } }
```

**Frontend — modified components:**
- `ContainersView.jsx`: Currently stub UI. Implement real operations: list, start, stop, pull, remove. Connect to new REST endpoints.

---

### 4. Package Management (sys.packages)

**Cross-platform detection:** Use `runtime.GOOS` + probe for package manager binary. Order: `dpkg`/`apt` (Debian), `rpm`/`dnf` (RHEL), `brew` (macOS), `winget` / PowerShell (Windows).

This capability is pure Go — uses `os/exec` to shell out to existing package managers. No new library dependency. Platform detection pattern already established in `software.go`.

**Entitlement gate:** `AllowPackageInstall bool` in Entitlements.

**Agent layer — new components:**
- `sys_packages.go` — new file. Implements: `packages.install(name)`, `packages.remove(name)`, `packages.upgrade(name)`, `packages.list()`, `packages.info(name)`. Uses runtime platform detection. Privilege escalation: `sudo` on Linux/macOS (requires the agent to be running as root or have sudo configured), elevation prompt on Windows via `runas`.

**Agent layer — modified components:**
- `sys_advanced.go`: Remove `packagesInstall` stub, moves to `sys_packages.go`.
- `sysscript.go` (sysPackages dict): Add `remove`, `upgrade`, `list`, `info` builtins.
- `sysscript.go` (Entitlements struct): Add `AllowPackageInstall bool`, `AllowPackageRemove bool`.

**Frontend — new components:**
- `PackagesView.jsx` — new view: per-host installed package list (from telemetry software inventory), install/remove trigger.

---

### 5. Service Management (sys.services)

**Platform split:**
- Linux: `github.com/coreos/go-systemd/v22/dbus` + `github.com/godbus/dbus/v5`. godbus/dbus is pure Go (native D-Bus protocol implementation). go-systemd/dbus depends on it. No CGO.
- macOS: `launchctl` via `os/exec`. No library needed.
- Windows: PowerShell `Get-Service`, `Start-Service`, `Stop-Service` via `os/exec`. No library needed.

Recommend compile-time build tags to isolate the D-Bus import to Linux only (`//go:build linux`).

**Agent layer — new components:**
- `sys_services_linux.go` (build tag `linux`) — systemd D-Bus implementation.
- `sys_services_darwin.go` (build tag `darwin`) — launchctl wrappers.
- `sys_services_windows.go` (build tag `windows`) — PowerShell wrappers.
- All three implement the same function signatures for Starlark: `services.start`, `services.stop`, `services.restart`, `services.status`, `services.list`, `services.enable`, `services.disable`.

**Agent layer — modified components:**
- `sys_advanced.go`: No existing stub to remove.
- `sysscript.go` (buildSysModule, sysServices dict): Register all service operations.
- `sysscript.go` (Entitlements struct): Add `AllowServiceControl bool`.

---

### 6. Drift Detection State Store

**Library:** `go.etcd.io/bbolt` — embedded pure Go key/value store. Single file on disk, no daemon, no CGO, compiles for all targets.

**Agent layer — new components:**
- `state_store.go` — new file. Wraps bbolt. Provides:
  - `SaveConvergenceState(scriptID, stateHash, snapshot []byte) error`
  - `GetConvergenceState(scriptID string) (*ConvergenceState, error)`
  - `SaveDriftReport(hostID string, report DriftReport) error`
  - `GetPendingDriftReports() ([]DriftReport, error)` — for batched sync on reconnect.

**Agent layer — modified components:**
- `main.go`: Initialize BoltDB at startup. Path: `$HOME/.systemapi/state.db` (or `/var/lib/systemapi/state.db` on Linux servers).
- `main.go` (telemetry loop): Add drift sync on connection — flush pending drift reports to server on WebSocket connect.

**Server layer — new components:**
- New PostgreSQL table `host_drift_reports` — columns: `host_id`, `script_id`, `convergence_id`, `reported_at`, `drift_items JSONB`, `auto_remediated bool`.
- New REST endpoint `GET /api/v1/systems/:hostId/drift` — returns drift history.

**Wire protocol additions:**
```
Agent → Server: { type: "drift_report", payload: { script_id, convergence_id, drift_items: [...], detected_at } }
Server → Agent: (no response required — fire and forget)
```

---

### 7. New Starlark Modules Summary

| Module | New File | Entitlement Gate | Platform |
|--------|----------|-----------------|----------|
| `sys.packages` | `sys_packages.go` | `AllowPackageInstall`, `AllowPackageRemove` | All (runtime detection) |
| `sys.services` | `sys_services_*.go` | `AllowServiceControl` | All (platform-split files) |
| `sys.process` | `sys_process.go` | `AllowProcessControl` | All (gopsutil, already dep) |
| `sys.network` | `sys_network.go` | `AllowNetInfo` | All (gopsutil + os/exec) |
| `sys.fs` (extended) | Extend `sysscript.go` | Existing FS entitlements | All |
| `sys.security` | `sys_security_*.go` | `AllowSecurityScan`, `AllowMemoryScan` | Linux/macOS (YARA CGO); Linux (memory) |
| `sys.containers` | `sys_containers.go` | `AllowContainers` | All (docker socket) |
| `sys.events` | `sys_events.go` | `AllowEventListen` | All (fsnotify — pure Go) |
| `sys.alerts` | `sys_advanced.go` (fix) | existing | All |

**sys.process:** gopsutil is already in go.mod. Add `sys_process.go` with `process.list()`, `process.kill(pid)`, `process.signal(pid, sig)`, `process.info(pid)`, `process.usage(pid)`. Pure Go, all platforms.

**sys.network:** Mix of gopsutil (already dep) for interface/connection info, and `os/exec` for firewall rules (`iptables`, `pfctl`, `netsh`). Add `sys_network.go`.

**sys.fs extended:** Add `stat`, `glob`, `mkdir`, `rm`, `chmod`, `chown`, `diff` to `sysFS` dict in `buildSysModule()`. Pure Go stdlib. Modify `sysscript.go` only.

**sys.events:** `github.com/fsnotify/fsnotify` — pure Go (uses `golang.org/x/sys` syscall wrappers, no CGO). Supports inotify (Linux), kqueue (macOS/BSD), ReadDirectoryChangesW (Windows). Add `sys_events.go`. The `eventsListen` stub in `sys_advanced.go` moves here.

---

### 8. Wire Protocol Extensions

**CommandMessage additions** (server → agent):

```go
type CommandMessage struct {
    // existing fields unchanged
    Type         string        `json:"type"`
    Script       string        `json:"script,omitempty"`
    Entitlements *Entitlements `json:"entitlements,omitempty"`
    RequestID    string        `json:"request_id"`
    Data         string        `json:"data,omitempty"`
    Rows         int           `json:"rows,omitempty"`
    Cols         int           `json:"cols,omitempty"`

    // v2.0 additions
    Mode           string      `json:"mode,omitempty"`          // "imperative" | "convergent"
    ConvergenceID  string      `json:"convergence_id,omitempty"`
    Operation      string      `json:"operation,omitempty"`     // for containers_op, service_op
    Params         interface{} `json:"params,omitempty"`        // operation-specific params
}
```

**ResponseMessage additions** (agent → server):

New `type` values the server must handle:
- `convergence_result` — convergent script result with drift diff
- `drift_report` — async drift detection event
- `security_scan_result` — YARA/memory scan output
- `containers_result` — container operation output
- `service_op_result` — service management output
- `package_op_result` — package management output

**Entitlements struct additions:**

```go
type Entitlements struct {
    // existing
    AllowFSWrite     []string `json:"allow_fs_write"`
    AllowFSRead      []string `json:"allow_fs_read"`
    AllowNetOutbound []string `json:"allow_net_outbound"`
    AllowExec        bool     `json:"allow_exec"`

    // v2.0 additions
    AllowPackageInstall  bool     `json:"allow_package_install"`
    AllowPackageRemove   bool     `json:"allow_package_remove"`
    AllowServiceControl  bool     `json:"allow_service_control"`
    AllowProcessControl  bool     `json:"allow_process_control"`
    AllowNetInfo         bool     `json:"allow_net_info"`
    AllowContainers      bool     `json:"allow_containers"`
    AllowSecurityScan    bool     `json:"allow_security_scan"`
    AllowMemoryScan      bool     `json:"allow_memory_scan"`
    AllowEventListen     bool     `json:"allow_event_listen"`
    YaraRules            []string `json:"yara_rules,omitempty"`
}
```

FleetManager must validate entitlements server-side before forwarding to agent — the agent enforces them too, but server-side check prevents unnecessary round-trips.

---

## Component Boundary Map

```
frontend/
  ContainersView.jsx      (modify — add real ops)
  SysscriptsView.jsx      (modify — add convergence mode toggle)
  SecurityView.jsx        (new)
  PackagesView.jsx        (new)
  ServicesView.jsx        (new, optional v2.0)

server.js / playground/
  fleet.js FleetManager   (modify — new message types, pushCommand method)
  routes/ (new)
    convergence.js        (new REST endpoints for convergence/drift)
    security.js           (new REST endpoints for scan results)
    containers.js         (new REST endpoints for container ops)
  PostgreSQL schema       (new tables: drift_reports, convergence_state, security_scans)

systemapi-agent/
  main.go                 (modify — CommandMessage fields, new switch cases, BoltDB init)
  sysscript.go            (modify — Entitlements fields, buildSysModule expansion)
  sys_advanced.go         (modify — remove stubs as they move to dedicated files)
  state_store.go          (new — BoltDB wrapper)
  convergence.go          (new — convergence engine wrapper)
  sys_packages.go         (new — pure Go, os/exec)
  sys_services_linux.go   (new — go-systemd/dbus)
  sys_services_darwin.go  (new — launchctl)
  sys_services_windows.go (new — PowerShell)
  sys_process.go          (new — gopsutil, already dep)
  sys_network.go          (new — gopsutil + os/exec)
  sys_containers.go       (new — docker/docker/client, pure Go)
  sys_events.go           (new — fsnotify, pure Go)
  sys_security_stub.go    (new — build tag !yara_full)
  sys_security_yara.go    (new — build tag yara_full, CGO)
  sys_security_memory.go  (new — /proc/pid/mem Linux, stubs elsewhere)
```

---

## Recommended Build Order

The ordering below respects these dependencies:
1. Wire protocol must be extended before any capability can send new message types.
2. State store must exist before convergence engine can use it.
3. Pure Go modules (no new deps) should land before CGO-gated ones.
4. Server-side schema and endpoints should land with or just before their agent counterparts.
5. Frontend views come last — they need server endpoints to exist first.

### Phase 1: Foundation — Wire Protocol + State Store
**Why first:** Every subsequent capability depends on the extended CommandMessage/Entitlements struct and the agent's ability to persist state. No capability works correctly without this base.

- Extend `CommandMessage` and `Entitlements` structs (agent + server must stay in sync)
- Add `state_store.go` (BoltDB) — initialize at agent startup
- Add `pushCommand` generalization to FleetManager (alongside existing `pushSysscript`)
- Add new message type dispatch stubs in `processIncomingMessage`
- Add new server-side message handler stubs in FleetManager `handleConnection`
- Schema migration: add `host_convergence_state`, `host_drift_reports`, `host_security_scans` tables

### Phase 2: Pure Go System Modules (no new external deps)
**Why second:** gopsutil is already in go.mod. These use `os/exec` patterns already established in `software.go`. Zero compile-constraint risk.

- `sys_process.go` — gopsutil process list/kill/signal/info
- `sys_fs` extended — stat/glob/mkdir/rm/chmod/diff in `sysscript.go`
- `sys_network.go` — gopsutil interfaces + os/exec firewall wrappers
- `sys_packages.go` — os/exec platform detection (dpkg/rpm/brew/winget)

### Phase 3: Service Management (platform-split, pure Go)
**Why third:** Requires platform-split file pattern to be established. godbus/dbus is pure Go but is a new dependency. Validates the `sys_services_*.go` build tag pattern before the more complex CGO split needed for security.

- Add `github.com/coreos/go-systemd/v22` and `github.com/godbus/dbus/v5` to go.mod
- `sys_services_linux.go`, `sys_services_darwin.go`, `sys_services_windows.go`
- Cross-compile test: `GOOS=windows GOARCH=amd64 go build` must pass

### Phase 4: Convergence Engine + Drift Detection
**Why fourth:** Depends on state store (Phase 1) and system modules (Phase 2 — convergence needs to read actual state). This is the Ansible-replacement core feature.

- `convergence.go` — wraps engine.Execute with pre/post snapshot
- `sysscript_convergent` command type dispatch
- `drift_report` message type from agent to server
- FleetManager drift report storage
- Server endpoints: `POST /converge`, `GET /drift`
- `SysscriptsView.jsx` — mode toggle + drift indicator

### Phase 5: Docker/OCI Container Management
**Why fifth:** Pure Go, new dep (`docker/docker/client`). The existing `ContainersView.jsx` is already stubbed in the frontend, making this the lowest-friction UI integration point.

- Add `github.com/docker/docker` to go.mod
- `sys_containers.go` — full container lifecycle
- `containers_op` / `containers_result` message types
- Server endpoint: `GET /systems/:hostId/containers`
- `ContainersView.jsx` — implement real operations

### Phase 6: Event Streaming (sys.events)
**Why sixth:** fsnotify is pure Go (no CGO), but the event streaming architecture (goroutines streaming back to server over WebSocket) needs careful design to avoid goroutine leaks. Deferred until other modules are working to isolate complexity.

- Add `github.com/fsnotify/fsnotify` to go.mod
- `sys_events.go` — replace stub with real watcher
- `events_start` / `events_stop` command types
- Agent: stream events as `event_notification` messages to server
- Server: forward to subscribed dashboard connections

### Phase 7: Security Scanning (CGO-gated)
**Why last:** CGO dependency breaks the pure-static-binary build. Requires parallel build pipeline. Most complex cross-compilation story. Defer until all pure-Go capabilities are proven.

- Add `github.com/hillu/go-yara/v4` to go.mod with CGO gate
- `sys_security_stub.go` (build tag `!yara_full`) — keeps default binary pure Go
- `sys_security_yara.go` (build tag `yara_full`) — CGO YARA implementation
- `sys_security_memory.go` — Linux `/proc/pid/mem` reader
- Makefile targets: `build-standard` vs `build-security`
- `SecurityView.jsx` — new view for scan results
- Server endpoint: `GET /systems/:hostId/security/scan-results`

---

## Cross-Platform Compile Constraints

| Capability | linux/amd64 | linux/arm64 | darwin/amd64 | darwin/arm64 | windows/amd64 |
|------------|:-----------:|:-----------:|:------------:|:------------:|:-------------:|
| sys.process | yes | yes | yes | yes | yes |
| sys.fs extended | yes | yes | yes | yes | yes |
| sys.network | yes | yes | yes | yes | yes |
| sys.packages | yes | yes | yes | yes | yes |
| sys.services | systemd | systemd | launchctl | launchctl | PowerShell |
| sys.containers | yes | yes | yes | yes | yes (npipe) |
| sys.events | inotify | inotify | kqueue | kqueue | ReadDirChanges |
| sys.security (YARA) | CGO build | CGO build | CGO build | CGO build | CGO+MinGW |
| sys.security (memory) | /proc | /proc | stub | stub | stub |
| convergence engine | yes | yes | yes | yes | yes |
| drift store (BoltDB) | yes | yes | yes | yes | yes |

**CGO isolation strategy:** Default `go build` produces pure-Go binary without YARA. A `go build -tags yara_full` produces the security-capable binary. The Dockerfile and CI pipeline must produce both artifacts with distinct names (`systemapi-agent` and `systemapi-agent-security`).

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Global mutable state for new sessions
**What goes wrong:** The existing `activePTY` in `pty.go` is a global singleton — only one PTY session per agent. The same pattern applied to containers or events would allow only one operation at a time.
**Prevention:** Use a `sync.Map` keyed by `request_id` for all stateful operations (event listeners, container log streams).

### Anti-Pattern 2: Blocking Starlark thread on long operations
**What goes wrong:** `eventsListen` in the current stub would block the Starlark execution thread indefinitely if implemented naively.
**Prevention:** Starlark `events.listen` should register a listener goroutine and return immediately. The goroutine sends `event_notification` messages over WebSocket independently of the script execution lifecycle.

### Anti-Pattern 3: Drift report loss on disconnect
**What goes wrong:** If the agent disconnects while a drift check is in-flight, the report is lost.
**Prevention:** Write drift reports to BoltDB first, then attempt WebSocket send. On reconnect, flush pending reports. The `state_store.go` `GetPendingDriftReports()` method handles this.

### Anti-Pattern 4: Breaking the telemetry loop with heavy operations
**What goes wrong:** Expensive operations (package list, YARA scan) run in the same goroutine as the 5s telemetry tick.
**Prevention:** All `sys.*` module calls run in the goroutine spawned by `processIncomingMessage` — already separate from the telemetry ticker. Confirm this stays true as new dispatchers are added.

### Anti-Pattern 5: Server-only entitlement enforcement
**What goes wrong:** FleetManager already validates entitlements before forwarding, but if this is the only check, a compromised server can grant any capability.
**Prevention:** Keep agent-side entitlement checks in every builtin. Both layers enforce — defense in depth.

---

## Sources

- Direct inspection: `systemapi-agent/main.go`, `sysscript.go`, `sys_advanced.go`, `telemetry.go`, `software.go`, `pty.go`, `go.mod`
- Direct inspection: `playground/fleet.js`, `playground/playground_fleet_schema.sql`, `server.js`
- go-yara CGO requirements: https://pkg.go.dev/github.com/hillu/go-yara/v4 (HIGH confidence)
- docker/docker/client pure Go status: https://pkg.go.dev/github.com/docker/docker/client (HIGH confidence)
- godbus/dbus pure Go status: https://pkg.go.dev/github.com/godbus/dbus/v5 (HIGH confidence)
- fsnotify CGO status: https://github.com/fsnotify/fsnotify README + go.mod (HIGH confidence — only deps `golang.org/x/sys`, no CGO)
- go-systemd cross-platform scope: https://pkg.go.dev/github.com/coreos/go-systemd/v22/dbus (HIGH confidence — Linux-only intentionally)
- gopsutil process API: https://pkg.go.dev/github.com/shirou/gopsutil/v3/process (HIGH confidence)
- bbolt API: Context7 `/etcd-io/bbolt` (HIGH confidence)
