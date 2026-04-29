# Technology Stack: SystemAPI.io v2.0 — New Capabilities

**Project:** SystemAPI.io v2.0 Next-Gen Systems Management
**Researched:** 2026-04-28
**Scope:** Go agent additions only — Node.js server and React frontend stack unchanged.

---

## Existing Agent Stack (Validated — Do Not Re-research)

| Package | Version | CGO? | Role |
|---------|---------|------|------|
| `go.starlark.net` | v0.0.0-20260210143700 | No | Starlark scripting engine |
| `github.com/gorilla/websocket` | v1.5.3 | No | WebSocket client |
| `github.com/creack/pty` | v1.1.24 | No (uses syscall) | PTY sessions |
| `github.com/shirou/gopsutil/v3` | v3.24.5 | No | Telemetry (CPU/mem/disk) |

---

## Capability 1: YARA Scanning (`sys.security.yara_scan`)

| Library | Version | CGO? | Notes |
|---------|---------|------|-------|
| `github.com/hillu/go-yara/v4` | v4.3.4 | **YES — HARD REQUIREMENT** | Wraps libyara C library. Requires libyara 4.3 headers + GCC at build time. |

**Why this library:** Only production-grade YARA binding for Go. YARA-X (the Rust rewrite) has no Go bindings. There is no pure-Go YARA engine — `gyp` (VirusTotal/gyp) only parses YARA rule syntax into an AST, it cannot execute rules against files.

**Static binary constraint: BROKEN without explicit workaround.** YARA introduces a CGO dependency that makes standard `CGO_ENABLED=0` static builds impossible for the YARA-enabled binary. Resolution options:

1. **Recommended — Split binary:** Compile a second agent variant (`systemapi-agent-security`) with YARA enabled and `CGO_ENABLED=1`. The base agent stays pure-Go static. The security agent is distributed separately and only required when `sys.security` entitlements are declared.
2. **Alternative — Static libyara:** Use `-tags yara_static -ldflags="-extldflags '-static'"` with a pre-built static libyara. Works on Linux/macOS but Windows requires MSYS2/MinGW. Cross-compilation requires a cross-toolchain with target libyara pre-built for each GOOS/GOARCH — significant CI complexity.
3. **Alternative — Stub with exec:** Keep the base binary pure-Go, invoke `yara` CLI tool via `sys.exec.run` if present on the host. Lower fidelity but zero CGO.

**Cross-compilation:** go-yara supports linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, and windows/amd64 — but each target requires a cross-compiling GCC toolchain and a pre-built libyara for that target. See `README.cross-building.md` in the go-yara repo.

**Confidence:** HIGH (pkg.go.dev verified, v4.3.4 published Jul 2025)

---

## Capability 2: Docker/OCI Container Management (`sys.containers`)

| Library | Version | CGO? | Notes |
|---------|---------|------|-------|
| `github.com/docker/docker/client` | v28.5.2+incompatible | **No** | Official Docker Engine API client. Communicates via Unix socket or TCP to dockerd. |
| `github.com/docker/docker/api/types/container` | same module | No | Container config/inspect types used alongside the client. |
| `github.com/google/go-containerregistry/pkg/crane` | v0.21.5 | **No** | Pure-Go OCI registry pull/push without requiring a running Docker daemon. Use for image inspection, pulling to tarball. |

**Why docker/docker client:** This is the canonical Go client for the Docker Engine API (12,458+ importers). It is pure Go — communicates over the Docker socket, no CGO. Covers: ContainerList, ContainerCreate, ContainerStart, ContainerStop, ContainerRemove, ContainerLogs, ContainerExec, ImagePull, ImagePush, ImageList, RegistryLogin.

**Why go-containerregistry (crane):** Handles OCI image pull/push directly against registries (no daemon required). Useful for environments where Docker is present but `dockerd` is not running, or for implementing `sys.containers.pull` without daemon dependency. Apache-2.0, pure Go, maintained by Google.

**Note on `+incompatible`:** `github.com/docker/docker` has not migrated to Go modules properly (still v28 on the v1 module path). This is normal for this package — all major Docker tooling uses it this way. Pin to a specific version in `go.mod`.

**Security note (confirmed):** pkg.go.dev flags 2 known vulnerabilities (GO-2026-4883, GO-2026-4887) against v28.5.2 as of research date. Check `go vuln` before shipping and update to latest patch.

**Cross-compilation:** No issues. Pure Go, compiles for all targets.

**Confidence:** HIGH (pkg.go.dev verified)

---

## Capability 3: Cross-Platform Package Management (`sys.packages`)

No external library required. Implement via `os/exec` + platform detection.

| Approach | Library | CGO? | Notes |
|---------|---------|------|-------|
| OS/distro detection | `github.com/shirou/gopsutil/v4/host` | **No** | `host.Info()` returns `Platform` (ubuntu, rhel, etc.) and `PlatformFamily` (debian, rhel). Upgrade existing gopsutil/v3 to v4. |
| Package manager invocation | stdlib `os/exec` | No | Shell out to `apt`, `dnf`, `brew`, `winget` with structured arg building. |

**Pattern:** Detect platform once at agent startup via `gopsutil/v4/host.PlatformInformation()`, store in agent state, then select the correct package manager command at `sys.packages.install` call time. This mirrors how tools like Ansible's `package` module work.

**Package manager mapping:**
- `PlatformFamily == "debian"` → `apt-get install -y <name>`
- `PlatformFamily == "rhel"` → `dnf install -y <name>` (or `yum` on older RHEL)
- `GOOS == "darwin"` → `brew install <name>`
- `GOOS == "windows"` → `winget install --id <name> -e`

**Note on gopsutil v3 → v4 upgrade:** The existing agent uses v3.24.5. v4.26.3 (Mar 2026) is the current stable — same pure-Go, same API surface with context-aware variants. Upgrade is low-risk. Import path changes from `gopsutil/v3/...` to `gopsutil/v4/...`.

**Cross-compilation:** No issues — pure Go, platform selection happens at runtime not compile time.

**Confidence:** HIGH

---

## Capability 4: System Service Management (`sys.services`)

| Library | Version | CGO? | Platform | Notes |
|---------|---------|------|---------|-------|
| `github.com/coreos/go-systemd/v22/dbus` | v22.7.0 | **No** | Linux | systemd control via D-Bus. StartUnit, StopUnit, RestartUnit, ListUnits, GetUnitProperties. |
| `github.com/godbus/dbus/v5` | v5.2.2 | **No** | Linux | go-systemd depends on this internally. May be needed directly for subscription/watch. |
| `golang.org/x/sys/windows/svc/mgr` | part of x/sys | **No** | Windows | Windows SCM: Connect, OpenService, Start, Control (Stop/Pause), Query, ListServices. |
| stdlib `os/exec` (launchctl) | stdlib | No | macOS | No Go library needed — `launchctl load/unload/start/stop/list` is the native interface. |

**Why go-systemd/dbus over godbus/dbus directly:** `go-systemd/dbus` provides a high-level typed API specifically for systemd (StartUnitContext, StopUnitContext, GetAllPropertiesContext, SubscribeUnitsContext). Using godbus/dbus raw requires constructing D-Bus method calls manually.

**CGO caveat in go-systemd:** The `sdjournal` subpackage requires CGO — but we only need the `dbus` subpackage, which is pure Go. Import only `github.com/coreos/go-systemd/v22/dbus`, never `sdjournal`.

**macOS launchctl strategy:** `launchctl list | grep <label>` for status, `launchctl load /Library/LaunchDaemons/<plist>` for enable, `launchctl start <label>` for start. Implement via `os/exec`. No library needed.

**Windows SCM strategy:** `golang.org/x/sys/windows/svc/mgr` provides `Connect() → OpenService(name) → Start() / Control(svc.Stop) / Query()`. Already an indirect dependency via gopsutil.

**Cross-compilation:** go-systemd and godbus are Linux-only at runtime but compile cleanly for all GOOS — use build constraints (`//go:build linux`) to guard usage. x/sys/windows compiles only on windows.

**Confidence:** HIGH (go-systemd v22.7.0 Jan 2026 verified; godbus v5.2.2 Dec 2025 verified)

---

## Capability 5: Cross-Platform Process Management (`sys.process`)

| Library | Version | CGO? | Notes |
|---------|---------|------|-------|
| `github.com/shirou/gopsutil/v4/process` | v4.26.3 | **No** | List all PIDs, inspect per-process (name, cmdline, memory, CPU, open files, connections). Kill, Terminate, SendSignal, Suspend, Resume. Cross-platform. |

**Why gopsutil v4:** Already the established dependency for telemetry. v4 process package covers Linux/macOS/Windows with pure Go (no CGO). "All works are implemented without cgo by porting C structs to Go structs." Signal sending (SIGKILL, SIGTERM, arbitrary signals) works on Linux/macOS; Windows uses TerminateProcess internally.

**Windows signal caveat:** POSIX signals do not exist on Windows. `SendSignal` on Windows only works for SIGKILL equivalent (TerminateProcess). `Suspend/Resume` map to NtSuspendProcess/NtResumeProcess.

**Upgrade action:** Bump existing `gopsutil/v3` to `gopsutil/v4` — same effort benefits both telemetry and process management.

**Confidence:** HIGH (pkg.go.dev v4.26.3 Mar 2026 verified)

---

## Capability 6: File System Event Watching (`sys.events`)

| Library | Version | CGO? | Backend Used | Notes |
|---------|---------|------|-------------|-------|
| `github.com/fsnotify/fsnotify` | v1.9.0 | **No** | inotify (Linux), kqueue (macOS), ReadDirectoryChangesW (Windows) | Cross-platform FS event watcher. Pure Go via x/sys syscall wrappers. |

**Why fsnotify:** Standard Go ecosystem choice (13,659+ importers). Handles all three OS backends without CGO. API is simple — `NewWatcher()`, `watcher.Add(path)`, range over `watcher.Events` channel. Events: Create, Write, Remove, Rename, Chmod.

**Recursive watching:** fsnotify v1.x does NOT support recursive directory watching natively (must call `Add` on each subdirectory). For `sys.events.listen` on a tree, implement a helper that walks and adds subdirs, then handles Create events to add newly-created subdirs.

**ETW note:** The Windows backend uses `ReadDirectoryChangesW` (not ETW). ETW (Event Tracing for Windows) is a different, lower-level system event tracing API used for process/network events. fsnotify covers file system events only. If ETW-level process/network events are needed later, that is a separate capability (no mature pure-Go ETW library exists; would require CGO or PowerShell subprocess).

**Confidence:** HIGH (pkg.go.dev v1.9.0 Apr 2025 verified)

---

## Capability 7: State Store for Drift Detection

| Library | Version | CGO? | Notes |
|---------|---------|------|-------|
| `go.etcd.io/bbolt` | v1.4.3 | **No** | Pure-Go embedded B+tree key/value store. ACID transactions. Single file on disk. No external process needed. |

**Why bbolt over SQLite (mattn/go-sqlite3 requires CGO) or file-based JSON:**
- SQLite via `mattn/go-sqlite3` requires CGO — breaks static binary constraint.
- File-based JSON with `os.WriteFile` has no atomic transaction semantics — risk of corruption on agent crash mid-write.
- bbolt is pure Go, embedded, ACID, and used in production at scale (etcd, Consul use it). Single `.db` file per agent.

**Why not modernc.org/sqlite (pure-Go SQLite):** bbolt is simpler and more appropriate for the use case (key/value state, not relational queries). `modernc.org/sqlite` is an option if structured queries are needed — it is pure Go with no CGO — but bbolt is lighter.

**State store schema design:**
- Bucket: `sysscript_state` → key: `<script_id>` → value: JSON blob `{applied_at, desired_state, last_hash}`
- Bucket: `host_facts` → key: `<fact_name>` → value: serialized fact

**Windows support:** bbolt works on Windows. File locking is enforced (exclusive write lock). Works correctly on all target platforms.

**Confidence:** HIGH (pkg.go.dev v1.4.3 Aug 2025 verified)

---

## Capability 8: Declarative State Convergence (Ansible-like Idempotency)

No external library required — this is a pattern, not a package.

**Pattern:** Implement a `Converge(desired StateSnapshot) (changed bool, err error)` function per resource type. Each converge function follows:
1. **Read current state** (using gopsutil, os/exec, docker client, etc.)
2. **Diff against desired state** (compare struct fields or hashes)
3. **If drift detected, apply changes** (install package, start service, write file, etc.)
4. **Re-read and verify** (optional but recommended — "test-after-apply")
5. **Return `changed=true/false`** so the Starlark script can report what happened

**Starlark integration pattern:**
```
# In Starlark, the convergence is expressed declaratively:
result = sys.state.ensure({
    "packages": ["nginx", "curl"],
    "services": [{"name": "nginx", "state": "running"}],
    "files": [{"path": "/etc/nginx/nginx.conf", "content": config_content}]
})
print("changed:", result.changed)
```

**State hash for drift detection:** Store SHA-256 of last-applied desired state in bbolt. On next run, hash current desired state spec. If hashes match and verification passes, skip — idempotent with O(1) skip cost.

**No external convergence library needed:** Puppet/CFEngine/Salt all have their own DSLs. For SystemAPI.io, the convergence logic lives in the Go agent's `sys.state` module with bbolt as backing store and Starlark as the expression layer.

**Confidence:** HIGH (pattern-based, no library uncertainty)

---

## Capability 9: Cross-Compilation Targets

**Current agent:** `go 1.25.7` (go.mod). This is ahead of any Go release I can verify — treat as `go 1.24` semantically for compatibility purposes. All libraries below are verified compatible with Go 1.20+.

| Target | Notes |
|--------|-------|
| `linux/amd64` | Native. All libraries work. YARA requires CGO + cross-linker if building on non-Linux. |
| `linux/arm64` | Pure-Go libraries compile with `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`. YARA requires arm64 libyara + GCC cross-toolchain. |
| `darwin/amd64` | Pure-Go libraries compile with `GOOS=darwin GOARCH=amd64 CGO_ENABLED=0`. Apple cross-SDK required for CGO. |
| `darwin/arm64` | Same as darwin/amd64. M1/M2/M3 targets. |
| `windows/amd64` | Pure-Go libraries compile with `GOOS=windows GOARCH=amd64 CGO_ENABLED=0`. Windows-specific packages (svc/mgr) compile only on this target. YARA requires MSYS2/MinGW on Windows or cross-compilation from Linux with mingw-w64. |

**Build matrix recommendation:**
```
# Pure-Go base agent (no YARA):
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o agent-linux-amd64
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o agent-linux-arm64
CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -o agent-darwin-amd64
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o agent-darwin-arm64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o agent-windows-amd64.exe

# YARA-enabled agent (separate build, CGO required):
# Build natively on each target OS or use Docker cross-compilation with pre-built libyara
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags yara_static \
  -ldflags="-extldflags '-static'" -o agent-security-linux-amd64
```

---

## Summary: CGO Impact Matrix

| Capability | Library | CGO? | Static Binary Impact |
|------------|---------|------|---------------------|
| YARA scanning | go-yara/v4 | **YES** | Breaks `CGO_ENABLED=0`. Requires split binary or static libyara. |
| Docker containers | docker/docker client | No | None |
| OCI registry | go-containerregistry | No | None |
| Package management | gopsutil/v4 + os/exec | No | None |
| Service mgmt (Linux) | go-systemd/v22/dbus | No | None (avoid sdjournal subpkg) |
| Service mgmt (Windows) | x/sys/windows/svc/mgr | No | None |
| Process management | gopsutil/v4/process | No | None |
| FS event watching | fsnotify | No | None |
| State store | bbolt | No | None |
| OS detection | gopsutil/v4/host | No | None |

**Net conclusion:** All capabilities except YARA are pure-Go and maintain the static single-binary constraint. YARA must be isolated into a separate binary or build variant. The base agent serving all non-security Sysscripts remains a zero-dependency static binary.

---

## Recommended `go.mod` Additions

```
require (
    // Upgraded (already present as v3)
    github.com/shirou/gopsutil/v4 v4.26.3

    // New additions — pure Go
    github.com/docker/docker         v28.5.2+incompatible
    github.com/google/go-containerregistry v0.21.5
    github.com/coreos/go-systemd/v22 v22.7.0
    github.com/godbus/dbus/v5        v5.2.2
    github.com/fsnotify/fsnotify     v1.9.0
    go.etcd.io/bbolt                 v1.4.3

    // New addition — CGO required, security binary only
    github.com/hillu/go-yara/v4      v4.3.4
)
```

---

## Sources

| Claim | Source | Confidence |
|-------|--------|------------|
| go-yara v4.3.4, CGO required, yara_static tag | pkg.go.dev/github.com/hillu/go-yara/v4 | HIGH |
| docker/docker v28.5.2 pure Go | pkg.go.dev/github.com/docker/docker/client | HIGH |
| go-containerregistry v0.21.5 pure Go | pkg.go.dev/google/go-containerregistry/pkg/crane (Apr 2026) | HIGH |
| gopsutil v4.26.3 pure Go, no CGO | pkg.go.dev/github.com/shirou/gopsutil/v4 (Mar 2026) | HIGH |
| go-systemd v22.7.0, dbus pkg pure Go, sdjournal CGO | pkg.go.dev/github.com/coreos/go-systemd/v22 (Jan 2026) | HIGH |
| godbus/dbus v5.2.2 pure Go | pkg.go.dev/github.com/godbus/dbus/v5 (Dec 2025) | HIGH |
| fsnotify v1.9.0 pure Go, inotify/kqueue/ReadDirChangesW | pkg.go.dev/github.com/fsnotify/fsnotify (Apr 2025) | HIGH |
| bbolt v1.4.3 pure Go, Windows supported | pkg.go.dev/go.etcd.io/bbolt (Aug 2025) | HIGH |
| x/sys/windows/svc/mgr pure Go SCM access | pkg.go.dev/golang.org/x/sys/windows/svc/mgr | HIGH |
| gopsutil v4 host.PlatformInformation() distro detection | pkg.go.dev/github.com/shirou/gopsutil/v4/host | HIGH |
