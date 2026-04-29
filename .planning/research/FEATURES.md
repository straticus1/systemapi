# Feature Landscape: SystemAPI.io v2.0

**Domain:** Fleet systems management platform (Ansible/Terraform alternative)
**Researched:** 2026-04-28
**Confidence:** HIGH — based on direct codebase inspection, existing stub analysis, schema review, and domain knowledge of Ansible/Chef/Puppet ecosystem patterns

---

## How to Read This Document

Each feature area is assessed against three axes:

- **Table Stakes** — What operators expect. Missing = product feels broken or untrustworthy.
- **Differentiators** — What makes SystemAPI.io better than Ansible/Chef/Puppet. These are the "why switch" reasons.
- **Anti-Features** — Complexity traps that add implementation cost without user value, or that violate the project's core model (WebSocket-only, Starlark-sandboxed, single binary).

Dependencies between features are noted where one feature's value depends on another being present.

---

## Feature 1: Declarative State Management (Ansible/Terraform Replacement)

The flagship value proposition of v2.0. Sysscripts already run imperatively; this adds convergence semantics.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| Convergence mode: script declares desired state, engine applies only what changed | This IS the Ansible replacement promise — without it the product is just remote exec | High |
| Idempotent execution: running the same script twice produces the same result | Standard contract of all config management tools | Medium |
| Dry-run / preview mode: show what WOULD change before applying | Ansible's `--check` flag. Operators won't run blind on production | Medium |
| Execution report: what was changed, what was already correct, what failed | Terraform's plan/apply output pattern. Required for audit | Medium |
| Both declarative AND imperative modes per script | Starlark already does imperative. Declarative mode must be addable without rewriting | High |
| Entitlement enforcement carries through convergence mode | The security model cannot have a bypass path in convergence | Low (already exists) |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Convergence runs in the agent (no control node) | Ansible requires a control machine with SSH access. SystemAPI agents converge themselves via WebSocket. Zero inbound ports. | Low — agent-local execution is already the model |
| Real-time convergence status streamed back | Ansible shows output only after completion. WebSocket lets you watch each step converge live. | Medium |
| Script-level entitlements on convergence runs | Ansible has no per-playbook capability sandboxing. A Sysscript must declare exactly what it needs. | Low — entitlements already exist |
| Starlark convergence = Python-readable, no YAML | Ansible YAML is notoriously fragile (indentation errors, quoting). Starlark is deterministic and has real control flow. | Low — Starlark is already the engine |
| Single binary — no Python, no pip, no virtualenv on managed host | Ansible requires Python on every managed node. SystemAPI agent is a static Go binary. | Low — already achieved |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Custom DSL for declaring desired state | PROJECT.md explicitly out-of-scope. Starlark IS the DSL. | Use Starlark functions/decorators as the state declaration mechanism |
| Global convergence lock (one script at a time per host) | Deadlock risk in fleet-wide operations. Fine-grained locking per resource category is correct. | Lock at resource level (package X, service Y), not globally |
| Pulling state from a central "state file" like Terraform tfstate | Distributed state stores are a major operational burden. | Keep state per-host in the agent's local store; server holds aggregate view only |
| Requiring network connectivity to converge | If the agent can't reach the server, it should still be able to re-apply its last known desired state. | Store last-applied script locally; apply on reconnect |

### Dependencies

- Depends on: **Drift Detection** (Feature 10) to know what has changed
- Enables: **Drift Detection** to compare desired state vs actual state
- Depends on: **State Store** (per-host, server-side aggregate) being built before convergence reporting is meaningful

---

## Feature 2: Security Scanning (YARA, CVE, Memory)

Stubs exist in `sys_advanced.go`. Must become real implementations.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| YARA rule scanning of files/directories | Security teams require signature-based detection. Without it the "security scanning" claim is empty. | High — requires CGo or pure-Go YARA library |
| CVE matching against installed software inventory | CVE alerting already has DB tables (`playground_host_cves`). Users expect this to actually fire. | Medium — NVD/OSV feed integration |
| Alert push on scan findings | `sys.alerts.push` stub exists. Must actually send back through the WebSocket. | Medium |
| Per-scan entitlement enforcement | A script must declare `allow_security_scan` to invoke YARA or memory scan — no implicit elevated privilege | Low |
| Scan results persisted and queryable | One-time scan output that isn't stored is useless for compliance and trending. | Medium |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Memory scanning of running processes | Detects injected shellcode, reflective DLL injection. Most SIEM tools don't reach into process memory from a management agent. | Very High — platform-specific (Linux: `/proc/PID/mem`, macOS: `vm_read`, Windows: `ReadProcessMemory`) |
| Real-time file-change triggered YARA scan | Watch a directory with `sys.events.listen`, auto-scan new/modified files. Combines Feature 7 (FS watch) with security scanning. | High |
| YARA rules as Sysscript-managed config | Operators can push new YARA rules via Sysscript to update detection without redeploying the agent. | Medium |
| Tie CVE alerts to package management | When `sys.packages.install` installs a version, auto-check it against the CVE DB. | Medium — requires Feature 3 integration |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Bundling a full AV engine in the agent binary | Binary size explosion, false positive management nightmare, vendor lock-in | Use YARA (signature-based, operator-controlled rules) |
| Scanning memory of ALL processes continuously | CPU/memory overhead renders the agent's host unusable | Scan on-demand or on specific triggers (exec of unknown binary, network connection spike) |
| Storing raw memory dumps on-host | Storage exhaustion risk, PII/secrets exposure | Scan in-memory, emit only match findings (rule name, offset, PID) |
| Building a CVE feed scraper | NVD and OSV already provide APIs and public feeds. Re-scraping is wasted effort. | Consume OSV API (open, well-structured, Google-maintained) |

### Dependencies

- Depends on: **Software Inventory** (already exists in `playground_host_software` table)
- Depends on: **sys.alerts.push** being a real WebSocket push, not just a log statement (currently a stub)
- Depends on: **sys.events.listen** for real-time scan trigger (Feature 7)
- Integrates with: **Package Management** (Feature 3) for install-time CVE check

---

## Feature 3: Package Management (dnf, apt, brew, winget)

Stub in `sys_advanced.go`: `packagesInstall` logs and returns true.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| Install a named package | The stub already promises this. Must actually invoke the right package manager for the host's platform. | Medium — platform detection exists via gopsutil |
| Remove/uninstall a package | Install without remove is half a feature. Config management requires both. | Medium |
| Query installed packages (list) | Required for inventory, CVE matching, and drift detection. | Low — `gatherSoftware()` already exists in telemetry |
| Check if package is installed | Needed for idempotent convergence: "install nginx if not installed" | Low |
| Pin a version (install specific version) | Production ops require version pinning to avoid surprise upgrades | Medium — package manager APIs differ |
| Cross-platform: dnf (RHEL/Rocky), apt (Debian/Ubuntu), brew (macOS), winget (Windows) | The four target platforms are explicit in PROJECT.md | High — four separate code paths |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Package install with entitlement audit trail | Every `sys.packages.install` call logged with who triggered it, what package, what version — Ansible has no built-in per-package audit trail | Low — execution audit table already exists |
| Fleet-wide package inventory with CVE overlay | Show all hosts, what packages they have, which have known CVEs. Ansible requires a separate role + Lynis/OpenSCAP. | Medium |
| Install-time CVE check with optional block | Before installing, check OSV for known vulns in requested version. Block or warn based on policy. | Medium |
| Package diff across fleet | "These 12 hosts have nginx 1.24, these 3 have 1.22.1 — here's the CVE delta" | Medium |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Custom package format or local package repository | Enormous scope creep. Adds infrastructure ops burden on users. | Use existing system package managers; optionally support direct URL installs |
| Parallel install across all packages in one call | Package manager locking (dpkg lock, rpm db) makes this deadlock-prone | Queue installs serially per host; allow parallel across hosts |
| Auto-updating packages on telemetry events | Silent auto-updates are how production breaks on a Friday night | Always require explicit `sys.packages.install` invocation; alerts are informational only |
| Homebrew on Linux | Homebrew on Linux is rarely used and adds significant path complexity | Linux uses dnf or apt; brew is macOS-only |

### Dependencies

- Depends on: Platform detection (via gopsutil `host.Info()` — already in telemetry)
- Depends on: Entitlements system (new `allow_packages` entitlement needed)
- Enables: **Security Scanning** CVE-on-install check
- Enables: **Drift Detection** package version tracking

---

## Feature 4: Service Management (systemd, launchd, Windows SCM)

Not yet stubbed. Complete new `sys.services` module.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| Start / stop / restart a service | Core config management primitive. Without this, deploying a package and starting it requires raw `sys.exec.run`. | Low — thin wrapper around systemctl/launchctl/sc.exe |
| Enable / disable (persist across reboots) | Start without enable is half the operation for long-running services | Low |
| Status query: is the service running, its PID, its restart count | Required for convergence check ("is nginx up?") and health monitoring | Low |
| List all services (running and stopped) | Inventory and audit requirement | Low |
| Cross-platform: systemd (Linux), launchd (macOS), SCM (Windows) | PROJECT.md lists all three explicitly | Medium — three code paths |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Service convergence in Sysscript | `services.ensure("nginx", state="running", enabled=True)` — idempotent single call | Low once service primitives exist |
| Service restart on config file change | Combined with `sys.fs.watch` (Feature 7): write a config, detect the change, restart the service automatically | Medium |
| Service failure alert integration | If a service that was `ensure`d running goes offline, push an alert via `sys.alerts` | Medium — requires periodic health check loop in agent |
| Unified status across fleet | Dashboard shows all services across all hosts in one view, not per-host SSH one-at-a-time | Low — server aggregates telemetry |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Implementing a process supervisor (like supervisord) | Existing init systems (systemd/launchd/SCM) are the right supervisors | Wrap the platform init system, don't replace it |
| Watching service logs in real-time from the agent | This overlaps with PTY terminal and creates unbounded data streams | Use PTY terminal for log tailing; service management is state only |
| Creating/managing systemd unit files via this module | Unit file templating is a Sysscript `sys.fs.write` concern, not `sys.services` | Keep concerns separate: fs writes the unit file, services enables it |

### Dependencies

- Depends on: Entitlements system (new `allow_services` entitlement)
- Depends on: Platform detection
- Pairs with: **Package Management** (install then start is the common pattern)
- Pairs with: **Filesystem Extended** (write config, restart service)
- Enables: **Drift Detection** service state tracking

---

## Feature 5: Process Management (list, kill, signal, resource per process)

Not yet stubbed. New `sys.process` module.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| List all processes (PID, name, CPU%, memory, user) | Every config management and security tool can enumerate processes | Low — gopsutil `process` package already available |
| Kill a process by PID | Basic process management. Required for remediation scripts. | Low |
| Send arbitrary signal (SIGTERM, SIGHUP, SIGKILL, SIGUSR1) | SIGHUP for config reload, SIGUSR1 for log rotation — standard ops patterns | Low on Linux/macOS; Windows signals are different |
| Per-process resource usage (CPU, memory, open files, network connections) | Needed for identifying runaway processes and resource leak detection | Low — gopsutil covers this |
| Find process by name | Operators write `kill process named "runaway_worker"` not `kill PID 48291` | Low |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Scriptable process remediation | "If any process is using >90% CPU for >5 minutes, send SIGTERM, wait 10s, then SIGKILL" — fully expressible in Starlark | Low once primitives exist |
| Process list as convergence input | Convergence script can assert "exactly one nginx worker should be running" and enforce it | Medium |
| Correlated with security scanning | List processes, then `sys.security.scan_memory(pid)` on unknown PIDs | Low — both modules present |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Process tree manipulation (reparenting, namespace management) | Container management territory; avoid conflation | Use `sys.containers` for namespace isolation |
| Continuous process monitoring loop in the agent's main goroutine | Blocks telemetry and command handling | Process queries are on-demand; persistent monitoring is done via alert rules on telemetry |
| Implementing a process debugger / ptrace interface | Enormous complexity, kernel version sensitivity, security risk | Out of scope; `sys.exec.run` with `strace` is available for experts |

### Dependencies

- Depends on: gopsutil (already imported in telemetry)
- Depends on: Entitlements (new `allow_process_kill` entitlement — signal/kill must be separately gated from list)
- Pairs with: **Security Scanning** (scan memory of suspicious processes)
- Pairs with: **Service Management** (kill and restart pattern)

---

## Feature 6: Container Management (Docker/OCI lifecycle)

Stub in `sys_advanced.go`: `containersRun` logs and returns true.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| List containers (running and stopped) | Every container tool shows a container list. Non-negotiable baseline. | Low — Docker API via unix socket |
| Run a container (image, env, ports, volumes, restart policy) | The stub promises this. Must actually call Docker. | Medium |
| Stop / kill a container | Run without stop is not usable. | Low |
| Remove a container | Cleanup is required for convergence. | Low |
| Pull an image (from registry) | Converging to a new image version requires pulling first. | Low |
| List images | Inventory and cleanup workflows require knowing what images exist locally. | Low |
| Exec into a running container (get output) | Required for health checks inside containers from a Sysscript. | Medium |
| Stream container logs (last N lines) | Every ops team needs "show me the last 100 lines of the nginx container log" | Low |
| Volume management: create, list, remove | Stateful containers require persistent volumes | Medium |
| Network management: create, list, connect, remove | Multi-container networking is a standard Docker workflow | Medium |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Starlark-scripted container convergence | `containers.ensure("nginx", image="nginx:1.25", state="running", ports={"80":"80"})` — idempotent, declarative. Docker Compose requires a separate file format. | Medium |
| Cross-host container fleet view | See all containers across all managed hosts in one dashboard view. Docker Desktop only shows local. Portainer requires a separate agent. | Low — server aggregates |
| Container CVE scanning via sys.security + sys.containers | Pull an image manifest, check layers against OSV/NVD, surface vulnerable base images | High — requires image layer parsing |
| No Kubernetes required | SystemAPI manages containers directly without a k8s cluster. For small-to-medium fleets, k8s is overkill. | Low — explicitly out of scope per PROJECT.md |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Implementing Docker Compose YAML parsing | Adds a YAML parser, a separate execution model, and diverges from Starlark | Express compose-style relationships in Starlark; call container primitives from a script |
| Kubernetes / pod / deployment management | Explicitly out of scope in PROJECT.md | Refer users to kubectl / Helm for k8s workloads |
| Building a container image (docker build) | Build pipelines belong in CI/CD, not in a systems management agent | Agents pull pre-built images; building is out of scope |
| Mounting host paths without entitlement enforcement | Any container with arbitrary volume mounts can escape the host filesystem | Volume mounts must be validated against `allow_fs_write` entitlements |
| Streaming real-time container log tails from agent to server | Unbounded data stream; network bandwidth risk on high-log containers | Return last N lines on demand; use PTY terminal for live tailing |

### Dependencies

- Depends on: Docker daemon running on managed host (agent communicates via `/var/run/docker.sock` or named pipe on Windows)
- Depends on: Entitlements (new `allow_containers` entitlement; volume mounts cross-checked against `allow_fs_write`)
- Enables: Container inventory view in frontend
- Integrates with: **Security Scanning** for image vulnerability assessment

---

## Feature 7: Filesystem Extended (stat, glob, mkdir, rm, chmod, chown, diff, watch)

Existing: `sys.fs.read` and `sys.fs.write` are implemented. All other operations are missing.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| `stat(path)` — size, mtime, permissions, owner | Required to write any convergence check: "does this file exist, is it the right size?" | Low |
| `glob(pattern)` — list matching files | Essential for any script operating on a set of files | Low |
| `mkdir(path, recursive)` — create directories | Writing a file to a non-existent directory path is a common pattern | Low |
| `rm(path, recursive)` — remove files/directories | Convergence requires removing files that should not exist | Low — requires entitlement enforcement |
| `chmod(path, mode)` — change permissions | Config files often require specific permissions (ssh keys = 0600) | Low — Linux/macOS only; Windows has ACLs |
| `chown(path, user, group)` — change ownership | Service config files often must be owned by the service user | Low |
| `diff(path_a, path_b)` — compare two files | Required for drift detection: "is this file different from what we deployed?" | Low |
| `watch(path, callback)` — notify on file change | Required for reactive automation: write config, detect change, restart service | High — platform-specific (inotify/kqueue/ReadDirectoryChangesW) |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| `sys.fs.diff` integrated with drift detection | Detect that a config file was manually edited and show the exact diff in the dashboard | Low once diff exists |
| `sys.fs.watch` triggering Starlark callbacks | React to file changes in real-time without polling. Ansible has no equivalent — it's push-only, not event-driven. | High |
| Entitlement-gated `rm -rf` equivalents | Unrestricted recursive delete is dangerous. SystemAPI enforces path-prefix allowlist on every destructive FS operation. | Low — extends existing entitlement model |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Streaming file content (large file download through WebSocket) | Memory exhaustion on large files; WebSocket is not a file transfer protocol | Support chunked reads with offset/limit parameters; for large file ops use `sys.exec.run` with rsync |
| Implementing a file sync protocol (rsync-equivalent) | Massive scope. File sync is a solved problem. | Use `sys.exec.run` to invoke rsync/scp if file sync is needed |
| `watch` with unbounded event queuing | High-activity directories generate thousands of events per second | Rate-limit/debounce watch events; collapse rapid-fire changes into a single callback |
| Recursive stat on large directory trees | I/O blocking, can take minutes on large filesystems | Glob + selective stat; never auto-recurse without explicit depth limit |

### Dependencies

- Depends on: Entitlements (all destructive operations — `rm`, `chmod`, `chown` — gated separately from reads)
- `watch` depends on: platform event APIs (inotify on Linux, kqueue on macOS, ReadDirectoryChangesW on Windows)
- Enables: **Service Management** "write config then restart" pattern
- Enables: **Security Scanning** real-time file scan on creation
- Enables: **Drift Detection** config file change detection

---

## Feature 8: Network Management (interfaces, connections, firewall, routing)

Not yet stubbed. New `sys.network` module.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| List network interfaces (name, IP, MAC, state up/down) | Any server management tool can show interface state | Low — gopsutil net.Interfaces() |
| List active connections (TCP/UDP, local/remote addr, PID, state) | Security baseline: "what is this host connected to right now?" | Low — gopsutil net.Connections() |
| List listening ports | Audit surface: "what ports are open on this host?" | Low — subset of connections |
| Firewall rule query (iptables/nftables on Linux, pf on macOS, Windows Firewall) | Security compliance requires knowing firewall state | High — three very different APIs |
| DNS lookup (forward and reverse) | Diagnostic tool: "can this host resolve this name from here?" | Low |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Fleet-wide "open ports" view | See across all hosts which ports are listening — one view. Nmap runs require network access; this runs inside each host. | Low — server aggregates |
| Connection to threat intel correlation | Active connections cross-referenced against threat intel (DarkAPI/OTX already in v1.0) | Medium — data join on server side |
| Firewall rule convergence via Sysscript | `network.firewall.ensure_rule("allow", "tcp", "80", "0.0.0.0/0")` — idempotent firewall management | High — platform-specific |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Implementing a software-defined networking layer | Enormous scope. SDN belongs in dedicated tools (Calico, Cilium). | Report on network state; don't manage it beyond simple firewall rules |
| Full iptables rule set management (add/delete arbitrary rules) | Incorrect rule ordering can lock the operator out of the host | Convergence-mode firewall only: "ensure this rule exists", never "replace all rules" |
| Routing table modification | Production network routing changes via a management agent are extremely high-risk | Read-only routing table query only; route modification is out of scope v2.0 |
| Per-packet capture / PCAP | Wireshark territory. Massive data volume. | Connection-level visibility is sufficient; refer to `tcpdump` via `sys.exec.run` |

### Dependencies

- Depends on: gopsutil (net package — already imported)
- Depends on: Platform detection for firewall rule management
- Depends on: Entitlements (new `allow_network_manage` for any mutating operations)
- Integrates with: **Threat Intel API** (v1.0 already built) for connection correlation

---

## Feature 9: Drift Detection (track applied state, detect divergence)

Not yet implemented. Foundational for the Ansible replacement claim.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| Record "desired state" when a Sysscript is applied to a host | Must know what was intended to detect drift from it | Medium — state store schema needed |
| Compare current state to last desired state on demand or on schedule | This is the drift check. Runs as a scheduled Sysscript or server-initiated poll | Medium |
| Report which items have drifted: packages (version changed), services (stopped), files (content changed) | A drift report without specifics is useless for remediation | Medium |
| Alert when drift detected (integrate with `sys.alerts`) | Passive detection that nobody sees is wasted effort | Low — once alerts are a real push |
| Convergence to fix drift: re-apply the last desired state | The operator should be able to click "converge" to fix the drift | Medium — depends on Feature 1 |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Automatic drift detection without a separate tool | Ansible requires Ansible Lint + Tower/AWX for drift; Puppet/Chef have separate compliance modules. SystemAPI does it natively. | Medium |
| Drift shown in fleet dashboard | Per-host drift status visible alongside CPU/memory. Ansible Tower shows this but costs $. | Low once drift data exists |
| Drift remediation one click | "This host has drifted. Converge now." — one button, no manual re-run of playbook. | Low once convergence exists |
| File content drift uses `sys.fs.diff` | Shows the actual diff of what changed, not just "file changed" | Low — integrates Feature 7 |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Storing full system state snapshots (all files, all processes) | Storage explosion. A full filesystem snapshot per host per check is infeasible. | Track only what was explicitly managed: packages installed, services enabled, files written |
| Continuous drift polling every few seconds | Adds significant overhead across a fleet; conflicts with telemetry bandwidth | Drift checks run on a configurable schedule (default: hourly); trigger on demand |
| Drift check that modifies state without operator confirmation | Silent auto-remediation breaks the trust model. | Detect and alert; converge only on explicit operator action (or an explicitly configured auto-converge policy) |
| Tracking drift for resources outside Sysscript scope | Can't detect drift in things the agent never managed | Scope drift detection to items explicitly managed by Sysscripts |

### Dependencies

- Depends on: **Declarative State Management** (Feature 1) to know the desired state
- Depends on: **Package Management** (Feature 3) for package version drift
- Depends on: **Service Management** (Feature 4) for service state drift
- Depends on: **Filesystem Extended** (Feature 7) for file content drift
- Depends on: **sys.alerts** push being real (currently a stub)
- Enables: Frontend "drift status" column in fleet dashboard

---

## Feature 10: Platform Support (RHEL/Rocky, Debian/Ubuntu, macOS, Windows Server)

This is a cross-cutting concern, not a separate module. Every feature above must work across all four platforms.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| Agent compiles and runs on linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 | PROJECT.md constraint. Operators managing mixed fleets cannot use a Linux-only tool. | Medium — build matrix + CI |
| Package manager auto-detection: dnf vs apt vs brew vs winget | Operator writes `sys.packages.install("nginx")` once; the agent picks the right tool | Medium — platform detect already in gopsutil |
| Service manager auto-detection: systemd vs launchd vs SCM | Same concern as package manager | Medium |
| SELinux context handling on RHEL/Rocky | Writing files to SELinux-managed paths without correct context labels causes permission failures | High — requires semanage/restorecon awareness |
| AppArmor awareness on Debian/Ubuntu | AppArmor profiles can block legitimate agent operations | Medium |
| Windows: PowerShell and WMI access for operations without native Go equivalent | Some Windows management tasks have no non-PowerShell path | Medium — `sys.exec.run("powershell.exe", "-Command", ...)` pattern |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| True single-binary cross-platform agent | No Python, no Ruby, no .NET runtime on managed host. CGO disabled where possible to keep binary static. | Medium — watch CGO dependencies |
| Unified Sysscript API across platforms | Operator writes one script; platform differences handled inside the agent, not in the script. Ansible requires separate roles per OS. | High — all module implementations must abstract platform differences |
| SELinux/AppArmor integration rather than fighting it | Most tools either disable SELinux or ignore it. Correct context labeling on file writes means managed hosts stay compliant. | High |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Platform-specific Starlark builtins (sys.linux.*, sys.windows.*) | Forces operators to write platform-conditional scripts everywhere | Platform differences go inside the Go builtin implementation; the Starlark API is unified |
| Disabling SELinux/AppArmor as part of setup | Security regressions. Any tool that requires disabling MAC frameworks is a security problem. | Handle MAC framework requirements correctly within each operation |
| Windows support as a second-class afterthought | If Windows is listed as supported, it must pass the same test matrix | Build and test Windows binaries in CI from day one of v2.0 |
| Homebrew as the macOS package manager for servers | Homebrew is a developer tool, not a server package manager. macOS Server workloads often use MacPorts or direct installs. | For macOS: brew for developer tools, direct installer scripts for server workloads |

### Dependencies

- This feature depends on: Every other feature having correct platform branching
- Enables: Mixed-OS fleet management from a single dashboard

---

## Feature 11: Real-Time System Event Streaming (inotify, kqueue, ETW)

Stub exists: `sys.events.listen` in `sys_advanced.go` logs and returns true.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| Subscribe to file system change events | Foundation for reactive automation: file written → restart service | High — platform kernel APIs |
| Subscribe to process creation/exit events | Security: detect when an unexpected binary executes | High — auditd/BSM/ETW |
| Callback invoked in Starlark with event data | The stub takes a callback. It must actually call it with event details (path, event type, PID) | High — requires running Starlark callbacks from a Go goroutine safely |
| Event delivery to agent's WebSocket if no callback | Events can also be pushed back to the dashboard without a local handler | Medium |

### Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Event-driven Sysscripts | "When any .conf file in /etc/nginx changes, run the nginx config test and reload if valid" — no polling, no cron. Ansible has no equivalent. | High |
| Cross-platform event normalization | Linux inotify events, macOS kqueue/FSEvents, Windows ETW all surface through the same `sys.events.listen` API | Very High |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Event-driven execution without rate limiting | A file that changes 1000 times/second (log file) would execute the Starlark callback 1000 times/second | Debounce: collapse events within a configurable window (default 500ms) before invoking callback |
| Subscribing to all events system-wide | inotify watches have kernel limits; ETW high-volume tracing can saturate I/O | Require explicit path/process scope in `events.listen` call |
| Long-running blocking operations in event callbacks | Starlark callbacks must complete quickly; blocking the event goroutine delays all subsequent events | Callbacks run in a separate goroutine per event; timeout enforced |

### Dependencies

- Depends on: Platform APIs (inotify on Linux, kqueue/FSEvents on macOS, ETW on Windows)
- Depends on: Thread-safe Starlark execution (calling `starlark.Call` from multiple goroutines requires separate Thread objects)
- Enables: **Security Scanning** file-creation triggers
- Enables: **Service Management** config-change-then-restart patterns
- Enables: **Drift Detection** real-time change notification

---

## Feature 12: sys.alerts Real Push (complete the stub)

Currently `sys.alerts.push` logs to the agent's stdout. It must actually push back through the WebSocket to the FleetManager.

### Table Stakes

| Behavior | Why Expected | Complexity |
|----------|--------------|------------|
| `sys.alerts.push(severity, message, metadata)` sends a WebSocket message to FleetManager | Every other feature in v2.0 produces events that need alerting. The alert pipe must work. | Low — agent has the WebSocket connection; add a channel to send alert messages |
| Alert stored in database and visible in alerts view | The alerts view already exists in the frontend. Alert records must be persisted. | Low — `playground_alerts` schema exists |
| Alert includes host_id, script_id, and custom payload | Operators need to know which host and which script triggered the alert | Low |
| Deduplication / rate limiting on alert push | A runaway script could call `sys.alerts.push` in a tight loop | Medium — deduplicate on (host_id, message_hash) within a time window |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Alert push bypassing the entitlement system | Alerts could become a data exfiltration channel if unrestricted | Gate `sys.alerts.push` behind an `allow_alerts` entitlement |
| Synchronous alert delivery (blocking the script) | If the WebSocket is slow or backpressured, the script hangs | Fire-and-forget: push to a buffered channel; the main goroutine drains it |

### Dependencies

- This is foundational: **every other feature** that produces alerts (security scan findings, drift detection, service failures, CVE discoveries) depends on this working
- Depends on: The existing WebSocket write path in `main.go`

---

## Cross-Feature Dependencies Map

```
sys.alerts.push (real)  <── every feature that emits an alert
       ↑
Drift Detection  ────────── Declarative State Mgmt
       ↑                           ↑
Package Mgmt  ──────────────── Service Mgmt
       ↑                           ↑
Platform Support (cross-cutting) ──┘
       ↑
Security Scanning  ──── sys.fs.watch (Events)
       ↑                      ↑
Process Mgmt            FS Extended
       ↑
Container Mgmt
       ↑
Network Mgmt
```

**Build order implied by dependencies:**

1. sys.alerts.push (real) — everything else alerts through this
2. sys.fs extended + sys.events.listen — used by multiple features
3. Package Management + Service Management — frequently paired
4. Process Management — relatively independent
5. Container Management — independent, uses Docker API
6. Network Management — independent
7. Security Scanning — depends on fs.watch, can alert
8. Declarative State Management — depends on all primitives existing
9. Drift Detection — depends on declarative state + all primitives
10. Platform support validation — runs through the whole matrix

---

## MVP Recommendation

For a shippable v2.0 milestone that delivers the Ansible replacement promise:

**Must ship (required for the core value proposition):**
1. sys.alerts.push — real WebSocket push (unblocks all other alerting)
2. Package management — install/remove/check/list (cross-platform)
3. Service management — start/stop/enable/disable/status (cross-platform)
4. Filesystem extended — stat, glob, mkdir, rm, chmod, chown, diff
5. Declarative convergence mode — idempotent, dry-run, execution report
6. Drift detection — at least package and service state

**Should ship (high value, reasonable complexity):**
7. Process management — list, kill, signal
8. Container management — run, stop, list, logs, pull, images
9. Security scanning — YARA file scan, CVE matching (memory scan deferred)

**Can defer (high complexity, lower urgency):**
10. sys.events.listen — real file watch (very high complexity; use polling for v2.0 drift detection instead)
11. Firewall rule management — read-only for v2.0; mutations in v2.1
12. Memory scanning — Very High complexity; defer to v2.1

## Sources

- Direct codebase inspection: `systemapi-agent/sysscript.go`, `systemapi-agent/sys_advanced.go`, `systemapi-agent/telemetry.go`, `playground/fleet.js`, `playground/playground_fleet_schema.sql`
- PROJECT.md milestone requirements and technical constraints
- FEATURE_ROADMAP.md existing planning
- Domain knowledge: Ansible/Chef/Puppet/Terraform ecosystem (HIGH confidence — well-documented design patterns from these tools' own documentation and community discourse)
- gopsutil library capabilities (HIGH confidence — directly imported in telemetry.go)
- Docker Engine API patterns (HIGH confidence — well-documented REST/unix-socket API)
- YARA rule engine capabilities (HIGH confidence — established open-source tool with documented Go bindings)
