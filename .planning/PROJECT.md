# SystemAPI.io

## What This Is

SystemAPI.io is a fleet systems management platform that replaces Ansible/Terraform with a
WebSocket-connected Go agent running sandboxed Starlark scripts (Sysscripts) on managed hosts.
It provides real-time telemetry, security scanning, container management, and interactive PTY
terminals across Linux (RHEL/Rocky, Debian, Ubuntu), macOS, and Windows Server fleets from a
single React dashboard.

## Core Value

An operator can write a Sysscript and watch it converge any host in their fleet - declaratively
or imperatively - without SSH keys, VPNs, or Ansible control nodes.

## Requirements

### Validated

<!-- Shipped in v1.0 - current codebase baseline -->

- [x] Go WebSocket agent with Starlark execution engine - v1.0
- [x] sys.exec.run (command execution with entitlements) - v1.0
- [x] sys.fs.read / sys.fs.write (path-prefix entitlement enforcement) - v1.0
- [x] sys.net.http_get (outbound allowlist enforcement) - v1.0
- [x] PTY terminal sessions (pty_start / pty_input / pty_resize / pty_stop) - v1.0
- [x] Telemetry push every 5s (CPU, memory, disk, network) - v1.0
- [x] FleetManager WebSocket mux on Node.js/Express server - v1.0
- [x] API key + OIDC/JWT auth (AuthManager) - v1.0
- [x] Rate limiting (Redis + PostgreSQL) - v1.0
- [x] React fleet dashboard with PTY, containers, sysscripts, alerts views - v1.0
- [x] Prometheus metrics endpoint - v1.0
- [x] Threat intel API (DarkAPI, DNSScience, OTX, CrowdSec) - v1.0
- [x] Code snippet generator (Python, Go, Node, PHP, curl) - v1.0

### Active

<!-- Milestone v2.0: Next-Gen Systems Management -->

- [ ] Declarative state management (Ansible replacement - convergence mode) - not started
- [ ] Imperative execution mode (push-and-verify, both modes supported) - imperative mode
      shipped (sysscripts run ad-hoc, async jobs ack results); declarative mode still missing
      so "both modes" isn't true yet
- [ ] sys.security: YARA scanning, memory scanning, real-time CVE alerting - stubbed
      (yara_scan/scan_memory return not-implemented; agent/sys_advanced.go)
- [x] sys.packages: cross-platform package management (dnf/yum, apt-get/dpkg, zypper, brew) -
      shipped; pacman (Arch) is parsed but not wired as an install target; winget/Windows deferred
- [x] sys.containers: Docker/OCI full lifecycle (run, stop, list, exec, logs, pull) - shipped,
      plus images/volumes/networks/compose with an allowlist preflight
- [ ] sys.events: real-time system event streaming (inotify, kqueue, ETW) - stubbed
      (eventsListen returns not-implemented; agent/sys_advanced.go)
- [x] sys.alerts: push alerts back to FleetManager (implemented, not stubbed) - shipped
- [x] sys.fs extended: stat, glob, mkdir, rm, chmod, chown, diff - shipped, with a hardened
      grant-path policy
- [x] sys.process: list, kill (with signal), resource usage per process - shipped
- [x] sys.services: systemd / launchd / openrc service management - shipped; Windows SCM
      deferred with the rest of Windows support
- [~] sys.network: interface info, connections, DNS reads/writes (set_address/set_route/set_dns)
      - shipped; firewall rules are explicitly out of scope per Decision 2, not pending work
- [x] Docker/OCI interface: images, volumes, networks, compose - shipped; registries beyond
      pull-by-ref not built out further
- [~] Platform support: RHEL/Rocky (dnf, SELinux), Debian/Ubuntu (apt, AppArmor), SUSE (zypper),
      Arch (detection only), macOS (launchd, Homebrew) all shipped; Windows Server deferred
- [x] Async sysscript jobs: /jobs API, CLI wait/kill, agent --sysscript-jobs flag (Linux/macOS),
      Studio job flow in the frontend - shipped (plan: .omc/plans/async-sysscript-jobs.md,
      docs/sah-sysscript-jobs.md); Windows job kill and a browser check of the Studio flow
      are still open
- [ ] Sysscript state store: track last-applied state per host, detect drift - not started
      (depends on declarative convergence)
- [ ] Frontend: state convergence UI, security scan results, package inventory views - not
      started

### Out of Scope

- Native mobile app - web dashboard is sufficient for v2.0
- Kubernetes operator - container management targets Docker/OCI, not k8s orchestration
- Built-in secrets vault - use env vars / external vault integration
- Custom DSL - Starlark is the scripting layer; no new language

## Context

**Current architecture:**
- `systemapi-agent/` - Go binary: WebSocket client, Starlark engine (go.starlark.net),
  PTY via creack/pty, telemetry (gopsutil). Stubs: alertsPush, securityYaraScan,
  securityScanMemory, eventsListen, packagesInstall, containersRun.
- `server.js` - Node.js/Express: REST API, WebSocket mux (FleetManager), Prometheus,
  OIDC auth, playground routes. Connects to PostgreSQL + Redis.
- `frontend/` - React + Vite: fleet dashboard, PTY terminal, containers view,
  sysscripts view, alerts view, access/API key management.
- `playground/` - AuthManager, FleetManager, PlaygroundRateLimiter, CodeSnippetGenerator,
  playground router. PostgreSQL schema: playground_hosts, playground_host_software,
  playground_host_cves.

**Key technical constraints:**
- Agent communicates only via WebSocket (outbound from host) - no inbound ports
- Starlark engine enforces entitlements per-script - security model is mandatory
- Cross-platform: agent must compile for linux/amd64, linux/arm64, darwin/amd64,
  darwin/arm64, windows/amd64
- Server is multi-tenant capable (api_site field in FleetManager)

## Constraints

- **Tech stack**: Go agent, Node.js server, React frontend - no stack changes
- **Security**: All Starlark builtins must enforce entitlements - no bypass paths
- **Compatibility**: Agent binary must be single static executable, no runtime deps
- **Protocol**: WebSocket JSON protocol (CommandMessage / ResponseMessage) is the wire format

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Starlark as scripting layer | Deterministic, sandboxable, Python-like syntax, Google-backed | Good |
| WebSocket outbound only | Agents behind NAT/firewall can connect without port forwarding | Good |
| Entitlements per-script | Fine-grained security - each execution declares its capabilities | Good |
| Both declarative + imperative modes | Covers Ansible replacement AND ad-hoc ops | - Pending |
| Single Go binary agent | Easy deployment - curl + chmod + run | Good |

## Current Milestone: v2.0 Next-Gen Systems Management

**Goal:** Transform SystemAPI.io into a production-grade Ansible/Terraform alternative with
full security scanning, real container management, and complete system primitives for Linux,
macOS, and Windows Server fleets.

**Target features:**
- Ansible/Terraform replacement (declarative + imperative Sysscripts)
- Security monitoring: YARA, CVE matching, memory scanning
- Full sys.* module suite: packages, services, processes, network, fs extended
- Docker/OCI container lifecycle management
- Platform support: RHEL/Rocky, Debian/Ubuntu, macOS, Windows Server

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? -> Move to Out of Scope with reason
2. Requirements validated? -> Move to Validated with phase reference
3. New requirements emerged? -> Add to Active
4. Decisions to log? -> Add to Key Decisions
5. "What This Is" still accurate? -> Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check - still the right priority?
3. Audit Out of Scope - reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-10-29 - v2.0 Active checklist reconciled against code/git history*
