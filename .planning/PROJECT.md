# SystemAPI.io

## What This Is

SystemAPI.io is a fleet systems management platform that replaces Ansible/Terraform with a
WebSocket-connected Go agent running sandboxed Starlark scripts (Sysscripts) on managed hosts.
It provides real-time telemetry, security scanning, container management, and interactive PTY
terminals across Linux (RHEL/Rocky, Debian, Ubuntu), macOS, and Windows Server fleets from a
single React dashboard.

## Core Value

An operator can write a Sysscript and watch it converge any host in their fleet — declaratively
or imperatively — without SSH keys, VPNs, or Ansible control nodes.

## Requirements

### Validated

<!-- Shipped in v1.0 — current codebase baseline -->

- ✓ Go WebSocket agent with Starlark execution engine — v1.0
- ✓ sys.exec.run (command execution with entitlements) — v1.0
- ✓ sys.fs.read / sys.fs.write (path-prefix entitlement enforcement) — v1.0
- ✓ sys.net.http_get (outbound allowlist enforcement) — v1.0
- ✓ PTY terminal sessions (pty_start / pty_input / pty_resize / pty_stop) — v1.0
- ✓ Telemetry push every 5s (CPU, memory, disk, network) — v1.0
- ✓ FleetManager WebSocket mux on Node.js/Express server — v1.0
- ✓ API key + OIDC/JWT auth (AuthManager) — v1.0
- ✓ Rate limiting (Redis + PostgreSQL) — v1.0
- ✓ React fleet dashboard with PTY, containers, sysscripts, alerts views — v1.0
- ✓ Prometheus metrics endpoint — v1.0
- ✓ Threat intel API (DarkAPI, DNSScience, OTX, CrowdSec) — v1.0
- ✓ Code snippet generator (Python, Go, Node, PHP, curl) — v1.0

### Active

<!-- Milestone v2.0: Next-Gen Systems Management -->

- [ ] Declarative state management (Ansible replacement — convergence mode)
- [ ] Imperative execution mode (push-and-verify, both modes supported)
- [ ] sys.security: YARA scanning, memory scanning, real-time CVE alerting
- [ ] sys.packages: cross-platform package management (dnf, apt, brew, winget)
- [ ] sys.containers: Docker/OCI full lifecycle (run, stop, list, exec, logs, pull)
- [ ] sys.events: real-time system event streaming (inotify, kqueue, ETW)
- [ ] sys.alerts: push alerts back to FleetManager (implemented, not stubbed)
- [ ] sys.fs extended: stat, glob, mkdir, rm, chmod, chown, diff
- [ ] sys.process: list, kill, signal, resource usage per process
- [ ] sys.services: systemd / launchd / SCM service management
- [ ] sys.network: interface info, connections, firewall rules, DNS
- [ ] Docker/OCI interface: images, volumes, networks, registries, compose
- [ ] Platform support: RHEL/Rocky (dnf, SELinux), Debian/Ubuntu (apt, AppArmor),
      macOS (launchd, Homebrew), Windows Server (PowerShell, WMI, winget)
- [ ] Sysscript state store: track last-applied state per host, detect drift
- [ ] Frontend: state convergence UI, security scan results, package inventory

### Out of Scope

- Native mobile app — web dashboard is sufficient for v2.0
- Kubernetes operator — container management targets Docker/OCI, not k8s orchestration
- Built-in secrets vault — use env vars / external vault integration
- Custom DSL — Starlark is the scripting layer; no new language

## Context

**Current architecture:**
- `systemapi-agent/` — Go binary: WebSocket client, Starlark engine (go.starlark.net),
  PTY via creack/pty, telemetry (gopsutil). Stubs: alertsPush, securityYaraScan,
  securityScanMemory, eventsListen, packagesInstall, containersRun.
- `server.js` — Node.js/Express: REST API, WebSocket mux (FleetManager), Prometheus,
  OIDC auth, playground routes. Connects to PostgreSQL + Redis.
- `frontend/` — React + Vite: fleet dashboard, PTY terminal, containers view,
  sysscripts view, alerts view, access/API key management.
- `playground/` — AuthManager, FleetManager, PlaygroundRateLimiter, CodeSnippetGenerator,
  playground router. PostgreSQL schema: playground_hosts, playground_host_software,
  playground_host_cves.

**Key technical constraints:**
- Agent communicates only via WebSocket (outbound from host) — no inbound ports
- Starlark engine enforces entitlements per-script — security model is mandatory
- Cross-platform: agent must compile for linux/amd64, linux/arm64, darwin/amd64,
  darwin/arm64, windows/amd64
- Server is multi-tenant capable (api_site field in FleetManager)

## Constraints

- **Tech stack**: Go agent, Node.js server, React frontend — no stack changes
- **Security**: All Starlark builtins must enforce entitlements — no bypass paths
- **Compatibility**: Agent binary must be single static executable, no runtime deps
- **Protocol**: WebSocket JSON protocol (CommandMessage / ResponseMessage) is the wire format

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Starlark as scripting layer | Deterministic, sandboxable, Python-like syntax, Google-backed | ✓ Good |
| WebSocket outbound only | Agents behind NAT/firewall can connect without port forwarding | ✓ Good |
| Entitlements per-script | Fine-grained security — each execution declares its capabilities | ✓ Good |
| Both declarative + imperative modes | Covers Ansible replacement AND ad-hoc ops | — Pending |
| Single Go binary agent | Easy deployment — curl + chmod + run | ✓ Good |

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
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-28 — Milestone v2.0 started*
