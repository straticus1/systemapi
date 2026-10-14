# Milestones

## v1.0 - Foundation (Shipped)

**Shipped:** 2026-04-28 (baseline - existing codebase)

**What shipped:**
- Go WebSocket agent with Starlark execution engine
- sys.exec, sys.fs, sys.net builtins with entitlement enforcement
- PTY terminal sessions (pty_start/input/resize/stop)
- Telemetry push: CPU, memory, disk, network (5s interval)
- FleetManager WebSocket multiplexer on Express server
- API key + OIDC/JWT authentication
- Redis + PostgreSQL rate limiting
- React fleet dashboard (PTY, containers, sysscripts, alerts, access views)
- Prometheus metrics endpoint
- Threat intel API (DarkAPI, DNSScience, OTX, CrowdSec, SafeBrowsing)
- Code snippet generator (Python, Go, Node, PHP, curl)
- Playground: auth, rate limiting, fleet management, PostgreSQL schema

**Stubs left for v2.0:**
- sys.security (alertsPush, securityYaraScan, securityScanMemory)
- sys.packages (packagesInstall)
- sys.containers (containersRun)
- sys.events (eventsListen)

---
*Last updated: 2026-04-28*
