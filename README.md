# SystemAPI.io - The Execution Control Plane

SystemAPI.io is a globally distributed, Zero-Trust Execution Control Plane. It consists of a centrally managed Node.js backend (`fleet.js`) mapping to a React frontend (`FleetDashboard`), and thousands of lightweight Go Agents (`systemapi-agent`) deployed across the fleet.

Instead of writing custom bash scripts for every server, SystemAPI utilizes **Sysscripts** (a restricted, Turing-complete subset of Python called Starlark). You push a Sysscript from the Dashboard, and the Go Agent executes it securely on the edge.

## Architecture Highlights

- **Starlark Playbook Engine**: Agents execute Sysscripts in memory. Standard library capabilities like `sys.exec.run` or `sys.os.list_dir` are strictly governed by granular Entitlement JSON scopes.
- **Zero-Trust WebPTY**: The Dashboard provides a pure xterm.js reverse-shell to any node. Traffic flows via secure WebSockets through the `fleet.js` proxy—the agent never opens a listening port.
- **WORM Audit Logging**: Every executed playbook, keystroke, and telemetry result is cryptographically hashed and streamed directly to an S3-compatible **DarkStorage.io** backend.
- **Incident Response Hooks**: Real-time server telemetry anomalies natively trigger SMS and Voice alarms through internal **Adstelco.io** REST hooks.

---

## 🚀 Quick Start

### 1. Start the Fleet Manager (Node.js)

The Fleet Manager routes PTY streams, validates API keys, and evaluates real-time telemetry from connected agents.

```bash
npm install
npm run start
```

### 2. Start the Fleet Dashboard (React)

The single-pane-of-glass UI for managing host telemetry, executing Sysscripts, and zero-trust terminal access.

```bash
cd frontend
npm install
npm run dev
```

### 3. Deploy the Go Agent

The Go Agent connects outbound to the Fleet Manager WebSocket. It features a completely headless mode for background execution using `systemd`.

```bash
cd systemapi-agent
go build -o agent .
./agent --api-key ak_live_1234.demo --server ws://localhost:3003/api/v1/systems/stream
```

---

## Expanding the Agent (`systemd`)

For production fleet expansion, use the standard `systemd` setup script to install the background worker on any Linux target.

```bash
sudo ./deploy_agent.sh --api-key ak_live_1234.demo
```

## Documentation

- **REST Endpoints & WebSockets**: Read `api_docs.md`
- **Sysscript Go API Reference**: Read `cli_docs.md`
