# SystemAPI.io API Reference

SystemAPI.io provides a robust REST API for Fleet Management and a bi-directional WebSocket API for Real-time Telemetry, Alerting, and Zero-Trust Terminal access.

## Authentication

All endpoints require a Master API Key passed either in the header or as a query parameter.

**Header:**
```http
X-API-Key: ak_live_yourkey
```

**Query Parameter (WebSockets):**
```
ws://api.systemapi.io/api/v1/systems/stream?api_key=ak_live_yourkey
```

---

## REST Endpoints

### 1. Retrieve Fleet Overview

Fetches a list of all hosts registered to the authenticated API Key, enriched with real-time connection status.

**Endpoint:** `GET /api/v1/fleet`

**Response:**
```json
{
  "hosts": [
    {
      "host_id": "c5bf94a5-1a0f-4165-b1ae-e47bcbe239c6",
      "hostname": "ubuntu-db-01",
      "os": "linux",
      "platform": "ubuntu",
      "status": "online",
      "last_seen_at": "2026-03-13T11:25:16Z",
      "live_stats": {
        "cpu": { "usage_percent": 14.5 },
        "memory": { "used_percent": 62.1 }
      }
    }
  ]
}
```

### 2. Execute Sysscript Playbook

Pushes a Starlark-based Sysscript payload out to a specific agent for immediate execution.

**Endpoint:** `POST /api/v1/fleet/:hostId/execute`

**Request Body:**
```json
{
  "script": "sys.exec.run('rm -rf /tmp/cache')",
  "entitlements": {
    "allow_exec": true,
    "allow_network": false,
    "allow_fs": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Script dispatched to node",
  "request_id": "1647891234567"
}
```

---

## WebSocket API (Agent Stream)

The Go Agent maintains a persistent WebSocket connection to stream telemetry and receive commands.

**Endpoint:** `ws://api.systemapi.io/api/v1/systems/stream`

### Agent -> Server Messages

#### 1. Telemetry Payload
Fired every 5-10 seconds by the agent.

```json
{
  "type": "telemetry",
  "payload": {
    "host": { "hostname": "mac-pro-01", "os": "darwin" },
    "cpu": { "usage_percent": 4.2 },
    "memory": { "used_percent": 45.1 },
    "network": { "rx_bytes": 1048576, "tx_bytes": 2048 },
    "disk": { "free_space": 45000000000 }
  }
}
```

#### 2. Command Result
Fired when a Sysscript finishes execution.

```json
{
  "type": "command_result",
  "payload": {
    "stdout": "total 0\n",
    "stderr": "",
    "error": null
  }
}
```

### Server -> Agent Messages

#### 1. Execute Sysscript
Requests the agent to evaluate the Starlark script inside the sandbox.

```json
{
  "type": "sysscript",
  "script": "sys.containers.restart('nginx')",
  "entitlements": { "allow_exec": true },
  "request_id": "1647891234567"
}
```

#### 2. Terminate Process
Specific action from the Dashboard quick-actions.

```json
{
  "type": "kill",
  "pid": 1048
}
```

---

## WebSocket API (Zero-Trust Terminal)

SystemAPI.io allows Dashboard users to pop a reverse-TTY shell into any active host using a secondary WebSocket tunnel that routes through the master API.

**Dashboard Endpoint:** `ws://api.systemapi.io/api/v1/systems/terminal/:hostId?api_key=ak_live...`

Once connected, binary payloads and JSON sizing commands are passed transparently into the Go Agent's `creack/pty` multiplexer.

### Dashboard -> Server -> Agent
```json
{
  "type": "pty_input",
  "data": "ls -la\n"
}
```
Or for resizing the virtual terminal:
```json
{
  "type": "pty_resize",
  "data": { "cols": 120, "rows": 40 }
}
```

### Agent -> Server -> Dashboard
The agent streams the raw `stdout/stderr` binary buffer back through the WebSocket, which is fed directly into `xterm.js`.
