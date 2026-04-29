# SystemAPI.io Agent Configuration & Sysscript Documentation

The `systemapi-agent` is a natively compiled, zero-dependency Go binary built to run across Linux, macOS, and Windows. It provides Deep System Telemetry, Cloud-Agnostic Container Orchestration, real-time Alert Engine bindings, and a Zero-Trust remote Web PTY.

---

## Agent Installation & CLI Usage

### Basic Execution
The agent requires only your Master API Key to authenticate with the dashboard.

```bash
./systemapi-agent --api-key ak_live_1234.demo
```

### Advanced Flags
You can customize the endpoint URL and logging verbosity.

```bash
./systemapi-agent \
  --api-key ak_live_1234.demo \
  --server wss://api.systemapi.io/api/v1/systems/stream \
  --verbose true \
  --tags "production,db-cluster,us-east"
```

### Background Service Deployment (Systemd)

We provide a universal install script to immediately daemonize the agent on Linux:

```bash
curl -sSL https://install.systemapi.io | sudo bash -s -- --api-key ak_live_1234.demo --tags "web-worker"
```

---

## The Sysscript Engine

SystemAPI.io utilizes **Sysscript**, a dialect of Starlark (Python-lite) explicitly hardened for systems administration. 

When a Sysscript is dispatched from the Dashboard, it is evaluated by the local Go Agent within a heavily restricted, non-Turing-complete sandbox. **All capabilities are default-deny.** The sender must explicitly pass authorization Entitlements (e.g., `allow_exec: true`).

### Global Modules

#### 1. `sys.os` (Entitlement: `allow_fs`)
Cross-platform OS utilities and File System interactions.

```python
# Read a file
content = sys.os.read_file("/etc/passwd")

# Check if a mount exists
is_mounted = sys.os.path_exists("/mnt/data")

# Get environment variables
db_pass = sys.os.getenv("PGPASSWORD")
```

#### 2. `sys.exec` (Entitlement: `allow_exec`)
Executing arbitrary shell commands on the host.

```python
# Execute and return stdout
result = sys.exec.run("systemctl restart nginx")
print(result.stdout)

# Run a background task
sys.exec.spawn("./long_running_job.sh")
```

#### 3. `sys.net` (Entitlement: `allow_network`)
Perform local network diagnostics.

```python
# Check if a port is physically listening
is_up = sys.net.check_port(5432)

# Ping an internal dependency
latency = sys.net.ping("10.0.0.5")
```

#### 4. `sys.containers` (Entitlement: `allow_exec`)
**Cloud-Agnostic Orchestration.** Automatically detects the local runtime (Docker socket, Podman, Containerd) and executes Lifecycle commands without requiring OS-specific tooling.

```python
# Restart a container dynamically
sys.containers.restart("redis-cache")

# Spin up a new workload
sys.containers.run(
    image="nginx:latest", 
    name="web-01", 
    ports=["80:80"]
)

# Pull down everything
sys.containers.stop_all()
```

#### 5. `sys.alerts` (Two-Way Automations)
Push telemetry anomalies or incident markers *back* to the Dashboard's alerting engine to trigger generic Remediations.

```python
# Analyze local logs for a match...
if "OOMKiller" in sys.os.read_file("/var/log/syslog"):
    # Send a high-severity alert to SystemAPI.io, which can trigger an SMS
    # or instantly execute a "Memory Dump" Playbook!
    sys.alerts.push(
        severity="critical",
        alert_name="OOMKiller_Triggered",
        message="Host RAM exhausted. Initiating auto-remediation."
    )
```

#### 6. `sys.ssh` (Access Management)
Abstract out IAM permissions by universally injecting public keys into the agent's authorized lists.

```python
# Add an engineer's public key for 1 hour (Requires allow_fs)
sys.ssh.add_key(
    user="root",
    key="ssh-ed25519 AAAAC3NzaC1... deploy@hq"
)
```

#### 7. `sys.security` & `sys.events` (State of the Art Hooking)
Advanced eBPF/ETW modules.

```python
# Scan a suspicious file against local YARA rules before letting it execute
matches = sys.security.yara_scan("/tmp/uploaded_binary", rules_dir="/opt/yara")

if len(matches) > 0:
    sys.alerts.push(severity="high", alert_name="YARA_Detect", message=matches[0])
    sys.exec.run("rm -f /tmp/uploaded_binary")
```

---

## Security Entitlements Matrix

To execute *any* of the above scripts successfully, the `POST /execute` payload must explicitly contain the required Entitlement flags:

| Starlark Module | Required Entitlement | Description |
| :--- | :--- | :--- |
| `sys.os` | `allow_fs: true` | Grants read/write access to the host's physical disk |
| `sys.exec` | `allow_exec: true` | Grants access to spawn generic shell processes |
| `sys.net` | `allow_network: true` | Grants ability to open outbound TCP/UDP sockets |
| `sys.containers` | `allow_exec: true` | Requires shell access to wrap Docker/Podman APIs |
| `sys.ssh` | `allow_fs: true` | Requires disk access to mutate `~/.ssh/authorized_keys` |
| `sys.security` | *built-in* | YARA scanning engine requires no specific entitlements |
