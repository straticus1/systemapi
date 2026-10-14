# Agent, CLI and Sysscript reference

## Agent (`systemapi-agent/`)

The agent dials the control plane over a WebSocket and never listens on a port.

```bash
cd systemapi-agent
go build -o systemapi-agent .
SYSTEMAPI_API_KEY=<key> ./systemapi-agent \
  --tenant acme \
  --server wss://api.systemapi.io/api/v1/systems/stream
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--server` | `ws://localhost:3003/api/v1/systems/stream` | Control-plane stream URL. A URL containing `api_key` is refused. |
| `--api-key` | `$SYSTEMAPI_API_KEY` | Prefer the environment variable. |
| `--tenant` | (required) | Tenant the host enrolls into. |
| `--hostname` | this machine | Reported hostname. |
| `--state` | `~/.systemapi/agent.json` | Host id, SSH key and pinned control key. |
| `--pty-user` | (none) | Account that `terminal:open` shells run as. Required when the agent runs as root; without it those sessions are refused with `pty_user_unset`. Must not be root. |
| `--pty-record` | `true` | Run terminal sessions under `adssh` so its audit chain records them. A missing `adssh` refuses the session with `recording_unavailable`. `false` runs the user's shell unrecorded. |
| `--pty-record-dir` | `/var/lib/systemapi-agent/pty` as root, else `<state dir>/pty` | Holds `terminal.rego` and one `adssh` audit log directory per shell user. |

`terminal:root` sessions use their own lease action (`pty_root`), run as root,
and need an agent running as root.

On dial it sends `Authorization: Bearer <key>`, `X-SystemAPI-Tenant`,
`X-SystemAPI-Host-ID`, `X-SystemAPI-Hostname` and `X-SystemAPI-SSH-PubKey`
(OpenSSH `ssh-ed25519`). It refuses commands as `not_enrolled` until it has
pinned the control public key, and refuses a changed key. TLS is 1.3 only.

Telemetry (every 5 seconds): host info, CPU, memory, disks, cumulative network
byte counters, installed software, and Docker or k3s summaries when present.

There is no install script; run the binary under your own service manager.

## CLI (`cli/systemapi.js`)

```
SYSTEMAPI_URL=https://api.systemapi.io SYSTEMAPI_API_KEY=<key> node cli/systemapi.js <command>

  hosts
  exec --host <id> --script-file <path>
  metrics --host <id>
  audit
  breakglass-ticket --host <id>
  host-json --host <id>
  login <username>
```

The key is sent only as `X-API-Key`. A key in `SYSTEMAPI_URL` is refused.

## Sysscript

Sysscripts are Starlark. `print()` output is returned as `result.output`; a
runtime error is returned as `result.error`. Each run carries entitlements;
anything not granted is refused. The control plane clamps them first:
`allow_exec` needs the `exec:run` scope, everything else needs `admin`.

### Entitlements

| Name | Type | Grants |
| --- | --- | --- |
| `allow_exec` | bool | `sys.exec.run`, `sys.proc.kill` |
| `allow_fs_read` | path list | `sys.fs.read`, `stat`, `glob`; `sys.config.backup` |
| `allow_fs_write` | path list | `sys.fs.write`, `mkdir`, `rm`, `chmod`; `sys.config.restore` |
| `allow_net_outbound` | host list | `sys.net.http_get` |
| `allow_config_write` | path list | `sys.config.write`, `restore` |
| `allow_service_reload` | name list | `sys.config.reload`, `sys.services.*` actions |
| `allow_packages` | exact list | `sys.packages.install` |
| `allow_containers` | bool | the `sys.containers` module |
| `allow_images` | exact list | `sys.containers.run` |
| `allow_k3s`, `allow_k8s` | bool | the `sys.k3s` / `sys.k8s` modules |
| `allow_k3s_namespaces`, `allow_k8s_namespaces` | exact list | namespaces those modules may touch |
| `allow_linux` | bool | `sys.linux`, `sys.disk`, `sys.procfs` (Linux hosts only) |
| `allow_mount_targets` | exact list | `sys.disk.mount`, `umount` |
| `allow_sysctl` | exact list | `sys.procfs.sysctl_get`, `sysctl_set` (some keys are always denied) |
| `allow_net_manage` | exact list | `sys.net.set_address`, `set_route`, `link_up`, `link_down`, `set_dns` |

A JSON boolean in a list field grants nothing, and `"*"` is dropped.

The control plane currently forwards `allow_fs_read`, `allow_fs_write`,
`allow_net_outbound`, `allow_config_write` and `allow_service_reload` as
booleans (see `clampEntitlements` in `controlplane/router.js`), so a run
started through the API or dashboard never receives those path or name lists.
The other list fields are passed through for admins.

### Modules

| Module | Functions |
| --- | --- |
| `sys.exec` | `run(cmd, *args)` returns `{"output": ...}` |
| `sys.fs` | `read`, `write`, `stat`, `glob`, `mkdir`, `rm`, `chmod` |
| `sys.net` | `http_get`, `dns_lookup`, `reverse_dns`, `port_check`, `links`, `addresses`, `routes`, `set_address`, `set_route`, `link_up`, `link_down`, `set_dns` |
| `sys.proc` | `list`, `get`, `find`, `kill` |
| `sys.services` | `start`, `stop`, `restart`, `enable`, `disable`, `status` |
| `sys.config` | `write`, `template`, `validate`, `reload`, `backup`, `restore` |
| `sys.packages` | `install` |
| `sys.json`, `sys.yaml`, `sys.ini` | `parse`, `encode` (and `encode_pretty`, `get`) |
| `sys.containers` | `list`, `stats`, `start`, `stop`, `restart`, `inspect`, `logs`, `run`, `exec` |
| `sys.k3s`, `sys.k8s` | `nodes`, `pods`, `apply`, `get`, `list`, `logs`, `exec`, `delete` |
| `sys.linux` | `os_release`, `uname`, `hostname`, `uptime`, `users`, `groups` |
| `sys.disk` | `mounts`, `usage`, `block_devices`, `mount`, `umount` |
| `sys.procfs` | `read`, `sysctl_get`, `sysctl_set` |

Not implemented:

- `sys.alerts.push(severity, message)` logs on the agent and returns `False`.
  Nothing forwards it to the control plane yet.
- `sys.security.yara_scan`, `sys.security.scan_memory` and `sys.events.listen`
  raise a "not implemented" error.

Example:

```python
r = sys.exec.run("df", "-h")
print(r["output"])
```
