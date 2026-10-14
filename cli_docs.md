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
| `--api-key-file` | (none) | File holding the API key, mode 0600. Preferred, with `SYSTEMAPI_API_KEY`; the agent removes `SYSTEMAPI_API_KEY` from its environment after reading it. `--api-key` works but is visible in the process list and logs a warning. |
| `--pty-user` | (none) | Account that `terminal:open` shells run as, with uid, gid and supplementary groups dropped. Required when the agent runs as root (else `pty_user_unset`). Must not be root. Membership in `docker`, `sudo`, `wheel`, `adm` and similar groups is logged and reported. |
| `--pty-allow-agent-user` | `false` | Let a non-root agent run `terminal:open` shells as its own user. Without it a non-root agent refuses them. Risk: that shell can read the agent's API key, state and recording key, and ptrace the agent. Recordings are then `user_owned`. |
| `--pty-record` | `true` | Record every input and output byte of each terminal session in an HMAC-chained file. `false` turns recording off (mode `off`). |
| `--pty-record-dir` | `/var/lib/systemapi/recordings` as root, else `<state dir>/recordings` | One `<session_id>.rec` file per session, directory mode 0700. The HMAC key is `recording.key` (0600) in the state directory. |
| `--pty-record-max-bytes` | 1 GiB | A session ends (`pty_exit` reason `stopped`, `record_error` `recording_size_limit`) once it has recorded this many bytes. |
| `--pty-record-min-free` | 1 GiB | A session is refused (`recording_unavailable`) when the recording filesystem has less free space than this. |

`terminal:root` sessions use their own lease action (`pty_root`), run as root,
and need an agent running as root. The agent keeps 4 of its 32 session slots
for `terminal:root` and break-glass. Ending a session (stop, lease expiry,
deadline, or the shell exiting) sends SIGHUP and then SIGKILL to its process
group and, on Linux, to every process in its session. On SIGINT, SIGTERM or a
lost connection the agent ends every session first.

### Verify a recording

```bash
sudo systemapi-agent verify-recording /var/lib/systemapi/recordings/<session_id>.rec \
  --digest <agent_exit.record.digest from the terminal_end audit row>
```

It replays the HMAC chain with the agent's key (`--key`, default
`~/.systemapi/recording.key` of the user running it, so run it as the agent's
user), requires the start line for that session id and the final `end` line,
and compares the final digest with `--digest` when given. It prints
`ok <session_id> digest=<hex>` and exits 0 when the recording is complete and
untouched; a truncated, edited, reordered or renamed file, a wrong key, or a
different digest exits 1. Bad usage exits 2.

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
