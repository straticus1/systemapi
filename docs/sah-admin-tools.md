# SAH admin helper scripts

Two scripts in `systemapi.io/scripts` wrap control-plane operations that have no
HTTP route. They are operator and admin convenience. They are not part of the
suite's cross-repo Wired join (`docs/sah-suite.md`); if this file and that one
disagree about what is wired, that file wins.

## sahpolicy.py — set a host's channel policy

Drives the channel-policy HTTP API (`api_docs.md`, "Channel policy") with
`SYSTEMAPI_URL` and `SYSTEMAPI_API_KEY` (or `SYSTEMAPI_TOKEN_FILE` from
`cli/systemapi.js login --fresh`, needed for a dangerous change). No ssh to the
control plane; `scripts/channel-policy.js` there stays the break-glass path.
Every write does a dry run first; add `--dry-run` to stop there and
`--confirm-dangerous` to apply a dangerous one.

```
sahpolicy.py show    [--host miniapps1]
sahpolicy.py add     [--host miniapps1] [--reason R] <grant flags>   # merge
sahpolicy.py set     [--host miniapps1] [--reason R] <grant flags>   # replace
sahpolicy.py clear | inherit [--host miniapps1] [--reason R]
```

- `--host` defaults to `miniapps1`. `--reason` defaults to `sahpolicy update`.
- `add` is merge-aware: GET, then PUT with `if_version`, re-sending every
  existing grant plus the new ones, so it never silently drops one (a write in
  between is a 409, not a lost update). If the live policy
  has a shape it cannot round-trip (for example a tcp CIDR rule), it refuses
  rather than write a partial policy. Use `set` for those.
- Grant flags, repeatable: `--service UNIT`, `--package NAME`, `--config DIR`,
  `--tweak-sysctl KEY`, `--tweak-unit UNIT`, `--tcp-local PORT`,
  `--file-read DIR`, `--file-write DIR`.

`--tcp-local`, `--file-read`, and `--file-write` back the wired TCP and file
channels (Wired join items 8 and 9). `--service`, `--package`, `--config`,
`--tweak-sysctl`, and `--tweak-unit` back the sys channels, which are partially
wired (see below): the `channel-policy.js` deployed on an enrolled host accepts
them, but the sys routes are not on `main` yet.

## sah_sys.mjs — sys-channel client

Node 22 built-ins only (`fetch` and `WebSocket`). The admin key is read from
`~/.config/sahcore/admin-api-key` (override `SAHCORE_ADMIN_KEY_FILE`). `API`
defaults to `https://api.systemapi.io`; the host name is `miniapps1`.

```
node scripts/sah_sys.mjs <purpose> '<json binding>'
```

Purposes and their binding verbs:

- `sys:tweak`   `{"verb":"sysctl-get","key":"net.ipv4.ip_forward"}` /
  `{"verb":"sysctl-set","key":"...","value":"..."}`
- `sys:package` `{"name":"cowsay","action":"query"}`
- `sys:config`  `{"action":"read","target":"/etc/hostname"}`
- `sys:service` `{"unit":"cron.service","action":"restart"}`

Flow: `GET /api/v1/hosts/resolve?name=miniapps1`, then `POST /api/v1/ws-ticket`
with the purpose, the `host_id`, and the binding under the field named for the
purpose, then the WebSocket `/api/v1/systems/sys/<host_id>?ticket=&purpose=`,
then exactly one `sys_result` frame. The binding must match the host's policy
allowlist (deny by default); a disallowed binding answers a `*_denied` error.

## Wired state (read before trusting the above as GA)

The sys channel is **partially wired**. The client (`sah_sys.mjs`), the policy
grants (`sahpolicy.py`), the control-plane sys routes (`sys:service`,
`sys:package`, `sys:config`, `sys:tweak`) and the agent's privilege-separated
mutation helpers (`sysctl_helper.go`, `config_helper.go`,
`systemd_override_helper.go`) are all on `main` (3f9b952, 5c86dbc); production
runs agent 5c86dbc. Reads work. Writes need the `sah-*-helper@` units and the
helper trust file, which the deploy kit does not install yet (planned:
`.omc/plans/sah-fleet-readiness.md` P3b), so writes fail on production.
