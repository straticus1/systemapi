# Ansible driver

The connection plugin runs one argv as `sys.exec.run`. It does not start a shell.

Pipes, redirects, and `&&` are refused because the API does not run a shell. Semicolons and backticks are refused too. A quoted argument that still contains those characters is refused.

Set these in the environment before running Ansible:

- `SYSTEMAPI_URL` — API base URL. A single trailing slash is stripped.
- `SYSTEMAPI_API_KEY` — sent only as the `X-API-Key` header, never as a query parameter or an inventory variable.

`SYSTEMAPI_TENANT` is optional and is not printed. Do not put the API key in `ansible.cfg`, group vars, or argv.

```bash
export ANSIBLE_CONNECTION_PLUGINS=drivers/ansible/plugins/connection
```

`ansible_host` is the SystemAPI host id. `ansible_connection` is `systemapi`.

File copy and stdin are not supported, so modules that upload a payload (`command`, `shell`) fail on `put_file`. Use `ansible.builtin.raw` with `gather_facts: false` so the command string reaches `exec_command`. `raw` still cannot use shell syntax (`|`, `>`, `<`, `;`, `&&`, backticks).
