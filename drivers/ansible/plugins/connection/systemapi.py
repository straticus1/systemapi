"""SystemAPI Ansible connection plugin.

Pipes, redirects, and ``&&`` are refused because the API does not run a shell.
``shlex.split`` supplies argv for ``sys.exec.run``. The API key is read from
``SYSTEMAPI_API_KEY`` and sent only as ``X-API-Key``. ``SYSTEMAPI_TENANT`` is
optional and is not printed.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DOCUMENTATION = """
name: systemapi
short_description: Run a command on a SystemAPI host
description:
  - Pipes, redirects, and && are refused because the API does not run a shell.
options:
  host:
    description: SystemAPI host id.
    vars:
      - name: ansible_host
      - name: inventory_hostname
"""

try:
    from ansible.errors import AnsibleError
    from ansible.plugins.connection import ConnectionBase
except ImportError:
    class ConnectionBase:  # type: ignore[no-redef]
        _systemapi_stub = True

        def __init__(self, play_context=None, new_stdin=None, *args, **kwargs):
            self._play_context = play_context
            self._connected = False

        def get_option(self, name):
            raise KeyError(name)

    class AnsibleError(RuntimeError):
        pass

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from systemapi_exec import starlark_exec  # noqa: E402

_SCRIPT_MAX = 64 * 1024
_BODY_MAX = 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise AnsibleError("redirect_rejected")


def _public(text, key):
    if not isinstance(text, str) or not text or (key and len(key) >= 8 and key in text):
        return "request_failed"
    return text


def _config():
    raw = (os.environ.get("SYSTEMAPI_URL") or "").strip()
    key = os.environ.get("SYSTEMAPI_API_KEY") or ""
    missing = []
    if not raw:
        missing.append("SYSTEMAPI_URL")
    if not key.strip():
        missing.append("SYSTEMAPI_API_KEY")
    if missing:
        raise AnsibleError("missing " + ", ".join(missing))
    if raw.endswith("/"):
        raw = raw[:-1]
    parts = urllib.parse.urlsplit(raw)
    leaked = any(name in ("api_key", "api-key") for name, _ in urllib.parse.parse_qsl(parts.query))
    if parts.scheme not in ("http", "https") or parts.username or parts.password or leaked:
        raise AnsibleError("invalid SYSTEMAPI_URL")
    path = parts.path[:-1] if len(parts.path) > 1 and parts.path.endswith("/") else parts.path
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", "")), key


class Connection(ConnectionBase):
    transport = "systemapi"
    has_pipelining = False

    def __init__(self, play_context=None, new_stdin=None, *args, **kwargs):
        self._play_context = play_context
        self._connected = False
        if not getattr(ConnectionBase, "_systemapi_stub", False):
            super().__init__(play_context, new_stdin, *args, **kwargs)

    def _connect(self):
        self._connected = True
        return self

    def close(self):
        self._connected = False

    def put_file(self, in_path, out_path, **kwargs):
        raise AnsibleError("systemapi does not copy files")

    def fetch_file(self, in_path, out_path, **kwargs):
        raise AnsibleError("systemapi does not fetch files")

    def _host_id(self):
        host = None
        getter = getattr(self, "get_option", None)
        if callable(getter):
            try:
                host = getter("host")
            except Exception:
                host = None
        if not host:
            play = getattr(self, "_play_context", None)
            if play is not None:
                host = getattr(play, "remote_addr", None) or getattr(play, "host", None)
        if not isinstance(host, str) or not host.strip():
            raise AnsibleError("host id required")
        host = host.strip()
        if host in (".", "..") or ".." in host or "/" in host or "\\" in host or any(ch.isspace() for ch in host):
            raise AnsibleError("invalid host id")
        return host

    def _post(self, endpoint, payload, key):
        req = urllib.request.Request(endpoint, data=payload, method="POST", headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-API-Key": key,
        })
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        try:
            resp = opener.open(req, timeout=60)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(_BODY_MAX + 1)
        except AnsibleError as exc:
            return 0, _public(str(exc), key).encode()
        try:
            return resp.status, resp.read(_BODY_MAX + 1)
        finally:
            resp.close()

    def exec_command(self, cmd, in_data=None, sudoable=True, **kwargs):
        if in_data:
            return (1, b"", b"stdin is not supported\n")
        if isinstance(cmd, bytes):
            cmd = cmd.decode("utf-8", "replace")
        if not isinstance(cmd, str):
            return (1, b"", b"bad command\n")
        try:
            script = starlark_exec(shlex.split(cmd))
            base, key = _config()
            host = self._host_id()
        except (ValueError, AnsibleError) as exc:
            return (1, b"", ((str(exc) or "request_failed") + "\n").encode())
        if len(script.encode("utf-8")) > _SCRIPT_MAX:
            return (1, b"", b"script larger than 64 KiB\n")
        endpoint = base + "/api/v1/fleet/" + urllib.parse.quote(host, safe="") + "/execute"
        payload = json.dumps({"script": script, "entitlements": {"allow_exec": True}}).encode()
        try:
            status, raw = self._post(endpoint, payload, key)
        except urllib.error.URLError:
            return (1, b"", b"request_failed\n")
        if status == 0:
            return (1, b"", raw + (b"" if raw.endswith(b"\n") else b"\n"))
        if len(raw) > _BODY_MAX:
            return (1, b"", b"response_too_large\n")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return (1, b"", b"request_failed\n")
        if not isinstance(parsed, dict):
            return (1, b"", b"bad_response\n")
        if status >= 400:
            return (1, b"", (_public(parsed.get("error"), key) + "\n").encode())
        result = parsed.get("result") if isinstance(parsed.get("result"), dict) else {}
        output = result.get("output") if isinstance(result.get("output"), str) else ""
        error = result.get("error") if isinstance(result.get("error"), str) else ""
        if key and len(key) >= 8 and (key in output or key in error):
            return (1, b"", b"request_failed\n")
        stdout = output.encode("utf-8")
        if error:
            err = error.encode("utf-8")
            return (1, stdout, err if err.endswith(b"\n") else err + b"\n")
        return (0, stdout, b"")
