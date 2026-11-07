#!/usr/bin/env python3
"""sahpolicy — set a host's SAH channel policy over the channel-policy HTTP API.

Talks to /api/v1/hosts/<id>/channel-policy (api_docs.md) with an admin key,
so no ssh to the control-plane host is needed. scripts/channel-policy.js stays
the break-glass path there.

  sahpolicy.py show [--host miniapps1]
  sahpolicy.py add  [--host miniapps1] [--reason R] <grant flags>     # merge: keep existing, add these
  sahpolicy.py set  [--host miniapps1] [--reason R] <grant flags>     # replace: exactly these
  sahpolicy.py clear | inherit [--host miniapps1] [--reason R]
  any write: [--dry-run] [--confirm-dangerous LIST]

Grant flags (repeatable): --service UNIT  --package NAME  --config DIR
  --tweak-sysctl KEY  --tweak-unit UNIT  --tcp-local PORT
  --file-read DIR  --file-write DIR

Environment: SYSTEMAPI_URL, and SYSTEMAPI_API_KEY or SYSTEMAPI_TOKEN_FILE (a
token from `cli/systemapi.js login --fresh`, needed for a dangerous change;
the server refuses API keys for those). A key is sent only as X-API-Key, a
token only as Authorization: Bearer; neither is ever printed.

Every write reads the current version and asks for a dry run first; it
applies only without --dry-run, and a dangerous change (P2c) only once the
dry run's list was shown (stderr) and confirmed: --confirm-dangerous with
exactly that comma list, or y at a y/N prompt on a terminal. Plain http is
allowed only to 127.0.0.1, localhost or ::1 (exact hostname). `add` is GET + PUT with if_version: it re-sends every
existing grant plus yours, so it never drops one. If the live policy holds a
shape the API cannot round-trip (e.g. a tcp CIDR rule) or a column that
inherits, the server's `grants` is null and `add` refuses rather than set a
partial policy — use `set`.
"""
import argparse, json, os, re, sys, urllib.error, urllib.parse, urllib.request

GRANTS = ["service", "package", "config", "tweak-sysctl", "tweak-unit", "tcp-local", "file-read", "file-write"]
HOST_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BODY_MAX = 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# Plain http only to this machine, by the exact parsed hostname (so
# http://localhost.evil.example or http://127.0.0.1@evil.example is refused).
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


def url_ok(base):
    try:
        u = urllib.parse.urlsplit(base)
        u.port  # raises on a bad port
    except ValueError:
        return False
    if u.username is not None or u.password is not None or not u.hostname or u.query or u.fragment:
        return False
    return u.scheme == "https" or (u.scheme == "http" and u.hostname in LOCAL_HOSTS)


def credentials():
    base = (os.environ.get("SYSTEMAPI_URL") or "").strip().rstrip("/")
    if not url_ok(base):
        sys.exit("sahpolicy: SYSTEMAPI_URL must be an https:// URL")
    key = (os.environ.get("SYSTEMAPI_API_KEY") or "").strip()
    bearer = False
    if not key:
        bearer = True
        path = os.environ.get("SYSTEMAPI_TOKEN_FILE") or ""
        if not os.path.isabs(path):
            sys.exit("sahpolicy: set SYSTEMAPI_API_KEY or an absolute SYSTEMAPI_TOKEN_FILE")
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, encoding="utf-8") as f:
                key = f.read(1024).strip()
        except OSError:
            sys.exit("sahpolicy: token_file_rejected")
    if len(key) < 8 or re.search(r"\s", key):
        sys.exit("sahpolicy: the key or token is malformed")
    return base, key, bearer


def call(cfg, method, path, body=None, query=None):
    base, key, bearer = cfg
    url = base + path + ("?" + urllib.parse.urlencode(query) if query else "")
    data = None if body is None else json.dumps(body).encode()
    # An API key as X-API-Key; a device token (SYSTEMAPI_TOKEN_FILE) as a
    # bearer, so the server sees a session principal that can pass step-up.
    headers = {"Authorization": "Bearer " + key} if bearer else {"X-API-Key": key}
    headers["Accept"] = "application/json"
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=20) as res:
            status, raw = res.status, res.read(BODY_MAX + 1)
    except urllib.error.HTTPError as err:
        status, raw = err.code, err.read(BODY_MAX + 1)
    except (urllib.error.URLError, OSError):
        sys.exit("sahpolicy: request_failed")
    if len(raw) > BODY_MAX:
        sys.exit("sahpolicy: response_too_large")
    try:
        parsed = json.loads(raw.decode() or "null")
    except ValueError:
        sys.exit("sahpolicy: bad_response")
    if key in json.dumps(parsed):
        sys.exit("sahpolicy: request_failed")
    return status, parsed


def fail(parsed):
    err = parsed.get("error") if isinstance(parsed, dict) else None
    reason = parsed.get("reason") if isinstance(parsed, dict) else None
    sys.exit("sahpolicy: " + (str(err) if err else "request_failed") + (f": {reason}" if reason else ""))


def host_id(cfg, name):
    if HOST_ID_RE.match(name):
        return name
    status, parsed = call(cfg, "GET", "/api/v1/hosts/resolve", query={"name": name})
    if status != 200 or not isinstance(parsed, dict) or not HOST_ID_RE.match(str(parsed.get("host_id", ""))):
        fail(parsed)
    return parsed["host_id"]


def grants_from_args(args):
    out = {}
    for g in GRANTS:
        values = getattr(args, g.replace("-", "_")) or []
        if values:
            out[g.replace("-", "_")] = [int(v) if g == "tcp-local" and v.isdigit() else v for v in values]
    return out


def merge(existing, new):
    out = {k: list(v) for k, v in existing.items() if v}
    for k, values in new.items():
        for v in values:
            out.setdefault(k, [])
            if v not in out[k]:
                out[k].append(v)
    return out


def ask_yes(question):
    sys.stderr.write(question)
    sys.stderr.flush()
    try:
        answer = sys.stdin.readline(64)
    except (OSError, ValueError):
        return False
    return answer.strip().lower() in ("y", "yes")


def write(cfg, base, verb, reason, version, grants, dry_run, confirm):
    body = {"reason": reason, "if_version": version}
    method, path = ("PUT", base) if verb == "set" else ("POST", f"{base}/{verb}")
    if verb == "set":
        body["grants"] = grants
    status, dry = call(cfg, method, path, body, query={"dry_run": "1"})
    if status != 200:
        fail(dry)
    if dry_run:
        return dry
    dangerous = dry.get("dangerous")
    if dangerous:
        if not isinstance(dangerous, list) or not all(isinstance(e, str) for e in dangerous):
            sys.exit("sahpolicy: bad_response")
        listed = ",".join(sorted(dangerous))
        sys.stderr.write("sahpolicy: dangerous: " + listed + "\n")
        if confirm is not None:
            named = sorted(set(e.strip() for e in confirm.split(",") if e.strip()))
            if ",".join(named) != listed:
                sys.stdout.write(json.dumps(dry, indent=2) + "\n")
                sys.exit("sahpolicy: dangerous_mismatch: --confirm-dangerous must name exactly: " + listed)
        elif not (sys.stdin.isatty() and sys.stderr.isatty() and ask_yes("apply these dangerous grants? [y/N] ")):
            sys.stdout.write(json.dumps(dry, indent=2) + "\n")
            sys.exit("sahpolicy: dangerous change; rerun with --confirm-dangerous " + listed + " and a `login --fresh` token")
        body["confirm_dangerous"] = dangerous
    status, done = call(cfg, method, path, body)
    if status != 200:
        fail(done)
    return done


def main():
    ap = argparse.ArgumentParser(prog="sahpolicy", description="set a host's SAH channel policy over the API")
    ap.add_argument("subcmd", choices=["show", "add", "set", "clear", "inherit"])
    ap.add_argument("--host", default="miniapps1")
    ap.add_argument("--reason", default="sahpolicy update")
    ap.add_argument("--dry-run", action="store_true")
    # The exact dangerous list the dry run names, comma separated.
    ap.add_argument("--confirm-dangerous", metavar="LIST", default=None)
    for g in GRANTS:
        ap.add_argument(f"--{g}", action="append", metavar=g.upper())
    args = ap.parse_args()

    cfg = credentials()
    base = "/api/v1/hosts/" + urllib.parse.quote(host_id(cfg, args.host), safe="") + "/channel-policy"
    status, cur = call(cfg, "GET", base)
    if status != 200 or not isinstance(cur, dict):
        fail(cur)
    if args.subcmd == "show":
        sys.stdout.write(json.dumps(cur, indent=2) + "\n")
        return
    new = grants_from_args(args)
    if args.subcmd in ("clear", "inherit"):
        if new:
            sys.exit(f"sahpolicy {args.subcmd}: takes no grant flags")
        out = write(cfg, base, args.subcmd, args.reason, cur["version"], None, args.dry_run, args.confirm_dangerous)
    elif args.subcmd == "set":
        if not new:
            sys.exit("sahpolicy set: give at least one grant, or use clear/inherit")
        out = write(cfg, base, "set", args.reason, cur["version"], new, args.dry_run, args.confirm_dangerous)
    else:
        existing = cur.get("grants")
        # A host that inherits everything has nothing of its own to keep.
        if all(v is None for v in (cur.get("host") or {}).values()):
            existing = {}
        if existing is None:
            sys.exit("sahpolicy add: refusing (would drop a grant): the host policy holds a shape the API cannot round-trip, or an inherited column; use `set`")
        merged = merge(existing, new)
        if not merged:
            sys.exit("sahpolicy add: nothing to grant")
        out = write(cfg, base, "set", args.reason, cur["version"], merged, args.dry_run, args.confirm_dangerous)
    sys.stdout.write(json.dumps(out, indent=2) + "\n")


if __name__ == "__main__":
    main()
