#!/usr/bin/env python3
"""sahpolicy — set a host's SAH channel policy without the ssh/systemd-run incantation.

There is no HTTP route that writes a host's channel policy (by design); it is set
by scripts/channel-policy.js running as the sahcore user on the control-plane host.
This wraps that over ssh so you type grants, not boilerplate.

  sahpolicy.py show [--host miniapps1]
  sahpolicy.py add  [--host miniapps1] [--reason R] <grant flags>     # merge: keep existing, add these
  sahpolicy.py set  [--host miniapps1] [--reason R] <grant flags>     # replace: exactly these
  sahpolicy.py clear | inherit [--host miniapps1] [--reason R]

Grant flags (repeatable): --service UNIT  --package NAME  --config DIR
  --tweak-sysctl KEY  --tweak-unit UNIT  --tcp-local PORT
  --file-read DIR  --file-write DIR

`add` reads the current policy and re-emits every existing grant plus yours, so it
never silently drops one. If the live policy has a shape it cannot round-trip
(e.g. a tcp CIDR rule), it refuses rather than set a partial policy — use `set`.
"""
import argparse, json, shlex, subprocess, sys

GRANTS = ["service", "package", "config", "tweak-sysctl", "tweak-unit", "tcp-local", "file-read", "file-write"]
REMOTE_NODE = "/opt/sahcore/node/bin/node"
REMOTE_CP = "/opt/sahcore/current/scripts/channel-policy.js"


def run_channel_policy(host, subcmd, reason, flags):
    """Build and run the channel-policy.js invocation on `host` over ssh. Returns stdout."""
    cp = [REMOTE_NODE, REMOTE_CP, subcmd, "--tenant", "afterdark", "--host", host]
    if subcmd != "show":
        cp += ["--reason", reason]
    cp += flags
    systemd_run = [
        "systemd-run", "--quiet", "--pipe", "--wait", "--collect", "--service-type=exec",
        "-p", "User=sahcore", "-p", "Group=sahcore", "-p", "UMask=0077",
        "-p", "NoNewPrivileges=yes", "-p", "PrivateTmp=yes",
        "-p", "EnvironmentFile=/etc/sahcore/sahcore.env", "-p", "Environment=ENV_FILE=/dev/null",
        "-p", "WorkingDirectory=/opt/sahcore/current",
    ] + cp
    remote = " ".join(shlex.quote(t) for t in systemd_run)
    proc = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", host, remote],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        sys.exit(f"sahpolicy: channel-policy {subcmd} failed on {host}")
    return proc.stdout


def flags_from_policy(pol):
    """Reconstruct the channel-policy.js grant flags from a host_*_policy JSON blob.
    Refuses (returns None, reason) on any shape it cannot faithfully round-trip."""
    flags = []
    tcp = (pol.get("host_tcp_policy") or {}).get("allow") or []
    for a in tcp:
        if not a.get("local") or a.get("cidr"):
            return None, "tcp policy has a non-local/CIDR rule; use `set` explicitly"
        for p in a.get("ports", []):
            flags += ["--tcp-local", str(p)]
    for r in (pol.get("host_file_policy") or {}).get("roots") or []:
        if r.get("root"):
            return None, "file policy has a file:root grant; use `set` explicitly"
        if r.get("write"):
            flags += ["--file-write", r["path"]]
        elif r.get("read"):
            flags += ["--file-read", r["path"]]
        else:
            return None, f"file root {r.get('path')!r} is neither read nor write; use `set`"
    for u in (pol.get("host_service_policy") or {}).get("units") or []:
        flags += ["--service", u]
    for n in (pol.get("host_package_policy") or {}).get("names") or []:
        flags += ["--package", n]
    for p in (pol.get("host_config_policy") or {}).get("paths") or []:
        flags += ["--config", p]
    tw = pol.get("host_tweak_policy") or {}
    for k in tw.get("sysctls") or []:
        flags += ["--tweak-sysctl", k]
    for u in tw.get("units") or []:
        flags += ["--tweak-unit", u]
    return flags, None


def grant_flags_from_args(args):
    flags = []
    for g in GRANTS:
        for v in getattr(args, g.replace("-", "_")) or []:
            flags += [f"--{g}", str(v)]
    return flags


def dedup(flags):
    """Dedup (flag,value) pairs, preserving order."""
    out, seen = [], set()
    for i in range(0, len(flags), 2):
        pair = (flags[i], flags[i + 1])
        if pair not in seen:
            seen.add(pair)
            out += [pair[0], pair[1]]
    return out


def main():
    ap = argparse.ArgumentParser(prog="sahpolicy", description="set a host's SAH channel policy")
    ap.add_argument("subcmd", choices=["show", "add", "set", "clear", "inherit"])
    ap.add_argument("--host", default="miniapps1")
    ap.add_argument("--reason", default="sahpolicy update")
    for g in GRANTS:
        ap.add_argument(f"--{g}", action="append", metavar=g.upper())
    args = ap.parse_args()

    if args.subcmd == "show":
        sys.stdout.write(run_channel_policy(args.host, "show", "", []))
        return
    if args.subcmd in ("clear", "inherit"):
        sys.stdout.write(run_channel_policy(args.host, args.subcmd, args.reason, []))
        return

    new = grant_flags_from_args(args)
    if args.subcmd == "set":
        if not new:
            sys.exit("sahpolicy set: give at least one grant, or use clear/inherit")
        sys.stdout.write(run_channel_policy(args.host, "set", args.reason, new))
        return

    # add: read current, merge, set the union
    try:
        cur = json.loads(run_channel_policy(args.host, "show", "", []))
    except json.JSONDecodeError:
        sys.exit("sahpolicy add: could not parse the current policy; use `set` explicitly")
    existing, why = flags_from_policy(cur)
    if existing is None:
        sys.exit(f"sahpolicy add: refusing (would drop a grant): {why}")
    merged = dedup(existing + new)
    if not merged:
        sys.exit("sahpolicy add: nothing to grant")
    sys.stdout.write(run_channel_policy(args.host, "set", args.reason, merged))


if __name__ == "__main__":
    main()
