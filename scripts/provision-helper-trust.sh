#!/usr/bin/env bash
# provision-helper-trust.sh — install the mutation helpers' trust anchor,
# /etc/systemapi-agent/helper-trust.json (systemapi-agent/helper_auth.go).
#
# usage: provision-helper-trust.sh --pubkey <base64 control key> --host-id <uuid>
#                                  [--state <agent.json>] [--out <trust file>]
#
# The control-plane public key is the root of trust for every helper write, so
# it must come from an OUT-OF-BAND pinned value (the install bundle, or the
# operator reading it from the control plane), never from the agent: agent.json
# lives in the agent-writable state dir, so a compromised agent could have put
# its own key there. This script takes the pinned key as --pubkey, reads
# agent.json only to CROSS-CHECK it, and refuses on any mismatch. --host-id is
# required for the same reason: it selects which host's leases verify, so it is
# pinned out of band too and never defaulted from agent.json.
#
# Linux only: the final rename uses GNU mv -T (never move INTO a directory that
# appeared at the trust path). The script probes for -T and refuses without it
# (BSD/macOS mv has no -T).
#
# Threats: a key substituted in agent.json, a symlink planted at the trust file,
# its directory or agent.json, a partial write, and a non-root run. Every
# failure exits non-zero and leaves any existing trust file untouched. The new
# file is written to a temp file in the same directory, made 0644 root:root,
# and renamed over the old one. Only host_id and control_pubkey are written;
# agent.json's private seed is never copied. Does NOT protect against someone
# who is already root (they can write the file themselves).
set -euo pipefail

STATE=/var/lib/systemapi-agent/agent.json
OUT=/etc/systemapi-agent/helper-trust.json
PUBKEY=
HOST_ID=

die() {
  echo "provision-helper-trust: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --pubkey) [ $# -ge 2 ] || die "--pubkey needs a value"; PUBKEY=$2; shift 2 ;;
    --host-id) [ $# -ge 2 ] || die "--host-id needs a value"; HOST_ID=$2; shift 2 ;;
    --state) [ $# -ge 2 ] || die "--state needs a value"; STATE=$2; shift 2 ;;
    --out) [ $# -ge 2 ] || die "--out needs a value"; OUT=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "must run as root"
[ -n "$PUBKEY" ] || die "--pubkey is required (the out-of-band pinned control-plane key)"
# A canonical standard-base64 32-byte Ed25519 key: 43 characters and one "=".
[[ "$PUBKEY" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] || die "--pubkey is not a base64 32-byte key"
[ -n "$HOST_ID" ] || die "--host-id is required (the out-of-band pinned host id)"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
[[ "$HOST_ID" =~ $UUID_RE ]] || die "--host-id is not a host id"
command -v jq >/dev/null 2>&1 || die "jq is required"
mv -T --help >/dev/null 2>&1 || die "needs GNU mv -T (coreutils); this script targets Linux hosts"

[ ! -L "$STATE" ] || die "$STATE is a symlink"
[ -f "$STATE" ] || die "$STATE is not a regular file (has the agent enrolled?)"
STATE_KEY=$(jq -er '.control_pubkey | strings' "$STATE") || die "$STATE has no control_pubkey"
STATE_HOST=$(jq -er '.host_id | strings' "$STATE") || die "$STATE has no host_id"
[ "$STATE_KEY" = "$PUBKEY" ] || die "control_pubkey in $STATE does not match the pinned --pubkey; refusing"
[[ "$STATE_HOST" =~ $UUID_RE ]] || die "host_id in $STATE is not a host id"
[ "$STATE_HOST" = "$HOST_ID" ] || die "host_id in $STATE does not match --host-id; refusing"

DIR=$(dirname "$OUT")
[ ! -L "$DIR" ] || die "$DIR is a symlink"
if [ ! -e "$DIR" ]; then
  mkdir -p "$DIR"
  chmod 0755 "$DIR"
fi
[ -d "$DIR" ] || die "$DIR is not a directory"
# helper_auth.go refuses a trust dir that is not root-owned or is group/other
# writable.
chown root:root "$DIR"
chmod go-w "$DIR"
[ ! -L "$OUT" ] || die "$OUT is a symlink"
if [ -e "$OUT" ] && [ ! -f "$OUT" ]; then
  die "$OUT exists and is not a regular file"
fi

TMP=$(mktemp "$DIR/.helper-trust.XXXXXX")
trap 'rm -f "$TMP"' EXIT
jq -n --arg h "$HOST_ID" --arg k "$PUBKEY" '{host_id: $h, control_pubkey: $k}' > "$TMP"
chown root:root "$TMP"
chmod 0644 "$TMP"
sync
mv -fT "$TMP" "$OUT"
trap - EXIT
sync
echo "provision-helper-trust: wrote $OUT for host $HOST_ID"
