#!/bin/sh
# npm run test:agent: the real Go agent against the real control plane
# (.omc/plans/async-sysscript-jobs.md §11, required before commit 6c).
# Builds the agent for Linux, starts postgres:16 in docker on a random
# 127.0.0.1 port with a random password, then runs
# tests/sysscript-jobs-agent.test.js. That test starts server.js against the
# database, mints the agent key with scripts/bootstrap-admin.js, runs the
# agent in a Linux container (--init) and drives it through the public HTTP
# API. Every container and network carries this run's label and is removed
# whatever the outcome, as is the work directory holding the binary and the
# password file. E2E_SLACK (default 1) stretches the test's timing bounds.
#
# Networks: Postgres and the agent each get their own labelled bridge
# network, so neither shares the default bridge with unrelated containers
# and the agent cannot reach Postgres. They are not --internal: an internal
# network drops the published Postgres port and the agent's route to the
# test's proxy on the host (host.docker.internal), which this test needs.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# Pinned by digest; the tag is what the digest was resolved from.
PG_IMAGE=${PG_TEST_IMAGE:-postgres:16@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54}
AGENT_IMAGE=${AGENT_TEST_IMAGE:-debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251}
GO_IMAGE=${GO_TEST_IMAGE:-golang:1.25@sha256:699337d620559a59b4a2bb298ad59611e535d2ee755a34cf2d2a98f37578dc80}
RUN=$(node -e 'process.stdout.write(require("crypto").randomBytes(6).toString("hex"))')
LABEL="systemapi-e2e=$RUN"
WORK=
cleanup() {
  ids=$(docker ps -aq --filter "label=$LABEL" 2>/dev/null || true)
  if [ -n "$ids" ]; then docker rm -f $ids >/dev/null 2>&1 || true; fi
  nets=$(docker network ls -q --filter "label=$LABEL" 2>/dev/null || true)
  if [ -n "$nets" ]; then docker network rm $nets >/dev/null 2>&1 || true; fi
  if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Preflight: the agent refuses a recorded PTY (recording_disk_low,
# systemapi-agent/recorder.go) when the Docker VM has under its default
# --pty-record-min-free (1 GiB), which otherwise shows up as an opaque
# terminal timeout. Check free space on the same storage containers use by
# running df inside the already-pinned agent image, and fail early with
# room to spare.
FREE_BYTES=$(docker run --rm --label "$LABEL" "$AGENT_IMAGE" df -B1 / | awk 'NR==2 {print $4}')
case "$FREE_BYTES" in
  '' | *[!0-9]*)
    echo "could not read free disk space from the agent image ($AGENT_IMAGE); check Docker is running" >&2
    exit 1
    ;;
esac
MIN_FREE_BYTES=$((2 * 1024 * 1024 * 1024))
if [ "$FREE_BYTES" -lt "$MIN_FREE_BYTES" ]; then
  FREE_GIB=$(awk -v b="$FREE_BYTES" 'BEGIN { printf "%.2f", b / 1073741824 }')
  echo "Docker VM disk has only ${FREE_GIB} GiB free; the agent needs >= 1 GiB free" \
    "(--pty-record-min-free, systemapi-agent/recorder.go) to record a PTY and refuses" \
    "with recording_disk_low below that. Free up Docker Desktop disk space and retry." >&2
  exit 1
fi

WORK=$(mktemp -d)

# Only systemapi-agent/ is mounted, read-only; the binary goes to /out.
ARCH=$(docker version -f '{{.Server.Arch}}')
if command -v go >/dev/null 2>&1; then
  (cd "$REPO/systemapi-agent" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$WORK/systemapi-agent" .)
else
  docker run --rm --label "$LABEL" \
    -v "$REPO/systemapi-agent":/src:ro -v "$WORK":/out \
    -v systemapi-gomod:/go/pkg/mod -v systemapi-gobuild:/root/.cache/go-build \
    -e CGO_ENABLED=0 -w /src \
    "$GO_IMAGE" go build -o /out/systemapi-agent .
fi

DB_NET="systemapi-e2e-db-$RUN"
AGENT_NET="systemapi-e2e-agent-$RUN"
docker network create --label "$LABEL" "$DB_NET" >/dev/null
docker network create --label "$LABEL" "$AGENT_NET" >/dev/null

# The password reaches Postgres as a 0600 file mounted read-only, never on
# the docker command line or in the container's environment. Postgres runs
# as this user so it can read that file, with its data directory under /tmp
# (the image's PGDATA belongs to its own postgres user).
PASS=$(node -e 'process.stdout.write(require("crypto").randomBytes(18).toString("hex"))')
(umask 077 && printf '%s' "$PASS" > "$WORK/pgpass")
CID=$(docker run -d --rm --label "$LABEL" --network "$DB_NET" --user "$(id -u):$(id -g)" \
  -e PGDATA=/tmp/pgdata \
  -v "$WORK/pgpass":/run/secrets/pgpass:ro -e POSTGRES_PASSWORD_FILE=/run/secrets/pgpass \
  -p 127.0.0.1::5432 "$PG_IMAGE")
PORT=$(docker port "$CID" 5432/tcp | head -n 1 | sed 's/.*://')
i=0
until docker exec "$CID" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then echo "postgres did not become ready" >&2; exit 1; fi
  sleep 1
done

# The agent container reaches the test's WebSocket proxy through
# host.docker.internal. Docker Desktop forwards that to the host's loopback;
# on Linux it is the bridge gateway, so the proxy listens there instead.
PROXY_HOST=127.0.0.1
if [ "$(uname -s)" = Linux ]; then
  PROXY_HOST=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
fi

cd "$REPO"
SYSTEMAPI_AGENT_BIN="$WORK/systemapi-agent" \
SYSTEMAPI_TEST_DATABASE_URL="postgres://postgres:$PASS@127.0.0.1:$PORT/postgres" \
SYSTEMAPI_E2E_RUN="$RUN" \
SYSTEMAPI_E2E_IMAGE="$AGENT_IMAGE" \
SYSTEMAPI_E2E_NETWORK="$AGENT_NET" \
SYSTEMAPI_E2E_PROXY_HOST="$PROXY_HOST" \
  node --test tests/sysscript-jobs-agent.test.js
