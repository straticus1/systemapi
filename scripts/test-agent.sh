#!/bin/sh
# npm run test:agent: the real Go agent against the real control plane
# (.omc/plans/async-sysscript-jobs.md §11, required before commit 6c).
# Builds the agent for Linux, starts postgres:16 in docker on a random
# 127.0.0.1 port with a random password, then runs
# tests/sysscript-jobs-agent.test.js. That test starts server.js against the
# database, mints the agent key with scripts/bootstrap-admin.js, runs the
# agent in a Linux container (--init) and drives it through the public HTTP
# API. Every container carries this run's label and is removed whatever the
# outcome, as is the work directory holding the binary.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PG_IMAGE=${PG_TEST_IMAGE:-postgres:16}
AGENT_IMAGE=${AGENT_TEST_IMAGE:-debian:bookworm-slim}
GO_IMAGE=${GO_TEST_IMAGE:-golang:1.25}
RUN=$(node -e 'process.stdout.write(require("crypto").randomBytes(6).toString("hex"))')
WORK=
cleanup() {
  ids=$(docker ps -aq --filter "label=systemapi-e2e=$RUN" 2>/dev/null || true)
  if [ -n "$ids" ]; then docker rm -f $ids >/dev/null 2>&1 || true; fi
  if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM
WORK=$(mktemp -d)

ARCH=$(docker version -f '{{.Server.Arch}}')
if command -v go >/dev/null 2>&1; then
  (cd "$REPO/systemapi-agent" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -tags sysscript_jobs_e2e -o "$WORK/systemapi-agent" .)
else
  docker run --rm --label "systemapi-e2e=$RUN" \
    -v "$REPO":/src -v "$WORK":/out \
    -v systemapi-gomod:/go/pkg/mod -v systemapi-gobuild:/root/.cache/go-build \
    -e CGO_ENABLED=0 -w /src/systemapi-agent \
    "$GO_IMAGE" go build -tags sysscript_jobs_e2e -o /out/systemapi-agent .
fi

PASS=$(node -e 'process.stdout.write(require("crypto").randomBytes(18).toString("hex"))')
CID=$(docker run -d --rm --label "systemapi-e2e=$RUN" -e POSTGRES_PASSWORD="$PASS" -p 127.0.0.1::5432 "$PG_IMAGE")
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
SYSTEMAPI_E2E_PROXY_HOST="$PROXY_HOST" \
  node --test tests/sysscript-jobs-agent.test.js
