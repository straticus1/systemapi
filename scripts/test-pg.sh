#!/bin/sh
# npm run test:pg: starts postgres:16 in docker on a random 127.0.0.1 port,
# runs tests/registry-pg.test.js against it, and removes the container
# whatever the outcome. The database is throwaway and uses trust auth (the
# channel-policy case connects with a deliberately wrong password to prove it
# is never printed), so it is published on loopback only.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${PG_TEST_IMAGE:-postgres:16}
CID=$(docker run -d --rm -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 "$IMAGE")
cleanup() { docker rm -f "$CID" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
PORT=$(docker port "$CID" 5432/tcp | head -n 1 | sed 's/.*://')
i=0
until docker exec "$CID" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then echo "postgres did not become ready" >&2; exit 1; fi
  sleep 1
done
cd "$REPO"
SYSTEMAPI_TEST_DATABASE_URL="postgres://postgres@127.0.0.1:$PORT/postgres" \
  node --test tests/registry-pg.test.js
