#!/bin/sh
# npm run test:pg: starts postgres:16 in docker on a random 127.0.0.1 port
# with a random password, runs tests/registry-pg.test.js against it, and
# removes the container whatever the outcome.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${PG_TEST_IMAGE:-postgres:16}
CID=
cleanup() { if [ -n "${CID:-}" ]; then docker rm -f "$CID" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT INT TERM
PASS=$(node -e 'process.stdout.write(require("crypto").randomBytes(18).toString("hex"))')
CID=$(docker run -d --rm -e POSTGRES_PASSWORD="$PASS" -p 127.0.0.1::5432 "$IMAGE")
PORT=$(docker port "$CID" 5432/tcp | head -n 1 | sed 's/.*://')
i=0
until docker exec "$CID" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then echo "postgres did not become ready" >&2; exit 1; fi
  sleep 1
done
cd "$REPO"
SYSTEMAPI_TEST_DATABASE_URL="postgres://postgres:$PASS@127.0.0.1:$PORT/postgres" \
  node --test tests/registry-pg.test.js
