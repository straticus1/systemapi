#!/bin/sh
# Runs the agent's Go tests on Linux (golang in docker) with the race detector.
# The whole repo is mounted so ../controlplane/testdata resolves from
# systemapi-agent/. --init reaps the zombies that the process-group tests
# leave behind. The module and build caches live in named docker volumes so
# repeated runs do not download again. Extra arguments go to `go test`
# (default: ./...).
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${GO_TEST_IMAGE:-golang:1.25}
if [ "$#" -eq 0 ]; then set -- ./...; fi
exec docker run --rm --init \
  -v "$REPO":/src \
  -v systemapi-gomod:/go/pkg/mod \
  -v systemapi-gobuild:/root/.cache/go-build \
  -w /src/systemapi-agent \
  "$IMAGE" go test -race -count=1 "$@"
