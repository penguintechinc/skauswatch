#!/usr/bin/env bash
# check-breaking.sh — local mirror of .github/workflows/proto.yml.
#
# Runs `buf breaking` of the live proto/ tree against the committed
# wire-compat baseline (proto/baseline/, what fielded v1 EDR agents compiled
# against), then `buf lint`. Uses the exact same pinned bufbuild/buf docker
# image as CI. Bash 3.2 compatible (macOS default shell).
#
# Usage: scripts/proto/check-breaking.sh

set -eu

# Same pin as .github/workflows/proto.yml — keep the two in sync.
BUF_IMAGE="bufbuild/buf:1.72.0@sha256:65bd496a89c762ad7151ca9e7d885a45dacb3671a8e8ec39738b9f844d3405ea"

# Resolve repo root without requiring the caller's cwd.
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required (runs ${BUF_IMAGE})" >&2
    exit 1
fi

echo "==> buf breaking: proto/ vs proto/baseline (FILE rules)"
docker run --rm \
    --volume "${REPO_ROOT}:/workspace:ro" \
    --workdir /workspace \
    "${BUF_IMAGE}" \
    breaking proto --against proto/baseline

echo "==> buf lint: proto/"
docker run --rm \
    --volume "${REPO_ROOT}:/workspace:ro" \
    --workdir /workspace \
    "${BUF_IMAGE}" \
    lint proto

echo "OK: proto/ is wire-compatible with the committed baseline"
