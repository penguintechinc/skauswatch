#!/bin/bash
# Golden parity harness entrypoint (bash 3.2-safe).
#
# Boots identical-but-isolated infrastructure (one postgres with two
# identically seeded databases, one valkey with two DB indexes, one shared
# stub upstream), builds/starts the v1 Quart manager and the v2 Rust
# manager, replays the corpus against both, and diffs.
#
# Usage:
#   ./run.sh            # up + replay + down
#   ./run.sh up         # start infrastructure + both managers, leave running
#   ./run.sh replay     # replay corpus against running managers
#   ./run.sh down       # remove all harness containers + network
#
# Requires: docker, python3 with `requests`.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

NET=parity-net
PG=parity-pg
REDIS=parity-redis
STUB=parity-stub
V1=parity-v1
V2=parity-v2

PG_USER=parity
PG_PASS=paritypass
V1_PORT=15001
V2_PORT=15002

JWT_SECRET=parity-jwt-secret
EDR_API_SECRET=parity-edr-secret
export EDR_API_SECRET

# Cargo caches live in the session scratchpad (fall back to /tmp for
# standalone runs).
SCRATCH="${PARITY_SCRATCH:-/tmp/claude-1000/-home-penguin-code-skauswatch/1f7aef20-b887-40e5-9822-90f00d5419c0/scratchpad}"
mkdir -p "$SCRATCH/cargo-cache" "$SCRATCH/cargo-git" "$SCRATCH/target-parity" "$SCRATCH/pip-cache"

RUST_IMG=rust:1.97-slim-bookworm
PY_IMG=python:3.13-slim-bookworm
PG_IMG=postgres:17-bookworm
REDIS_IMG=valkey/valkey:8-bookworm

down() {
  for c in "$V1" "$V2" "$STUB" "$REDIS" "$PG"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "parity containers cleaned up"
}

wait_http() {
  # wait_http <url> <seconds>
  n=0
  while [ "$n" -lt "$2" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true)"
    case "$code" in
      200|503) return 0 ;;
    esac
    sleep 1
    n=$((n + 1))
  done
  echo "timeout waiting for $1" >&2
  return 1
}

build_v2() {
  echo "== building v2 manager (docker cargo) =="
  docker run --rm \
    -v "$REPO":/src -w /src \
    -v "$SCRATCH/cargo-cache":/usr/local/cargo/registry \
    -v "$SCRATCH/cargo-git":/usr/local/cargo/git \
    -v "$SCRATCH/target-parity":/t -e CARGO_TARGET_DIR=/t \
    "$RUST_IMG" cargo build -p skauswatch-manager
}

up() {
  down
  docker network create "$NET" >/dev/null

  echo "== postgres (two identical databases) =="
  docker run -d --name "$PG" --network "$NET" \
    -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=postgres \
    "$PG_IMG" >/dev/null
  n=0
  until docker exec "$PG" pg_isready -U "$PG_USER" >/dev/null 2>&1; do
    sleep 1; n=$((n + 1)); [ "$n" -lt 60 ] || { echo "postgres not ready" >&2; exit 1; }
  done
  docker exec "$PG" psql -q -U "$PG_USER" -d postgres \
    -c "CREATE DATABASE skauswatch_v1;" -c "CREATE DATABASE skauswatch_v2;"
  docker exec -i "$PG" psql -q -v ON_ERROR_STOP=1 -U "$PG_USER" -d skauswatch_v1 <"$HERE/seed.sql"
  docker exec -i "$PG" psql -q -v ON_ERROR_STOP=1 -U "$PG_USER" -d skauswatch_v2 <"$HERE/seed.sql"

  echo "== valkey (db 0 = v1, db 1 = v2) =="
  docker run -d --name "$REDIS" --network "$NET" "$REDIS_IMG" >/dev/null

  echo "== stub upstream (worker-scanner / worker-darwin / log-receiver / S3) =="
  docker run -d --name "$STUB" --network "$NET" \
    -v "$HERE/stub_upstream.py":/stub.py:ro \
    "$PY_IMG" python3 /stub.py >/dev/null

  build_v2

  echo "== v1 manager (Quart) =="
  # services/manager on this branch is the v2 Rust service; the v1 Python
  # source lives frozen on release/v1.0.x. Extract a pristine snapshot from
  # git history for the container mount.
  V1_SRC="$SCRATCH/v1-manager-src"
  rm -rf "$V1_SRC"
  mkdir -p "$V1_SRC"
  git -C "$REPO" archive release/v1.0.x services/manager | tar -x -C "$V1_SRC"
  # Dependencies install once into a persistent PYTHONUSERBASE volume so the
  # runner's poisoned-connection recovery (docker restart) reboots in
  # seconds instead of re-running pip (see README: v1 defect — a SQL error
  # aborts the shared PyDAL connection permanently).
  mkdir -p "$SCRATCH/pip-user"
  docker run -d --name "$V1" --network "$NET" -p "$V1_PORT":5000 \
    -v "$V1_SRC/services/manager":/app:ro \
    -v "$REPO/.version":/.version:ro \
    -v "$SCRATCH/pip-cache":/tmp/pip-cache \
    -v "$SCRATCH/pip-user":/pipuser \
    -w /app \
    -e PYTHONUSERBASE=/pipuser -e PATH=/pipuser/bin:/usr/local/bin:/usr/bin:/bin \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -e DB_TYPE=postgres -e DB_HOST="$PG" -e DB_PORT=5432 -e DB_NAME=skauswatch_v1 \
    -e DB_USER="$PG_USER" -e DB_PASS="$PG_PASS" \
    -e REDIS_URL="redis://$REDIS:6379/0" \
    -e JWT_SECRET_KEY="$JWT_SECRET" -e SECRET_KEY=parity-secret \
    -e EDR_API_SECRET="$EDR_API_SECRET" \
    -e GRPC_ENABLED=false -e QUART_ENV=production \
    -e WORKER_SCANNER_URL="http://$STUB:9999" \
    -e WORKER_DARWIN_URL="http://$STUB:9999" \
    -e LOG_RECEIVER_URL="http://$STUB:9999" \
    -e PIP_CACHE_DIR=/tmp/pip-cache \
    "$PY_IMG" bash -c \
    "[ -f /pipuser/.done ] || (pip install -q --user --require-hashes -r requirements.txt && touch /pipuser/.done); exec python3 main.py --port 5000" \
    >/dev/null

  echo "== v2 manager (Rust) =="
  docker run -d --name "$V2" --network "$NET" -p "$V2_PORT":5000 \
    -v "$SCRATCH/target-parity/debug/skauswatch-manager":/usr/local/bin/skauswatch-manager:ro \
    -v "$REPO/.version":/work/.version:ro \
    -w /work \
    -e DB_TYPE=postgresql -e DB_HOST="$PG" -e DB_PORT=5432 -e DB_NAME=skauswatch_v2 \
    -e DB_USER="$PG_USER" -e DB_PASS="$PG_PASS" \
    -e REDIS_URL="redis://$REDIS:6379/1" \
    -e JWT_SECRET_KEY="$JWT_SECRET" \
    -e EDR_API_SECRET="$EDR_API_SECRET" \
    -e GRPC_ENABLED=false \
    -e LICENSE_SERVER_URL="http://$STUB:9999" \
    -e WORKER_SCANNER_URL="http://$STUB:9999" \
    -e WORKER_DARWIN_URL="http://$STUB:9999" \
    -e LOG_RECEIVER_URL="http://$STUB:9999" \
    "$PY_IMG" skauswatch-manager serve \
    >/dev/null

  echo "== waiting for both managers =="
  wait_http "http://127.0.0.1:$V2_PORT/healthz" 60
  wait_http "http://127.0.0.1:$V1_PORT/healthz" 600   # first boot pip-installs
  echo "both managers up: v1 :$V1_PORT  v2 :$V2_PORT"
}

replay() {
  PARITY_V1_URL="http://127.0.0.1:$V1_PORT" \
  PARITY_V2_URL="http://127.0.0.1:$V2_PORT" \
  EDR_API_SECRET="$EDR_API_SECRET" \
  python3 "$HERE/runner.py"
}

case "${1:-all}" in
  up) up ;;
  replay) replay ;;
  down) down ;;
  all)
    trap down EXIT
    up
    replay
    ;;
  *)
    echo "usage: $0 [up|replay|down|all]" >&2
    exit 2
    ;;
esac
