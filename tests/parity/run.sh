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
ENDPOINT_API_SECRET=parity-endpoint-secret
export ENDPOINT_API_SECRET

# v2-only: skauswatch-vault envelope encryption (crates/skauswatch-vault/src/crypto.rs)
# is wired into the manager for S3 bucket credential storage (see
# services/manager/src/state.rs) and exits at startup if no VAULT_MEK* is
# set. Fixed 32 raw bytes, base64-standard-encoded, matching the KEY_LEN=32
# AES-256 requirement. v1 predates Vault entirely, so it needs no equivalent.
VAULT_MEK=cGFyaXR5LXZhdWx0LW1lay1maXhlZC0zMi1ieXRlcyE=

# Cargo/pip caches + build scratch dir. Override with PARITY_SCRATCH (CI
# sets this to a runner-temp path); defaults to a fixed /tmp dir for
# standalone local runs.
SCRATCH="${PARITY_SCRATCH:-/tmp/skauswatch-parity-scratch}"
mkdir -p "$SCRATCH/cargo-cache" "$SCRATCH/cargo-git" "$SCRATCH/target-parity" "$SCRATCH/pip-cache"

# v2-only: ES256 (EC P-256) JWT keypair for the manager. v2 replaced the
# HS256 shared-secret JWT_SECRET_KEY with an asymmetric keypair --
# JWT_SIGNING_KEY (private, PKCS#8) mints tokens, JWT_VERIFY_KEY (public,
# SPKI) verifies them. v1 predates this migration and keeps using the
# HS256 JWT_SECRET_KEY var below unchanged.
V2_JWT_DIR="$SCRATCH/jwt-keys"
V2_JWT_PRIV="$V2_JWT_DIR/signing-key.pem"
V2_JWT_PUB="$V2_JWT_DIR/verify-key.pem"

# Pinned by digest (external images — see backend-rust.md / devops-containers.md
# dependency-pinning rules); digests match the ones already pinned in
# services/manager/Dockerfile and .github/workflows/rust.yml so a single
# `docker pull` warms the cache for both the harness and the rest of CI.
RUST_IMG=rust:1.97-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777
PY_IMG=python:3.13-slim-bookworm@sha256:e853aef5a8b52fb7d636b7b545aea2fb90f41c27101ee1d2f25789f29a7b5cf8
PG_IMG=postgres:17-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394
REDIS_IMG=valkey/valkey:8-bookworm@sha256:fea8b3e67b15729d4bb70589eb03367bab9ad1ee89c876f54327fc7c6e618571

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

# aws-lc-sys (rustls' default crypto provider, pulled in transitively by
# reqwest/sqlx-tls everywhere in the workspace) needs cmake + a C/C++
# compiler + perl for its assembly codegen, plus libclang for bindgen; git is
# needed for the penguin-licensing workspace git dependency; ssh client covers
# git-over-ssh workspace deps if any are added later. Same package list as
# services/manager/Dockerfile's builder stage — the bare rust:*-slim-bookworm
# image ships none of this.
BUILD_DEPS="cmake clang libclang-dev perl pkg-config g++ make git openssh-client"

gen_v2_jwt_keys() {
  echo "== generating v2 ES256 JWT keypair =="
  command -v openssl >/dev/null 2>&1 || {
    echo "openssl not found -- required to generate the v2 ES256 JWT keypair" >&2
    exit 1
  }
  mkdir -p "$V2_JWT_DIR"
  openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -out "$V2_JWT_PRIV"
  openssl ec -in "$V2_JWT_PRIV" -pubout -out "$V2_JWT_PUB"
}

build_v2() {
  echo "== building v2 manager (docker cargo) =="
  docker run --rm \
    -v "$REPO":/src -w /src \
    -v "$SCRATCH/cargo-cache":/usr/local/cargo/registry \
    -v "$SCRATCH/cargo-git":/usr/local/cargo/git \
    -v "$SCRATCH/target-parity":/t -e CARGO_TARGET_DIR=/t \
    "$RUST_IMG" bash -c \
    "apt-get update -qq && apt-get install -y -qq --no-install-recommends $BUILD_DEPS >/dev/null && cargo build -p skauswatch-manager"
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
  # The official postgres image runs a transient init-only instance (initdb +
  # docker-entrypoint-initdb.d scripts) on the same Unix socket before
  # stopping it and starting the real server a moment later; pg_isready can
  # observe that transient instance as "accepting connections" and return
  # success just before the socket goes away for the handoff. Retry an
  # actual query (not just pg_isready) so we don't race that gap.
  n=0
  until docker exec "$PG" psql -q -U "$PG_USER" -d postgres -c "SELECT 1" >/dev/null 2>&1; do
    sleep 1; n=$((n + 1)); [ "$n" -lt 30 ] || { echo "postgres not accepting queries" >&2; exit 1; }
  done
  docker exec "$PG" psql -q -U "$PG_USER" -d postgres \
    -c "CREATE DATABASE skauswatch_v1;" -c "CREATE DATABASE skauswatch_v2;"
  docker exec -i "$PG" psql -q -v ON_ERROR_STOP=1 -U "$PG_USER" -d skauswatch_v1 <"$HERE/seed_v1.sql"
  docker exec -i "$PG" psql -q -v ON_ERROR_STOP=1 -U "$PG_USER" -d skauswatch_v2 <"$HERE/seed_v2.sql"

  echo "== valkey (db 0 = v1, db 1 = v2) =="
  docker run -d --name "$REDIS" --network "$NET" "$REDIS_IMG" >/dev/null

  echo "== stub upstream (scanner / worker-codescan / logs / S3) =="
  docker run -d --name "$STUB" --network "$NET" \
    -v "$HERE/stub_upstream.py":/stub.py:ro \
    "$PY_IMG" python3 /stub.py >/dev/null

  build_v2

  echo "== v1 manager (Quart) =="
  # services/manager on this branch is the v2 Rust service; the v1 Python
  # source lives frozen on release/v1.0.x. Extract a pristine snapshot from
  # git history for the container mount. Resolve the ref defensively: a
  # local dev clone has a local `release/v1.0.x` branch, but a CI checkout
  # (actions/checkout, even with fetch-depth:0) only creates the
  # remote-tracking ref `origin/release/v1.0.x` — no local branch.
  V1_REF="$(git -C "$REPO" rev-parse --verify --quiet release/v1.0.x || true)"
  if [ -z "$V1_REF" ]; then
    V1_REF="$(git -C "$REPO" rev-parse --verify --quiet origin/release/v1.0.x || true)"
  fi
  if [ -z "$V1_REF" ]; then
    echo "release/v1.0.x not found (checked local branch and origin/release/v1.0.x)" >&2
    exit 1
  fi
  V1_SRC="$SCRATCH/v1-manager-src"
  rm -rf "$V1_SRC"
  mkdir -p "$V1_SRC"
  git -C "$REPO" archive "$V1_REF" services/manager | tar -x -C "$V1_SRC"
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
    -e EDR_API_SECRET="$ENDPOINT_API_SECRET" \
    -e GRPC_ENABLED=false -e QUART_ENV=production \
    -e WORKER_SCANNER_URL="http://$STUB:9999" \
    -e WORKER_DARWIN_URL="http://$STUB:9999" \
    -e LOG_RECEIVER_URL="http://$STUB:9999" \
    -e PIP_CACHE_DIR=/tmp/pip-cache \
    "$PY_IMG" bash -c \
    "[ -f /pipuser/.done ] || (pip install -q --user --require-hashes -r requirements.txt && touch /pipuser/.done); exec python3 main.py --port 5000" \
    >/dev/null

  echo "== v2 manager (Rust) =="
  gen_v2_jwt_keys
  # RELEASE_MODE=false: skauswatch-identity (crates/skauswatch-identity/src/lib.rs)
  # hard-fails startup if the SPIFFE Workload API is unreachable while in
  # production posture — there is no SPIRE agent in this harness, and per
  # that crate's own docs RELEASE_MODE=false is the only supported way to
  # run outside production posture (no domain-based bypass exists, by
  # design). v1 predates SPIFFE identity entirely, so it needs no equivalent.
  # Rate limiting (tower_governor) is a v2-only feature (v1 has none); parity
  # compares API behavior, not throttling, so it is neutralized with huge
  # bursts (RATE_LIMIT_*_BURST below) — the rapid sequential /auth/* replay
  # would otherwise trip 429s (defaults: global 50 / auth 5). Documented
  # v1<->v2 divergence, handled here rather than allowlisting 20 auth 429s.
  # JWT_SIGNING_KEY/JWT_VERIFY_KEY: ES256 keypair generated by
  # gen_v2_jwt_keys above (v2-only -- v1 keeps the HS256 JWT_SECRET_KEY
  # used in its own docker run block, unchanged).
  docker run -d --name "$V2" --network "$NET" -p "$V2_PORT":5000 \
    -v "$SCRATCH/target-parity/debug/skauswatch-manager":/usr/local/bin/skauswatch-manager:ro \
    -v "$REPO/.version":/work/.version:ro \
    -w /work \
    -e DB_TYPE=postgresql -e DB_HOST="$PG" -e DB_PORT=5432 -e DB_NAME=skauswatch_v2 \
    -e DB_USER="$PG_USER" -e DB_PASS="$PG_PASS" \
    -e REDIS_URL="redis://$REDIS:6379/1" \
    -e JWT_SIGNING_KEY="$(cat "$V2_JWT_PRIV")" \
    -e JWT_VERIFY_KEY="$(cat "$V2_JWT_PUB")" \
    -e ENDPOINT_API_SECRET="$ENDPOINT_API_SECRET" \
    -e VAULT_MEK="$VAULT_MEK" \
    -e RELEASE_MODE=false \
    -e RATE_LIMIT_GLOBAL_BURST=1000000 \
    -e RATE_LIMIT_AUTH_BURST=1000000 \
    -e GRPC_ENABLED=false \
    -e LICENSE_SERVER_URL="http://$STUB:9999" \
    -e SCANNER_URL="http://$STUB:9999" \
    -e WORKER_CODESCAN_URL="http://$STUB:9999" \
    -e LOGS_URL="http://$STUB:9999" \
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
  ENDPOINT_API_SECRET="$ENDPOINT_API_SECRET" \
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
