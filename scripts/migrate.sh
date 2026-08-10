#!/bin/bash
# SkausWatch Database Migration Script
#
# Runs Alembic migrations for all services that have them.
# Requires postgres to be running in the target cluster.
#
# Usage:
#   ./scripts/migrate.sh [--env alpha|beta] [--service SERVICE] [--dry-run]
#
# Examples:
#   ./scripts/migrate.sh                              # migrate all services on beta
#   ./scripts/migrate.sh --env alpha                  # migrate all services on alpha
#   ./scripts/migrate.sh --service scanner     # migrate one service only
#   ./scripts/migrate.sh --dry-run                    # show current revision without upgrading

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# === Defaults ===
ENV="beta"
SPECIFIC_SERVICE=""
DRY_RUN=false
LOCAL_PG_PORT=15432   # local port for port-forward (avoids clash with local postgres on 5432)

# === Services with Alembic migrations ===
# Format: "helm-chart-name:service-dir:alembic-ini-path"
MIGRATION_SERVICES=(
  "worker-codescan:services/worker-codescan:alembic.ini"
  "scanner:services/scanner:alembic/alembic.ini"
)

# === Colors ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_header()  { echo -e "\n${CYAN}══════════════════════════════════════════${NC}\n${CYAN}$1${NC}\n${CYAN}══════════════════════════════════════════${NC}\n"; }

# === Argument parsing ===
while [[ $# -gt 0 ]]; do
  case $1 in
    --env)       ENV="$2";              shift 2 ;;
    --service)   SPECIFIC_SERVICE="$2"; shift 2 ;;
    --dry-run)   DRY_RUN=true;          shift ;;
    --help|-h)
      sed -n '3,14p' "$0" | sed 's/^# //'
      exit 0 ;;
    *) log_error "Unknown option: $1"; exit 1 ;;
  esac
done

# === Resolve K8s context and namespace ===
case "$ENV" in
  alpha) KUBE_CONTEXT="local-alpha" ;;
  beta)  KUBE_CONTEXT="dal2-beta"   ;;
  *)     log_error "Unknown --env '$ENV'. Use alpha or beta."; exit 1 ;;
esac
NAMESPACE="skauswatch"

# === Port-forward cleanup ===
PF_PID=""
cleanup() {
  if [[ -n "$PF_PID" ]] && kill -0 "$PF_PID" 2>/dev/null; then
    log_info "Stopping postgres port-forward (pid $PF_PID)..."
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# === Helpers ===

# Extract a key from a K8s secret (base64-decoded), or return a default
k8s_secret_get() {
  local secret_name="$1"
  local key="$2"
  local default="$3"
  local value
  value=$(kubectl --context "${KUBE_CONTEXT}" get secret "${secret_name}" \
    -n "${NAMESPACE}" \
    -o jsonpath="{.data.${key}}" 2>/dev/null | base64 --decode 2>/dev/null || true)
  echo "${value:-$default}"
}

# Check postgres pod is running
check_postgres_running() {
  local pg_pod
  pg_pod=$(kubectl --context "${KUBE_CONTEXT}" get pods -n "${NAMESPACE}" \
    -l app=postgres --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [[ -z "$pg_pod" ]]; then
    log_error "No running postgres pod found in namespace '${NAMESPACE}' on context '${KUBE_CONTEXT}'."
    log_error "Deploy infrastructure first (postgres + redis) before running migrations."
    log_info  "  kubectl --context ${KUBE_CONTEXT} apply -f k8s/manifests/namespace.yaml"
    log_info  "  kubectl --context ${KUBE_CONTEXT} apply -f k8s/manifests/configmap.yaml"
    log_info  "  kubectl --context ${KUBE_CONTEXT} apply -f k8s/manifests/secrets.yaml"
    log_info  "  kubectl --context ${KUBE_CONTEXT} apply -f k8s/manifests/postgres-secrets.yaml"
    log_info  "  kubectl --context ${KUBE_CONTEXT} apply -f k8s/manifests/postgres-deployment.yaml"
    log_info  "  kubectl --context ${KUBE_CONTEXT} apply -f k8s/manifests/postgres-service.yaml"
    exit 1
  fi
  log_success "Postgres pod running: ${pg_pod}"
}

# Start port-forward and wait until the port is accepting connections
start_port_forward() {
  log_info "Port-forwarding postgres service → localhost:${LOCAL_PG_PORT}..."
  kubectl --context "${KUBE_CONTEXT}" port-forward \
    -n "${NAMESPACE}" \
    svc/postgres "${LOCAL_PG_PORT}:5432" &>/dev/null &
  PF_PID=$!

  # Wait up to 10 seconds for the port to be open
  local attempts=0
  while ! nc -z localhost "${LOCAL_PG_PORT}" 2>/dev/null; do
    if (( ++attempts > 20 )); then
      log_error "Timed out waiting for port-forward on localhost:${LOCAL_PG_PORT}"
      exit 1
    fi
    sleep 0.5
  done
  log_success "Port-forward established on localhost:${LOCAL_PG_PORT}"
}

# Run alembic in the given service directory with the supplied env vars
run_alembic() {
  local service_dir="$1"
  local alembic_ini="$2"
  shift 2
  local env_vars=("$@")   # remaining args are VAR=value pairs

  local abs_dir="${PROJECT_ROOT}/${service_dir}"
  local abs_ini="${abs_dir}/${alembic_ini}"

  if [[ ! -f "$abs_ini" ]]; then
    log_warning "alembic.ini not found at ${abs_ini}, skipping."
    return 0
  fi

  # Resolve alembic executable: prefer venv, then PATH
  local alembic_bin
  if [[ -f "${abs_dir}/.venv/bin/alembic" ]]; then
    alembic_bin="${abs_dir}/.venv/bin/alembic"
  elif [[ -f "${abs_dir}/venv/bin/alembic" ]]; then
    alembic_bin="${abs_dir}/venv/bin/alembic"
  elif command -v alembic &>/dev/null; then
    alembic_bin="alembic"
  else
    log_error "alembic not found for ${service_dir}. Install with: pip3 install alembic"
    return 1
  fi

  local alembic_cmd=("$alembic_bin" "-c" "$abs_ini")
  if [[ "$DRY_RUN" == true ]]; then
    alembic_cmd+=("current")
    log_info "[dry-run] Showing current revision for ${service_dir}"
  else
    alembic_cmd+=("upgrade" "head")
    log_info "Running: alembic upgrade head in ${service_dir}"
  fi

  # Run with injected env vars.
  # NOTE: Do NOT blindly prepend $abs_dir to PYTHONPATH — if the service root
  # contains a directory named "alembic/", it would shadow the installed alembic
  # package and cause "No module named 'alembic.config'" errors.
  # Instead, pass EXTRA_PYTHONPATH per-caller only when an import needs it.
  local extra_pythonpath="${EXTRA_PYTHONPATH:-}"
  (
    cd "$abs_dir"
    if [[ -n "$extra_pythonpath" ]]; then
      export PYTHONPATH="${extra_pythonpath}:${PYTHONPATH:-}"
    fi
    for pair in "${env_vars[@]}"; do
      export "${pair?}"
    done
    "${alembic_cmd[@]}"
  )
}

# === Per-service migration functions ===

migrate_worker_codescan() {
  log_header "Migrating worker-codescan"

  # Use the postgres superuser (from postgres-credentials secret) so migrations
  # can run even before the per-service 'codescan' role is created.
  local pg_user pg_pass db_name
  pg_user=$(k8s_secret_get "postgres-credentials" "username" "skauswatch")
  pg_pass=$(k8s_secret_get "postgres-credentials" "password" "skauswatch-secure-password-2025")
  db_name=$(k8s_secret_get "postgres-credentials" "database" "skauswatch")

  # worker-codescan env.py reads through config/settings.py which uses:
  #   DB_TYPE, DB_HOST, DB_PORT, DB_NAME, CODESCAN_DB_USER, CODESCAN_DB_PASS
  # EXTRA_PYTHONPATH lets the subshell import config.settings without shadowing alembic.
  if ! EXTRA_PYTHONPATH="${PROJECT_ROOT}/services/worker-codescan" \
      run_alembic "services/worker-codescan" "alembic.ini" \
        "DB_TYPE=postgresql" \
        "DB_HOST=localhost" \
        "DB_PORT=${LOCAL_PG_PORT}" \
        "DB_NAME=${db_name}" \
        "CODESCAN_DB_USER=${pg_user}" \
        "CODESCAN_DB_PASS=${pg_pass}"; then
    log_error "worker-codescan migration failed"
    return 1
  fi

  log_success "worker-codescan migration complete"
}

migrate_scanner() {
  log_header "Migrating scanner"

  # Use the postgres superuser so migrations can run regardless of whether
  # the per-service 'app_user' role exists yet.
  local pg_user pg_pass db_name
  pg_user=$(k8s_secret_get "postgres-credentials" "username" "skauswatch")
  pg_pass=$(k8s_secret_get "postgres-credentials" "password" "skauswatch-secure-password-2025")
  db_name=$(k8s_secret_get "postgres-credentials" "database" "skauswatch")

  local database_url="postgresql://${pg_user}:${pg_pass}@localhost:${LOCAL_PG_PORT}/${db_name}"

  # scanner env.py reads DATABASE_URL directly.
  # Do NOT add the service dir to PYTHONPATH — it contains an alembic/ subdir
  # that would shadow the installed alembic package.
  if ! run_alembic "services/scanner" "alembic/alembic.ini" \
      "DATABASE_URL=${database_url}"; then
    log_error "scanner migration failed"
    return 1
  fi

  log_success "scanner migration complete"
}

# === Main ===

log_header "SkausWatch Migration — env=${ENV}"
log_info "Context:   ${KUBE_CONTEXT}"
log_info "Namespace: ${NAMESPACE}"
log_info "Dry-run:   ${DRY_RUN}"

check_postgres_running
start_port_forward

FAILED=()
for svc_spec in "${MIGRATION_SERVICES[@]}"; do
  IFS=':' read -r svc_name _ alembic_ini <<< "$svc_spec"

  # Skip if --service filter is active and doesn't match
  if [[ -n "$SPECIFIC_SERVICE" && "$SPECIFIC_SERVICE" != "$svc_name" ]]; then
    continue
  fi

  case "$svc_name" in
    worker-codescan)  migrate_worker_codescan  || FAILED+=("$svc_name") ;;
    scanner) migrate_scanner || FAILED+=("$svc_name") ;;
    *) log_warning "No migration function for ${svc_name}, skipping" ;;
  esac
done

echo ""
if [[ ${#FAILED[@]} -gt 0 ]]; then
  log_error "Migration FAILED for: ${FAILED[*]}"
  exit 1
else
  if [[ "$DRY_RUN" == true ]]; then
    log_success "Dry-run complete — no changes made."
  else
    log_success "All migrations applied successfully."
  fi
fi
