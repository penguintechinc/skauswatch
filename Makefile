# SkausWatch Makefile
# Rust workspace (12 services) + Node/React webui — no Python, no Docker Compose.
# Docker Compose is deprecated for all environments; deployment is Helm v4 -> Kubernetes only.

.PHONY: help build lint format test test-unit test-integration test-e2e test-security \
	test-functional test-parity smoke-test coverage test-coverage db-test-up db-test-down \
	seed-mock-data docker-build docker-push dev deploy-alpha deploy-beta clean version-update \
	version-update-minor version-update-major version-show license-validate \
	license-check-features pre-commit info env

.DEFAULT_GOAL := help

# === Variables ===
PROJECT_NAME := skauswatch
product := skauswatch
VERSION := $(shell cat .version 2>/dev/null | tr -d '[:space:]' || echo "development")
DOCKER_REGISTRY := ghcr.io
DOCKER_ORG := penguintechinc

# Rust workspace services (Cargo workspace members under services/) + webui (Node/React).
# Dockerfiles live at services/<dir>/Dockerfile, built from the REPO ROOT context.
RUST_SERVICES := manager pki sshca logs codescan-backend monitor vault s3scan scanner worker-codescan worker-vault-sync endpoint-agent
SERVICES := $(RUST_SERVICES) webui

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m

# === Help ===
help: ## Show this help message
	@echo "$(BLUE)$(PROJECT_NAME) Development Commands$(RESET)"
	@echo ""
	@echo "$(GREEN)Development Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Development/ {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Testing Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Testing/ {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Build Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Build/ {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Docker Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Docker/ {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Deploy Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Deploy/ {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Other Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && !/Development|Testing|Build|Docker|Deploy/ {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# === Development Commands ===
dev: ## Development - Deploy the workspace to local alpha (MicroK8s/Docker Desktop) via Helm
	@echo "$(BLUE)Deploying $(PROJECT_NAME) to local-alpha...$(RESET)"
	@echo "$(YELLOW)Docker Compose is deprecated — this deploys via Helm to the local-alpha K8s context.$(RESET)"
	@$(MAKE) deploy-alpha

# === Testing Commands ===
# DB-backed handler/repo tests (skauswatch-testkit) need a real reachable
# Postgres — see `db-test-up` below and docs/v2-port/testing-pattern.md.
# CI provides this via `services:` containers in .github/workflows/rust.yml;
# locally, run `make db-test-up` once before `test`/`smoke-test`/`coverage`.
test: ## Testing - Run all tests (cargo workspace + webui)
	@echo "$(BLUE)Running all tests...$(RESET)"
	cargo test --workspace --locked
	@cd services/webui && npm test
	@echo "$(GREEN)All tests completed!$(RESET)"

test-unit: ## Testing - Run unit tests only (cargo lib/bin targets)
	@echo "$(BLUE)Running unit tests...$(RESET)"
	cargo test --workspace --locked --lib --bins

test-integration: ## Testing - Run integration tests only (cargo tests/ targets)
	@echo "$(BLUE)Running integration tests...$(RESET)"
	cargo test --workspace --locked --test '*'

test-e2e: ## Testing - Run end-to-end tests (webui Playwright)
	@echo "$(BLUE)Running E2E tests...$(RESET)"
	@cd services/webui && npm run test:e2e
	@echo "$(YELLOW)Note: tests/e2e (legacy pytest, pre-Rust-migration) is stale and not wired in — pending its own cleanup.$(RESET)"

test-parity: ## Testing - Run golden parity harness (manager v1 vs v2; needs docker + release/v1.0.x)
	@echo "$(BLUE)Running v1/v2 manager parity harness...$(RESET)"
	@tests/parity/run.sh
	@echo "$(YELLOW)tests/smoke/s3_scan is NOT covered here — it needs a live deployed alpha/beta$(RESET)"
	@echo "$(YELLOW)stack (MinIO, WebUI, seeded auth user); run manually: tests/smoke/s3_scan/run_all.sh <alpha|beta>$(RESET)"

smoke-test: ## Testing - Build + quick workspace test pass (run before every commit)
	@echo "$(BLUE)Running smoke tests...$(RESET)"
	cargo build --workspace --locked
	cargo test --workspace --locked

test-coverage: coverage ## Testing - Alias for coverage

coverage: ## Testing - Generate coverage report (fails below 90% lines; requires `make db-test-up`)
	@echo "$(BLUE)Running coverage (>=90% lines required)...$(RESET)"
	cargo llvm-cov --workspace --locked --fail-under-lines 90 \
		--ignore-filename-regex '(^|/)src/main\.rs$$|(^|/)src/bin/'

db-test-up: ## Testing - Start throwaway Postgres + Valkey containers for local DB-backed tests
	@echo "$(BLUE)Starting test Postgres + Valkey...$(RESET)"
	docker network create skauswatch-test-net 2>/dev/null || true
	docker run --rm -d --name skauswatch-test-postgres --network skauswatch-test-net \
		-e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres \
		-p 5432:5432 postgres:17-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394
	docker run --rm -d --name skauswatch-test-valkey --network skauswatch-test-net \
		-p 6379:6379 valkey/valkey:8-bookworm@sha256:fea8b3e67b15729d4bb70589eb03367bab9ad1ee89c876f54327fc7c6e618571
	@echo "$(YELLOW)Waiting for Postgres to accept connections...$(RESET)"
	@until docker exec skauswatch-test-postgres pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	@echo "$(GREEN)Test DB ready — export DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASS=postgres DB_NAME=postgres$(RESET)"

db-test-down: ## Testing - Stop the local test Postgres + Valkey containers
	@echo "$(BLUE)Stopping test Postgres + Valkey...$(RESET)"
	-docker stop skauswatch-test-postgres skauswatch-test-valkey
	-docker network rm skauswatch-test-net

test-security: ## Testing - Run security scans (cargo-deny, npm audit, gitleaks)
	@echo "$(BLUE)Running security scans...$(RESET)"
	cargo deny check
	@cd services/webui && npm audit --omit=dev || true
	@if command -v gitleaks >/dev/null 2>&1; then echo "-- gitleaks --"; gitleaks detect --source . --no-git; fi

test-functional: ## Testing - Run functional tests
	@echo "$(YELLOW)No functional tests defined$(RESET)"

seed-mock-data: ## Testing - Seed services with mock data for development
	@echo "$(BLUE)Seeding mock data...$(RESET)"
	@echo "$(YELLOW)TODO: implement seed-mock-data (no seed script exists yet)$(RESET)"

pre-commit: ## Testing - Run pre-commit checks (lint, security, build, smoke-test, test, parity)
	@echo "$(BLUE)=== Pre-commit checks ===$(RESET)"
	@$(MAKE) lint
	@$(MAKE) test-security
	@$(MAKE) build
	@$(MAKE) smoke-test
	@$(MAKE) test
	@$(MAKE) test-parity
	@echo "$(GREEN)=== Pre-commit complete ===$(RESET)"

# === Build Commands ===
build: ## Build - Build the Rust workspace (release) + webui
	@echo "$(BLUE)Building all services...$(RESET)"
	cargo build --workspace --release --locked
	@cd services/webui && npm ci && npm run build
	@echo "$(GREEN)All builds completed!$(RESET)"

# === Code Quality Commands ===
lint: ## Code Quality - Run all linters (cargo, webui, Docker, shell, OpenAPI)
	@echo "$(BLUE)Linting all code...$(RESET)"
	cargo fmt --all --check
	cargo check --workspace --locked
	cargo clippy --workspace --all-targets --locked -- -D warnings
	@cd services/webui && npm run lint
	@if command -v hadolint >/dev/null 2>&1; then \
		echo "-- hadolint --"; \
		for f in services/*/Dockerfile; do [ -f "$$f" ] && hadolint "$$f"; done; \
	fi
	@if command -v shellcheck >/dev/null 2>&1; then \
		echo "-- shellcheck --"; \
		find scripts -name "*.sh" -print0 | xargs -0 -r shellcheck; \
	fi
	@if ls services/*/openapi/v1.yaml >/dev/null 2>&1; then \
		if command -v spectral >/dev/null 2>&1; then echo "-- spectral --"; spectral lint --ruleset .spectral.yaml --fail-severity=error services/*/openapi/v1.yaml; \
		else echo "$(YELLOW)spectral not installed, skipping OpenAPI lint$(RESET)"; fi; \
	fi

format: ## Code Quality - Format Rust + webui code
	@echo "$(BLUE)Formatting code...$(RESET)"
	cargo fmt --all
	@cd services/webui && npm run format --if-present

# === Docker Commands ===
docker-build: ## Docker - Build all SkausWatch service images (repo-root context)
	@echo "$(BLUE)Building Docker images...$(RESET)"
	@for svc in $(SERVICES); do \
		echo "$(YELLOW)Building $$svc...$(RESET)"; \
		docker build -f services/$$svc/Dockerfile -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(product)/$$svc:$(VERSION) . || exit 1; \
	done
	@echo "$(GREEN)All images built!$(RESET)"

docker-push: ## Docker - Push all service images to registry
	@echo "$(BLUE)Pushing Docker images...$(RESET)"
	@for svc in $(SERVICES); do \
		echo "$(YELLOW)Pushing $$svc...$(RESET)"; \
		docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(product)/$$svc:$(VERSION) || exit 1; \
	done

# === Deploy Commands ===
deploy-alpha: ## Deploy - Deploy all charts to local-alpha via Helm
	@echo "$(BLUE)Deploying to local-alpha...$(RESET)"
	@for svc in $(SERVICES); do \
		echo "$(YELLOW)helm upgrade --install $$svc (local-alpha)...$(RESET)"; \
		helm upgrade --install $$svc ./k8s/helm/$$svc \
			--kube-context local-alpha \
			--namespace $(product) --create-namespace \
			--values ./k8s/helm/$$svc/alpha.yml \
			--set image.tag=$(VERSION) || exit 1; \
	done

deploy-beta: ## Deploy - Deploy all charts to dal2-beta via Helm (CI-built images only)
	@echo "$(BLUE)Deploying to dal2-beta...$(RESET)"
	@for svc in $(SERVICES); do \
		echo "$(YELLOW)helm upgrade --install $$svc (dal2-beta)...$(RESET)"; \
		helm upgrade --install $$svc ./k8s/helm/$$svc \
			--kube-context dal2-beta \
			--namespace $(product) --create-namespace \
			--values ./k8s/helm/$$svc/beta.yml || exit 1; \
	done

# === Version Management Commands ===
version-update: ## Version - Update version (build epoch by default)
	@./scripts/version/update-version.sh

version-update-minor: ## Version - Update minor version
	@./scripts/version/update-version.sh minor

version-update-major: ## Version - Update major version
	@./scripts/version/update-version.sh major

version-show: ## Version - Show current version
	@echo "Current version: $(VERSION)"

# === License Commands ===
license-validate: ## License - Validate license configuration
	@echo "$(BLUE)Validating license configuration...$(RESET)"
	@curl -f $${LICENSE_SERVER_URL:-https://license.penguintech.io}/api/v2/validate \
		-H "Authorization: Bearer $${LICENSE_KEY}" \
		-H "Content-Type: application/json" \
		-d '{"product": "skauswatch"}'

license-check-features: ## License - Check available licensed features
	@echo "$(BLUE)Checking licensed features...$(RESET)"
	@curl -s $${LICENSE_SERVER_URL:-https://license.penguintech.io}/api/v2/features \
		-H "Authorization: Bearer $${LICENSE_KEY}" \
		-H "Content-Type: application/json" \
		-d '{"product": "skauswatch"}'

# === Cleanup Commands ===
clean: ## Clean - Clean build artifacts and caches
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	cargo clean
	@rm -rf services/webui/dist services/webui/coverage
	@rm -rf htmlcov/ coverage.xml .coverage

# === Info Commands ===
info: ## Info - Show project information and deployment hosts
	@echo "$(BLUE)Project Information:$(RESET)"
	@echo "  Name:           $(PROJECT_NAME)"
	@echo "  Version:        $(VERSION)"
	@echo "  Services:       $(SERVICES)"
	@echo ""
	@echo "$(BLUE)Deployment Hosts:$(RESET)"
	@echo "  Alpha (local):  https://skauswatch.localhost.local (context: local-alpha)"
	@echo "  Beta:           https://skauswatch.penguintech.cloud (context: dal2-beta)"
	@echo "  Gamma:          https://skauswatch-gamma.penguintech.cloud (context: dal2-gamma)"

env: ## Info - Show relevant environment variables
	@echo "$(BLUE)Environment Variables:$(RESET)"
	@env | grep -E "^(LICENSE_|SKAUSWATCH_|AWS_|DATABASE_|DB_)" | sort
