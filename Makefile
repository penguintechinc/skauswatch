# SkausWatch Makefile
# Development and operational tasks for the SkausWatch project

.PHONY: help setup dev test build clean lint format docker deploy

# Default target
.DEFAULT_GOAL := help

# Variables
PROJECT_NAME := skauswatch
VERSION := $(shell cat .version 2>/dev/null || echo "development")
DOCKER_REGISTRY := ghcr.io
DOCKER_ORG := penguintechinc
PYTHON_VERSION := 3.13

# Service directories
SERVICES := services/manager-new services/pki-server-new services/ssh-ca services/aaa-monitor services/worker-s3 services/worker-scanner services/webui services/edr-agent

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m

# Help target
help: ## Show this help message
	@echo "$(BLUE)$(PROJECT_NAME) Development Commands$(RESET)"
	@echo ""
	@echo "$(GREEN)Setup Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Setup/ {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
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
	@echo "$(GREEN)Other Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && !/Setup|Development|Testing|Build|Docker/ {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Setup Commands
setup: ## Setup - Install all dependencies and initialize the project
	@echo "$(BLUE)Setting up $(PROJECT_NAME)...$(RESET)"
	@$(MAKE) setup-env
	@$(MAKE) setup-python
	@$(MAKE) setup-git-hooks
	@echo "$(GREEN)Setup complete!$(RESET)"

setup-env: ## Setup - Create environment file from template
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)Creating .env from .env.example...$(RESET)"; \
		cp .env.example .env; \
		echo "$(YELLOW)Please edit .env with your configuration$(RESET)"; \
	fi

setup-python: ## Setup - Install Python dependencies and tools
	@echo "$(BLUE)Setting up Python dependencies...$(RESET)"
	@python3 --version || (echo "$(RED)Python $(PYTHON_VERSION) not installed$(RESET)" && exit 1)
	@pip install --upgrade pip
	@for svc in $(SERVICES); do \
		if [ -f $$svc/requirements.txt ]; then \
			echo "$(YELLOW)Installing $$svc requirements...$(RESET)"; \
			pip install -r $$svc/requirements.txt; \
		fi; \
	done
	@pip install black isort flake8 mypy pytest pytest-cov

setup-git-hooks: ## Setup - Install Git pre-commit hooks
	@echo "$(BLUE)Installing Git hooks...$(RESET)"
	@if [ -f scripts/git-hooks/pre-commit ]; then \
		cp scripts/git-hooks/pre-commit .git/hooks/pre-commit; \
		chmod +x .git/hooks/pre-commit; \
	fi
	@if [ -f scripts/git-hooks/commit-msg ]; then \
		cp scripts/git-hooks/commit-msg .git/hooks/commit-msg; \
		chmod +x .git/hooks/commit-msg; \
	fi

# Development Commands
dev: ## Development - Start full development stack with Docker Compose
	@echo "$(BLUE)Starting $(PROJECT_NAME) development environment...$(RESET)"
	@docker-compose -f docker-compose.dev.yml up -d
	@echo "$(GREEN)Development stack started. See 'make info' for service URLs.$(RESET)"

dev-full: ## Development - Start full stack (production compose)
	@docker-compose up -d

dev-db: ## Development - Start only database services
	@docker-compose up -d postgres redis

dev-monitoring: ## Development - Start monitoring services
	@docker-compose up -d prometheus grafana

dev-stop: ## Development - Stop development environment
	@docker-compose -f docker-compose.dev.yml down

# Testing Commands
test: ## Testing - Run all tests
	@echo "$(BLUE)Running all tests...$(RESET)"
	@$(MAKE) test-python
	@echo "$(GREEN)All tests completed!$(RESET)"

test-python: ## Testing - Run Python tests for all services
	@echo "$(BLUE)Running Python tests...$(RESET)"
	@pytest tests/ \
		--cov=services \
		--cov-report=xml:coverage.xml \
		--cov-report=html:htmlcov \
		-v

test-unit: ## Testing - Run unit tests
	@echo "$(BLUE)Running unit tests...$(RESET)"
	@pytest tests/unit/ -v

test-integration: ## Testing - Run integration tests
	@echo "$(BLUE)Running integration tests...$(RESET)"
	@docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit
	@docker-compose -f docker-compose.test.yml down

test-e2e: ## Testing - Run end-to-end tests
	@echo "$(BLUE)Running E2E tests...$(RESET)"
	@pytest tests/e2e/ -v

smoke-test: ## Testing - Run smoke tests
	@echo "$(BLUE)Running smoke tests...$(RESET)"
	@pytest tests/smoke/ -v

test-coverage: ## Testing - Generate coverage report
	@$(MAKE) test-python
	@echo "$(GREEN)Coverage report generated: htmlcov/ and coverage.xml$(RESET)"

seed-mock-data: ## Testing - Seed services with mock data for development
	@echo "$(BLUE)Seeding mock data...$(RESET)"
	@python3 scripts/seed-mock-data.py 2>/dev/null || echo "$(YELLOW)seed-mock-data.py not found, skipping$(RESET)"

# Build Commands
build: ## Build - Validate all Python services compile cleanly
	@echo "$(BLUE)Building all services...$(RESET)"
	@$(MAKE) build-python
	@echo "$(GREEN)All builds completed!$(RESET)"

build-python: ## Build - Syntax-check all Python services
	@echo "$(BLUE)Checking Python services...$(RESET)"
	@python3 -m compileall services/manager-new || true
	@python3 -m compileall services/pki-server-new || true
	@python3 -m compileall services/ssh-ca || true
	@python3 -m compileall services/aaa-monitor || true
	@python3 -m compileall services/worker-s3 || true
	@python3 -m compileall services/worker-scanner || true
	@python3 -m compileall services/webui || true
	@python3 -m compileall services/edr-agent || true

# Docker Commands
docker-build: ## Docker - Build all SkausWatch service images
	@echo "$(BLUE)Building Docker images...$(RESET)"
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-manager:$(VERSION) \
		-f services/manager-new/Dockerfile services/manager-new/
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-pki-server:$(VERSION) \
		-f services/pki-server-new/Dockerfile services/pki-server-new/
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-ssh-ca:$(VERSION) \
		-f services/ssh-ca/Dockerfile services/ssh-ca/
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-aaa-monitor:$(VERSION) \
		-f services/aaa-monitor/Dockerfile services/aaa-monitor/
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-worker-s3:$(VERSION) \
		-f services/worker-s3/Dockerfile services/worker-s3/
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-worker-scanner:$(VERSION) \
		-f services/worker-scanner/Dockerfile services/worker-scanner/
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-webui:$(VERSION) \
		-f services/webui/Dockerfile services/webui/
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-edr-agent:$(VERSION) \
		-f services/edr-agent/Dockerfile services/edr-agent/
	@echo "$(GREEN)All images built!$(RESET)"

docker-push: ## Docker - Push all service images to registry
	@echo "$(BLUE)Pushing Docker images...$(RESET)"
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-manager:$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-pki-server:$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-ssh-ca:$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-aaa-monitor:$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-worker-s3:$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-worker-scanner:$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-webui:$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-edr-agent:$(VERSION)

docker-run: ## Docker - Run application with Docker Compose
	@docker-compose up --build

docker-clean: ## Docker - Clean up Docker resources
	@echo "$(BLUE)Cleaning up Docker resources...$(RESET)"
	@docker-compose down -v
	@docker system prune -f

# Code Quality Commands
lint: ## Code Quality - Run Python linting across all services
	@echo "$(BLUE)Linting Python code...$(RESET)"
	@flake8 services/ --max-line-length=120 --exclude=__pycache__,.git
	@mypy services/ --ignore-missing-imports

format: ## Code Quality - Format Python code across all services
	@echo "$(BLUE)Formatting Python code...$(RESET)"
	@black services/
	@isort services/

# Database Commands
db-migrate: ## Database - Run database migrations
	@echo "$(BLUE)Running database migrations...$(RESET)"
	@python3 scripts/migrate.py 2>/dev/null || echo "$(YELLOW)migrate.py not found, skipping$(RESET)"

db-seed: ## Database - Seed database with test data
	@echo "$(BLUE)Seeding database...$(RESET)"
	@$(MAKE) seed-mock-data

db-reset: ## Database - Reset database (WARNING: destroys data)
	@echo "$(RED)WARNING: This will destroy all data!$(RESET)"
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ]
	@docker-compose down -v
	@docker-compose up -d postgres redis
	@sleep 5
	@$(MAKE) db-migrate
	@$(MAKE) db-seed

db-backup: ## Database - Create skauswatch database backup
	@echo "$(BLUE)Creating database backup...$(RESET)"
	@mkdir -p backups
	@docker-compose exec postgres pg_dump -U postgres skauswatch > backups/backup-$(shell date +%Y%m%d-%H%M%S).sql

db-restore: ## Database - Restore database from backup (requires BACKUP_FILE)
	@echo "$(BLUE)Restoring database from $(BACKUP_FILE)...$(RESET)"
	@docker-compose exec -T postgres psql -U postgres skauswatch < $(BACKUP_FILE)

# License Commands
license-validate: ## License - Validate license configuration
	@echo "$(BLUE)Validating license configuration...$(RESET)"
	@python3 scripts/license-validate.py 2>/dev/null || \
		curl -f $${LICENSE_SERVER_URL:-https://license.penguintech.io}/api/v2/validate \
		-H "Authorization: Bearer $${LICENSE_KEY}" \
		-H "Content-Type: application/json" \
		-d '{"product": "skauswatch"}'

license-check-features: ## License - Check available licensed features
	@echo "$(BLUE)Checking licensed features...$(RESET)"
	@curl -s $${LICENSE_SERVER_URL:-https://license.penguintech.io}/api/v2/features \
		-H "Authorization: Bearer $${LICENSE_KEY}" \
		-H "Content-Type: application/json" \
		-d '{"product": "skauswatch"}' | python3 -m json.tool

# Version Management Commands
version-update: ## Version - Update version (patch by default)
	@./scripts/version/update-version.sh

version-update-minor: ## Version - Update minor version
	@./scripts/version/update-version.sh minor

version-update-major: ## Version - Update major version
	@./scripts/version/update-version.sh major

version-show: ## Version - Show current version
	@echo "Current version: $(VERSION)"

# Deployment Commands
deploy-dev: ## Deploy - Deploy to beta (penguintech.cloud)
	@echo "$(BLUE)Deploying to beta environment...$(RESET)"
	@$(MAKE) docker-build
	@$(MAKE) docker-push

deploy-prod: ## Deploy - Deploy to production environment
	@echo "$(BLUE)Deploying to production...$(RESET)"
	@$(MAKE) docker-build
	@$(MAKE) docker-push

# Health Check Commands
health: ## Health - Check all service health endpoints
	@echo "$(BLUE)Checking service health...$(RESET)"
	@curl -sf http://localhost:5000/health && echo "$(GREEN)manager: OK$(RESET)" || echo "$(RED)manager (5000): FAILED$(RESET)"
	@curl -sf http://localhost:5001/health && echo "$(GREEN)pki-server: OK$(RESET)" || echo "$(RED)pki-server (5001): FAILED$(RESET)"
	@curl -sf http://localhost:5002/health && echo "$(GREEN)ssh-ca: OK$(RESET)" || echo "$(RED)ssh-ca (5002): FAILED$(RESET)"
	@curl -sf http://localhost:5003/health && echo "$(GREEN)aaa-monitor: OK$(RESET)" || echo "$(RED)aaa-monitor (5003): FAILED$(RESET)"
	@curl -sf http://localhost:5004/health && echo "$(GREEN)worker-scanner: OK$(RESET)" || echo "$(RED)worker-scanner (5004): FAILED$(RESET)"
	@curl -sf http://localhost:3000/health && echo "$(GREEN)webui: OK$(RESET)" || echo "$(RED)webui (3000): FAILED$(RESET)"

logs: ## Logs - Show all service logs
	@docker-compose logs -f

logs-manager: ## Logs - Show manager service logs
	@docker-compose logs -f manager

logs-pki: ## Logs - Show PKI server logs
	@docker-compose logs -f pki-server

logs-ssh-ca: ## Logs - Show SSH CA logs
	@docker-compose logs -f ssh-ca

logs-aaa: ## Logs - Show AAA monitor logs
	@docker-compose logs -f aaa-monitor

logs-worker: ## Logs - Show S3 worker logs
	@docker-compose logs -f worker-s3

logs-scanner: ## Logs - Show scanner worker logs
	@docker-compose logs -f worker-scanner

logs-webui: ## Logs - Show WebUI logs
	@docker-compose logs -f webui

logs-edr: ## Logs - Show EDR agent logs
	@docker-compose logs -f edr-agent

logs-db: ## Logs - Show database logs
	@docker-compose logs -f postgres redis

# Cleanup Commands
clean: ## Clean - Clean build artifacts and caches
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	@rm -rf htmlcov/ coverage.xml .coverage

clean-docker: ## Clean - Clean Docker resources
	@$(MAKE) docker-clean

clean-all: ## Clean - Clean everything (build artifacts, Docker, etc.)
	@$(MAKE) clean
	@$(MAKE) clean-docker

# Security Commands
security-scan: ## Security - Run security scans
	@echo "$(BLUE)Running security scans...$(RESET)"
	@safety check --json 2>/dev/null || pip install safety && safety check --json
	@bandit -r services/ -ll 2>/dev/null || echo "$(YELLOW)bandit not installed, skipping$(RESET)"

audit: ## Security - Run full security audit
	@echo "$(BLUE)Running security audit...$(RESET)"
	@$(MAKE) security-scan

# Monitoring Commands
metrics: ## Monitoring - Show manager service metrics
	@echo "$(BLUE)Application metrics:$(RESET)"
	@curl -s http://localhost:5000/metrics 2>/dev/null || echo "$(YELLOW)Metrics endpoint not available$(RESET)"

monitor: ## Monitoring - Open Grafana monitoring dashboard
	@echo "$(BLUE)Opening monitoring dashboard...$(RESET)"
	@open http://localhost:3001 2>/dev/null || xdg-open http://localhost:3001 2>/dev/null || \
		echo "$(YELLOW)Visit http://localhost:3001 for Grafana$(RESET)"

# Documentation Commands
docs-serve: ## Documentation - Serve documentation locally
	@echo "$(BLUE)Serving documentation...$(RESET)"
	@cd docs && python3 -m http.server 8080

# Git Commands
git-hooks-install: ## Git - Install Git hooks
	@$(MAKE) setup-git-hooks

git-hooks-test: ## Git - Test Git hooks
	@echo "$(BLUE)Testing Git hooks...$(RESET)"
	@.git/hooks/pre-commit
	@echo "$(GREEN)Git hooks test completed$(RESET)"

# Info Commands
info: ## Info - Show project information and service URLs
	@echo "$(BLUE)Project Information:$(RESET)"
	@echo "  Name:           $(PROJECT_NAME)"
	@echo "  Version:        $(VERSION)"
	@echo "  Python Version: $(PYTHON_VERSION)"
	@echo ""
	@echo "$(BLUE)Service URLs (local dev):$(RESET)"
	@echo "  Manager:        http://localhost:5000"
	@echo "  PKI Server:     http://localhost:5001"
	@echo "  SSH CA:         http://localhost:5002"
	@echo "  AAA Monitor:    http://localhost:5003"
	@echo "  Worker Scanner: http://localhost:5004"
	@echo "  WebUI:          http://localhost:3000"
	@echo "  Prometheus:     http://localhost:9090"
	@echo "  Grafana:        http://localhost:3001"
	@echo ""
	@echo "$(BLUE)Deployment Hosts:$(RESET)"
	@echo "  Alpha (local):  https://skauswatch.localhost.local"
	@echo "  Beta:           https://skauswatch.penguintech.cloud"

env: ## Info - Show relevant environment variables
	@echo "$(BLUE)Environment Variables:$(RESET)"
	@env | grep -E "^(LICENSE_|POSTGRES_|REDIS_|SKAUSWATCH_|AWS_)" | sort
