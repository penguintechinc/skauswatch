# Project Template Makefile
# This Makefile provides common development tasks for multi-language projects

.PHONY: help setup dev test build clean lint format docker deploy

# Default target
.DEFAULT_GOAL := help

# Variables
PROJECT_NAME := project-template
VERSION := $(shell cat .version 2>/dev/null || echo "development")
DOCKER_REGISTRY := ghcr.io
DOCKER_ORG := penguintechinc
PYTHON_VERSION := 3.12
NODE_VERSION := 18

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
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Setup/ {printf "  $(YELLOW)%-30s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Development Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Development/ {printf "  $(YELLOW)%-30s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Testing Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Testing/ {printf "  $(YELLOW)%-30s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Build Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Build/ {printf "  $(YELLOW)%-30s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Docker Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Docker/ {printf "  $(YELLOW)%-30s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Kubernetes Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Kubernetes/ {printf "  $(YELLOW)%-30s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Other Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && !/Setup|Development|Testing|Build|Docker|Kubernetes/ {printf "  $(YELLOW)%-30s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Setup Commands
setup: ## Setup - Install all dependencies and initialize the project
	@echo "$(BLUE)Setting up $(PROJECT_NAME)...$(RESET)"
	@$(MAKE) setup-env
	@$(MAKE) setup-python
	@$(MAKE) setup-node
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
	@pip install -r requirements.txt
	@pip install black isort flake8 mypy pytest pytest-cov

setup-node: ## Setup - Install Node.js dependencies and tools
	@echo "$(BLUE)Setting up Node.js dependencies...$(RESET)"
	@node --version || (echo "$(RED)Node.js $(NODE_VERSION) not installed$(RESET)" && exit 1)
	@npm install
	@cd web && npm install

setup-git-hooks: ## Setup - Install Git pre-commit hooks
	@echo "$(BLUE)Installing Git hooks...$(RESET)"
	@cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@cp scripts/git-hooks/commit-msg .git/hooks/commit-msg
	@chmod +x .git/hooks/commit-msg

# Development Commands
dev: ## Development - Start development environment
	@echo "$(BLUE)Starting development environment...$(RESET)"
	@docker-compose up -d postgres redis
	@sleep 5
	@$(MAKE) dev-services

dev-services: ## Development - Start all services for development
	@echo "$(BLUE)Starting development services...$(RESET)"
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

dev-db: ## Development - Start only database services
	@docker-compose up -d postgres redis

dev-monitoring: ## Development - Start monitoring services
	@docker-compose up -d prometheus grafana

dev-full: ## Development - Start full development stack
	@docker-compose up -d

# Testing Commands
test: ## Testing - Run all tests
	@echo "$(BLUE)Running all tests...$(RESET)"
	@$(MAKE) test-python
	@$(MAKE) test-node
	@echo "$(GREEN)All tests completed!$(RESET)"

test-python: ## Testing - Run Python tests
	@echo "$(BLUE)Running Python tests...$(RESET)"
	@pytest --cov=shared --cov=apps --cov-report=xml:coverage-python.xml --cov-report=html:htmlcov-python

test-node: ## Testing - Run Node.js tests
	@echo "$(BLUE)Running Node.js tests...$(RESET)"
	@npm test
	@cd web && npm test

test-integration: ## Testing - Run integration tests
	@echo "$(BLUE)Running integration tests...$(RESET)"
	@docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit
	@docker-compose -f docker-compose.test.yml down

test-coverage: ## Testing - Generate coverage reports
	@$(MAKE) test
	@echo "$(GREEN)Coverage reports generated:$(RESET)"
	@echo "  Python: coverage-python.xml, htmlcov-python/"
	@echo "  Node.js: coverage/"

# Alpha/Beta Test Suite
test-alpha: ## Testing - Run all alpha tests (local Docker E2E)
	@echo "$(BLUE)Running alpha test suite...$(RESET)"
	@./tests/alpha/run-all.sh

test-alpha-build: ## Testing - Run alpha build verification test
	@./tests/alpha/01-build-test.sh

test-alpha-runtime: ## Testing - Run alpha runtime verification test
	@./tests/alpha/02-runtime-test.sh

test-alpha-mock: ## Testing - Run alpha mock data integration test
	@./tests/alpha/03-mock-data-test.sh

test-alpha-pages: ## Testing - Run alpha page load test
	@./tests/alpha/04-page-load-test.sh

test-alpha-api: ## Testing - Run alpha API test
	@./tests/alpha/05-api-test.sh

test-alpha-cleanup: ## Testing - Clean up alpha test environment
	@./tests/alpha/cleanup.sh

test-beta: ## Testing - Run all beta tests (K8s E2E)
	@echo "$(BLUE)Running beta test suite...$(RESET)"
	@./tests/beta/run-all.sh

test-beta-kustomize: ## Testing - Run beta Kustomize deployment test
	@./tests/beta/01-kustomize-deploy-test.sh

test-beta-kubectl: ## Testing - Run beta kubectl deployment test
	@./tests/beta/02-kubectl-deploy-test.sh

test-beta-helm: ## Testing - Run beta Helm deployment test
	@./tests/beta/03-helm-deploy-test.sh

test-beta-runtime: ## Testing - Run beta K8s runtime test
	@./tests/beta/04-k8s-runtime-test.sh

test-beta-api: ## Testing - Run beta K8s API test
	@./tests/beta/05-k8s-api-test.sh

test-beta-pages: ## Testing - Run beta K8s page load test
	@./tests/beta/06-k8s-page-load-test.sh

test-beta-cleanup: ## Testing - Clean up beta test environment
	@./tests/beta/cleanup.sh

mock-data: ## Testing - Populate mock data (3-4 items per feature)
	@echo "$(BLUE)Populating mock data...$(RESET)"
	@./tests/mock-data/populate.sh

# Build Commands
build: ## Build - Build all applications
	@echo "$(BLUE)Building all applications...$(RESET)"
	@$(MAKE) build-python
	@$(MAKE) build-node
	@echo "$(GREEN)All builds completed!$(RESET)"

build-python: ## Build - Build Python applications
	@echo "$(BLUE)Building Python applications...$(RESET)"
	@python -m py_compile apps/web/app.py

build-node: ## Build - Build Node.js applications
	@echo "$(BLUE)Building Node.js applications...$(RESET)"
	@npm run build
	@cd web && npm run build

build-production: ## Build - Build for production with optimizations
	@echo "$(BLUE)Building for production...$(RESET)"
	@cd web && npm run build

# Docker Commands
docker-build: ## Docker - Build all Docker images
	@echo "$(BLUE)Building Docker images...$(RESET)"
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-flask-backend:$(VERSION) -f services/flask-backend/Dockerfile .
	@docker build -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-webui:$(VERSION) -f services/webui/Dockerfile .

docker-push: ## Docker - Push Docker images to registry
	@echo "$(BLUE)Pushing Docker images...$(RESET)"
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-flask-backend:$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(PROJECT_NAME)-webui:$(VERSION)

docker-run: ## Docker - Run application with Docker Compose
	@docker-compose up --build

docker-clean: ## Docker - Clean up Docker resources
	@echo "$(BLUE)Cleaning up Docker resources...$(RESET)"
	@docker-compose down -v
	@docker system prune -f

# Kubernetes Configuration Variables
K8S_CONTEXT ?= docker-desktop
K8S_NAMESPACE_DEV := darwin-dev
K8S_NAMESPACE_STAGING := darwin-staging
K8S_NAMESPACE_PROD := darwin-prod
HELM_RELEASE_FLASK := darwin-flask-backend
HELM_RELEASE_WEBUI := darwin-webui
HELM_RELEASE_POSTGRES := darwin-postgresql
HELM_RELEASE_REDIS := darwin-redis

# Kubernetes Deployment Commands
.PHONY: k8s-namespace-create k8s-deploy-dev k8s-deploy-staging k8s-deploy-prod \
	helm-install-dev helm-install-staging helm-install-prod \
	helm-uninstall-dev helm-uninstall-staging helm-uninstall-prod \
	k8s-status-dev k8s-status-staging k8s-status-prod \
	k8s-health-dev k8s-health-staging k8s-health-prod \
	k8s-logs-flask-dev k8s-logs-webui-dev k8s-logs-postgres-dev k8s-logs-redis-dev \
	k8s-port-forward-flask-dev k8s-port-forward-webui-dev k8s-port-forward-postgres-dev k8s-port-forward-redis-dev \
	k8s-rollback-flask-dev helm-rollback-dev \
	k8s-apply-netpol-dev k8s-apply-netpol-prod \
	k8s-clean-dev k8s-clean-staging k8s-clean-prod

# Beta Deployment
deploy-beta: ## Kubernetes - Deploy to beta environment (registry + K8s)
	@echo "$(BLUE)Deploying to beta environment...$(RESET)"
	@./scripts/deploy-to-beta.sh
	@echo "$(GREEN)Beta deployment complete!$(RESET)"

# Namespace Management
k8s-namespace-create: ## Kubernetes - Create all Kubernetes namespaces
	@echo "$(BLUE)Creating Kubernetes namespaces...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) create namespace $(K8S_NAMESPACE_DEV) --dry-run=client -o yaml | kubectl apply -f -
	@kubectl --context=$(K8S_CONTEXT) create namespace $(K8S_NAMESPACE_STAGING) --dry-run=client -o yaml | kubectl apply -f -
	@kubectl --context=$(K8S_CONTEXT) create namespace $(K8S_NAMESPACE_PROD) --dry-run=client -o yaml | kubectl apply -f -
	@echo "$(GREEN)Namespaces created successfully$(RESET)"

# Kustomize Deployments
k8s-deploy-dev: ## Kubernetes - Deploy to development using Kustomize
	@echo "$(BLUE)Deploying to development namespace...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) apply -k infrastructure/kubernetes/overlays/dev
	@echo "$(GREEN)Development deployment complete$(RESET)"

k8s-deploy-staging: ## Kubernetes - Deploy to staging using Kustomize
	@echo "$(BLUE)Deploying to staging namespace...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) apply -k infrastructure/kubernetes/overlays/staging
	@echo "$(GREEN)Staging deployment complete$(RESET)"

k8s-deploy-prod: ## Kubernetes - Deploy to production using Kustomize (requires confirmation)
	@echo "$(RED)WARNING: Deploying to PRODUCTION environment$(RESET)"
	@read -p "Type 'deploy-production' to confirm: " confirm && [ "$$confirm" = "deploy-production" ]
	@echo "$(BLUE)Deploying to production namespace...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) apply -k infrastructure/kubernetes/overlays/prod
	@echo "$(GREEN)Production deployment complete$(RESET)"

# Helm Deployments
helm-install-dev: ## Kubernetes - Install all services to dev using Helm
	@echo "$(BLUE)Installing services to development namespace using Helm...$(RESET)"
	@echo "$(YELLOW)Installing PostgreSQL...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_POSTGRES) \
		infrastructure/kubernetes/helm/postgresql \
		--namespace $(K8S_NAMESPACE_DEV) \
		--values infrastructure/kubernetes/helm/postgresql/values-dev.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing Redis...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_REDIS) \
		infrastructure/kubernetes/helm/redis \
		--namespace $(K8S_NAMESPACE_DEV) \
		--values infrastructure/kubernetes/helm/redis/values-dev.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing Flask Backend...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_FLASK) \
		infrastructure/kubernetes/helm/flask-backend \
		--namespace $(K8S_NAMESPACE_DEV) \
		--values infrastructure/kubernetes/helm/flask-backend/values-dev.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing WebUI...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_WEBUI) \
		infrastructure/kubernetes/helm/webui \
		--namespace $(K8S_NAMESPACE_DEV) \
		--values infrastructure/kubernetes/helm/webui/values-dev.yaml \
		--wait --timeout 5m
	@echo "$(GREEN)All services installed successfully$(RESET)"

helm-install-staging: ## Kubernetes - Install all services to staging using Helm
	@echo "$(BLUE)Installing services to staging namespace using Helm...$(RESET)"
	@echo "$(YELLOW)Installing PostgreSQL...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_POSTGRES) \
		infrastructure/kubernetes/helm/postgresql \
		--namespace $(K8S_NAMESPACE_STAGING) \
		--values infrastructure/kubernetes/helm/postgresql/values-staging.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing Redis...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_REDIS) \
		infrastructure/kubernetes/helm/redis \
		--namespace $(K8S_NAMESPACE_STAGING) \
		--values infrastructure/kubernetes/helm/redis/values-staging.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing Flask Backend...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_FLASK) \
		infrastructure/kubernetes/helm/flask-backend \
		--namespace $(K8S_NAMESPACE_STAGING) \
		--values infrastructure/kubernetes/helm/flask-backend/values-staging.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing WebUI...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_WEBUI) \
		infrastructure/kubernetes/helm/webui \
		--namespace $(K8S_NAMESPACE_STAGING) \
		--values infrastructure/kubernetes/helm/webui/values-staging.yaml \
		--wait --timeout 5m
	@echo "$(GREEN)All services installed successfully$(RESET)"

helm-install-prod: ## Kubernetes - Install all services to production using Helm (requires confirmation)
	@echo "$(RED)WARNING: Installing services to PRODUCTION environment$(RESET)"
	@read -p "Type 'deploy-production' to confirm: " confirm && [ "$$confirm" = "deploy-production" ]
	@echo "$(BLUE)Installing services to production namespace using Helm...$(RESET)"
	@echo "$(YELLOW)Installing PostgreSQL...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_POSTGRES) \
		infrastructure/kubernetes/helm/postgresql \
		--namespace $(K8S_NAMESPACE_PROD) \
		--values infrastructure/kubernetes/helm/postgresql/values-prod.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing Redis...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_REDIS) \
		infrastructure/kubernetes/helm/redis \
		--namespace $(K8S_NAMESPACE_PROD) \
		--values infrastructure/kubernetes/helm/redis/values-prod.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing Flask Backend...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_FLASK) \
		infrastructure/kubernetes/helm/flask-backend \
		--namespace $(K8S_NAMESPACE_PROD) \
		--values infrastructure/kubernetes/helm/flask-backend/values-prod.yaml \
		--wait --timeout 5m
	@echo "$(YELLOW)Installing WebUI...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) install $(HELM_RELEASE_WEBUI) \
		infrastructure/kubernetes/helm/webui \
		--namespace $(K8S_NAMESPACE_PROD) \
		--values infrastructure/kubernetes/helm/webui/values-prod.yaml \
		--wait --timeout 5m
	@echo "$(GREEN)All services installed successfully$(RESET)"

# Helm Uninstall
helm-uninstall-dev: ## Kubernetes - Uninstall all Helm releases from dev
	@echo "$(BLUE)Uninstalling services from development namespace...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_WEBUI) --namespace $(K8S_NAMESPACE_DEV) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_FLASK) --namespace $(K8S_NAMESPACE_DEV) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_REDIS) --namespace $(K8S_NAMESPACE_DEV) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_POSTGRES) --namespace $(K8S_NAMESPACE_DEV) || true
	@echo "$(GREEN)Development services uninstalled$(RESET)"

helm-uninstall-staging: ## Kubernetes - Uninstall all Helm releases from staging
	@echo "$(BLUE)Uninstalling services from staging namespace...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_WEBUI) --namespace $(K8S_NAMESPACE_STAGING) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_FLASK) --namespace $(K8S_NAMESPACE_STAGING) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_REDIS) --namespace $(K8S_NAMESPACE_STAGING) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_POSTGRES) --namespace $(K8S_NAMESPACE_STAGING) || true
	@echo "$(GREEN)Staging services uninstalled$(RESET)"

helm-uninstall-prod: ## Kubernetes - Uninstall all Helm releases from production (requires confirmation)
	@echo "$(RED)WARNING: Uninstalling services from PRODUCTION environment$(RESET)"
	@read -p "Type 'delete-production' to confirm: " confirm && [ "$$confirm" = "delete-production" ]
	@echo "$(BLUE)Uninstalling services from production namespace...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_WEBUI) --namespace $(K8S_NAMESPACE_PROD) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_FLASK) --namespace $(K8S_NAMESPACE_PROD) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_REDIS) --namespace $(K8S_NAMESPACE_PROD) || true
	@helm --kube-context=$(K8S_CONTEXT) uninstall $(HELM_RELEASE_POSTGRES) --namespace $(K8S_NAMESPACE_PROD) || true
	@echo "$(GREEN)Production services uninstalled$(RESET)"

# Status Commands
k8s-status-dev: ## Kubernetes - Show status of dev deployments
	@echo "$(BLUE)Development namespace status:$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) get all -n $(K8S_NAMESPACE_DEV)

k8s-status-staging: ## Kubernetes - Show status of staging deployments
	@echo "$(BLUE)Staging namespace status:$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) get all -n $(K8S_NAMESPACE_STAGING)

k8s-status-prod: ## Kubernetes - Show status of production deployments
	@echo "$(BLUE)Production namespace status:$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) get all -n $(K8S_NAMESPACE_PROD)

# Health Check Commands
k8s-health-dev: ## Kubernetes - Check health of dev deployments
	@echo "$(BLUE)Checking development deployment health...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) rollout status deployment/flask-backend -n $(K8S_NAMESPACE_DEV) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status deployment/webui -n $(K8S_NAMESPACE_DEV) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status statefulset/postgresql -n $(K8S_NAMESPACE_DEV) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status statefulset/redis -n $(K8S_NAMESPACE_DEV) --timeout=60s
	@echo "$(GREEN)All deployments are healthy$(RESET)"

k8s-health-staging: ## Kubernetes - Check health of staging deployments
	@echo "$(BLUE)Checking staging deployment health...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) rollout status deployment/flask-backend -n $(K8S_NAMESPACE_STAGING) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status deployment/webui -n $(K8S_NAMESPACE_STAGING) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status statefulset/postgresql -n $(K8S_NAMESPACE_STAGING) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status statefulset/redis -n $(K8S_NAMESPACE_STAGING) --timeout=60s
	@echo "$(GREEN)All deployments are healthy$(RESET)"

k8s-health-prod: ## Kubernetes - Check health of production deployments
	@echo "$(BLUE)Checking production deployment health...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) rollout status deployment/flask-backend -n $(K8S_NAMESPACE_PROD) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status deployment/webui -n $(K8S_NAMESPACE_PROD) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status statefulset/postgresql -n $(K8S_NAMESPACE_PROD) --timeout=60s
	@kubectl --context=$(K8S_CONTEXT) rollout status statefulset/redis -n $(K8S_NAMESPACE_PROD) --timeout=60s
	@echo "$(GREEN)All deployments are healthy$(RESET)"

# Logs Commands
k8s-logs-flask-dev: ## Kubernetes - Show Flask backend logs from dev
	@echo "$(BLUE)Flask backend logs (development):$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) logs -f -l app=flask-backend -n $(K8S_NAMESPACE_DEV)

k8s-logs-webui-dev: ## Kubernetes - Show WebUI logs from dev
	@echo "$(BLUE)WebUI logs (development):$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) logs -f -l app=webui -n $(K8S_NAMESPACE_DEV)

k8s-logs-postgres-dev: ## Kubernetes - Show PostgreSQL logs from dev
	@echo "$(BLUE)PostgreSQL logs (development):$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) logs -f -l app=postgresql -n $(K8S_NAMESPACE_DEV)

k8s-logs-redis-dev: ## Kubernetes - Show Redis logs from dev
	@echo "$(BLUE)Redis logs (development):$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) logs -f -l app=redis -n $(K8S_NAMESPACE_DEV)

# Port Forwarding Commands
k8s-port-forward-flask-dev: ## Kubernetes - Port forward Flask backend from dev (5000)
	@echo "$(BLUE)Port forwarding Flask backend (5000)...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) port-forward -n $(K8S_NAMESPACE_DEV) svc/flask-backend 5000:5000

k8s-port-forward-webui-dev: ## Kubernetes - Port forward WebUI from dev (3000)
	@echo "$(BLUE)Port forwarding WebUI (3000)...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) port-forward -n $(K8S_NAMESPACE_DEV) svc/webui 3000:3000

k8s-port-forward-postgres-dev: ## Kubernetes - Port forward PostgreSQL from dev (5432)
	@echo "$(BLUE)Port forwarding PostgreSQL (5432)...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) port-forward -n $(K8S_NAMESPACE_DEV) svc/postgresql 5432:5432

k8s-port-forward-redis-dev: ## Kubernetes - Port forward Redis from dev (6379)
	@echo "$(BLUE)Port forwarding Redis (6379)...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) port-forward -n $(K8S_NAMESPACE_DEV) svc/redis 6379:6379

# Rollback Commands
k8s-rollback-flask-dev: ## Kubernetes - Rollback Flask backend deployment in dev
	@echo "$(BLUE)Rolling back Flask backend deployment...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) rollout undo deployment/flask-backend -n $(K8S_NAMESPACE_DEV)
	@kubectl --context=$(K8S_CONTEXT) rollout status deployment/flask-backend -n $(K8S_NAMESPACE_DEV)
	@echo "$(GREEN)Rollback complete$(RESET)"

helm-rollback-dev: ## Kubernetes - Rollback all Helm releases in dev
	@echo "$(BLUE)Rolling back Helm releases in development...$(RESET)"
	@helm --kube-context=$(K8S_CONTEXT) rollback $(HELM_RELEASE_WEBUI) --namespace $(K8S_NAMESPACE_DEV) || true
	@helm --kube-context=$(K8S_CONTEXT) rollback $(HELM_RELEASE_FLASK) --namespace $(K8S_NAMESPACE_DEV) || true
	@helm --kube-context=$(K8S_CONTEXT) rollback $(HELM_RELEASE_REDIS) --namespace $(K8S_NAMESPACE_DEV) || true
	@helm --kube-context=$(K8S_CONTEXT) rollback $(HELM_RELEASE_POSTGRES) --namespace $(K8S_NAMESPACE_DEV) || true
	@echo "$(GREEN)Rollback complete$(RESET)"

# Network Policies
k8s-apply-netpol-dev: ## Kubernetes - Apply network policies to dev
	@echo "$(BLUE)Applying network policies to development...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) apply -f infrastructure/kubernetes/base/network-policies/ -n $(K8S_NAMESPACE_DEV)
	@echo "$(GREEN)Network policies applied$(RESET)"

k8s-apply-netpol-prod: ## Kubernetes - Apply network policies to production
	@echo "$(BLUE)Applying network policies to production...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) apply -f infrastructure/kubernetes/base/network-policies/ -n $(K8S_NAMESPACE_PROD)
	@echo "$(GREEN)Network policies applied$(RESET)"

# Cleanup Commands
k8s-clean-dev: ## Kubernetes - Clean up dev namespace
	@echo "$(BLUE)Cleaning up development namespace...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) delete all --all -n $(K8S_NAMESPACE_DEV)
	@echo "$(GREEN)Development namespace cleaned$(RESET)"

k8s-clean-staging: ## Kubernetes - Clean up staging namespace
	@echo "$(BLUE)Cleaning up staging namespace...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) delete all --all -n $(K8S_NAMESPACE_STAGING)
	@echo "$(GREEN)Staging namespace cleaned$(RESET)"

k8s-clean-prod: ## Kubernetes - Clean up production namespace (requires confirmation)
	@echo "$(RED)WARNING: Cleaning up PRODUCTION namespace$(RESET)"
	@read -p "Type 'delete-production' to confirm: " confirm && [ "$$confirm" = "delete-production" ]
	@echo "$(BLUE)Cleaning up production namespace...$(RESET)"
	@kubectl --context=$(K8S_CONTEXT) delete all --all -n $(K8S_NAMESPACE_PROD)
	@echo "$(GREEN)Production namespace cleaned$(RESET)"

# Code Quality Commands
lint: ## Code Quality - Run linting for all languages
	@echo "$(BLUE)Running linting...$(RESET)"
	@$(MAKE) lint-python
	@$(MAKE) lint-node

lint-python: ## Code Quality - Run Python linting
	@echo "$(BLUE)Linting Python code...$(RESET)"
	@flake8 .
	@mypy . --ignore-missing-imports

lint-node: ## Code Quality - Run Node.js linting
	@echo "$(BLUE)Linting Node.js code...$(RESET)"
	@npm run lint
	@cd web && npm run lint

format: ## Code Quality - Format code for all languages
	@echo "$(BLUE)Formatting code...$(RESET)"
	@$(MAKE) format-python
	@$(MAKE) format-node

format-python: ## Code Quality - Format Python code
	@echo "$(BLUE)Formatting Python code...$(RESET)"
	@black .
	@isort .

format-node: ## Code Quality - Format Node.js code
	@echo "$(BLUE)Formatting Node.js code...$(RESET)"
	@npm run format
	@cd web && npm run format

# Database Commands
db-migrate: ## Database - Run database migrations
	@echo "$(BLUE)Running database migrations...$(RESET)"
	@echo "Database migrations are handled by PyDAL in Flask backend"

db-seed: ## Database - Seed database with test data
	@echo "$(BLUE)Seeding database...$(RESET)"
	@echo "Database seeding is handled by Flask backend initialization"

db-reset: ## Database - Reset database (WARNING: destroys data)
	@echo "$(RED)WARNING: This will destroy all data!$(RESET)"
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ]
	@docker-compose down -v
	@docker-compose up -d postgres redis
	@sleep 5
	@$(MAKE) db-migrate
	@$(MAKE) db-seed

db-backup: ## Database - Create database backup
	@echo "$(BLUE)Creating database backup...$(RESET)"
	@mkdir -p backups
	@docker-compose exec postgres pg_dump -U postgres project_template > backups/backup-$(shell date +%Y%m%d-%H%M%S).sql

db-restore: ## Database - Restore database from backup (requires BACKUP_FILE)
	@echo "$(BLUE)Restoring database from $(BACKUP_FILE)...$(RESET)"
	@docker-compose exec -T postgres psql -U postgres project_template < $(BACKUP_FILE)

# License Commands
license-validate: ## License - Validate license configuration
	@echo "$(BLUE)Validating license configuration...$(RESET)"
	@echo "License validation is configured via environment variables"

license-test: ## License - Test license server integration
	@echo "$(BLUE)Testing license server integration...$(RESET)"
	@curl -f $${LICENSE_SERVER_URL:-https://license.penguintech.io}/api/v2/validate \
		-H "Authorization: Bearer $${LICENSE_KEY}" \
		-H "Content-Type: application/json" \
		-d '{"product": "'$${PRODUCT_NAME:-project-template}'"}'

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
deploy-staging: ## Deploy - Deploy to staging environment
	@echo "$(BLUE)Deploying to staging...$(RESET)"
	@$(MAKE) docker-build
	@$(MAKE) docker-push
	# Add staging deployment commands here

deploy-production: ## Deploy - Deploy to production environment
	@echo "$(BLUE)Deploying to production...$(RESET)"
	@$(MAKE) docker-build
	@$(MAKE) docker-push
	# Add production deployment commands here

# Health Check Commands
health: ## Health - Check service health
	@echo "$(BLUE)Checking service health...$(RESET)"
	@curl -f http://localhost:8080/health || echo "$(RED)API health check failed$(RESET)"
	@curl -f http://localhost:8000/health || echo "$(RED)Python web health check failed$(RESET)"
	@curl -f http://localhost:3000/health || echo "$(RED)Node web health check failed$(RESET)"

logs: ## Logs - Show service logs
	@docker-compose logs -f

logs-api: ## Logs - Show API logs
	@docker-compose logs -f api

logs-web: ## Logs - Show web logs
	@docker-compose logs -f web-python web-node

logs-db: ## Logs - Show database logs
	@docker-compose logs -f postgres redis

# Cleanup Commands
clean: ## Clean - Clean build artifacts and caches
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	@rm -rf bin/
	@rm -rf dist/
	@rm -rf node_modules/
	@rm -rf web/node_modules/
	@rm -rf web/dist/
	@rm -rf __pycache__/
	@rm -rf .pytest_cache/
	@rm -rf htmlcov-python/
	@rm -rf coverage-*.out
	@rm -rf coverage-*.xml

clean-docker: ## Clean - Clean Docker resources
	@$(MAKE) docker-clean

clean-all: ## Clean - Clean everything (build artifacts, Docker, etc.)
	@$(MAKE) clean
	@$(MAKE) clean-docker

# Security Commands
security-scan: ## Security - Run security scans
	@echo "$(BLUE)Running security scans...$(RESET)"
	@safety check --json

audit: ## Security - Run security audit
	@echo "$(BLUE)Running security audit...$(RESET)"
	@npm audit
	@cd web && npm audit
	@$(MAKE) security-scan

# Monitoring Commands
metrics: ## Monitoring - Show application metrics
	@echo "$(BLUE)Application metrics:$(RESET)"
	@curl -s http://localhost:8080/metrics | grep -E '^# (HELP|TYPE)' | head -20

monitor: ## Monitoring - Open monitoring dashboard
	@echo "$(BLUE)Opening monitoring dashboard...$(RESET)"
	@open http://localhost:3001  # Grafana

# Documentation Commands
docs-serve: ## Documentation - Serve documentation locally
	@echo "$(BLUE)Serving documentation...$(RESET)"
	@cd docs && python -m http.server 8080

docs-build: ## Documentation - Build documentation
	@echo "$(BLUE)Building documentation...$(RESET)"
	@echo "Documentation build not implemented yet"

# Git Commands
git-hooks-install: ## Git - Install Git hooks
	@$(MAKE) setup-git-hooks

git-hooks-test: ## Git - Test Git hooks
	@echo "$(BLUE)Testing Git hooks...$(RESET)"
	@.git/hooks/pre-commit
	@echo "$(GREEN)Git hooks test completed$(RESET)"

# Info Commands
info: ## Info - Show project information
	@echo "$(BLUE)Project Information:$(RESET)"
	@echo "Name: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Python Version: $(PYTHON_VERSION)"
	@echo "Node Version: $(NODE_VERSION)"
	@echo ""
	@echo "$(BLUE)Service URLs:$(RESET)"
	@echo "Flask Backend: http://localhost:5000"
	@echo "WebUI: http://localhost:3000"
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3001"

env: ## Info - Show environment variables
	@echo "$(BLUE)Environment Variables:$(RESET)"
	@env | grep -E "^(LICENSE_|POSTGRES_|REDIS_|NODE_|GIN_|PY4WEB_)" | sort