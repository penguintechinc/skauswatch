#!/bin/bash

# SkausWatch Development Setup Script
# This script sets up the local development environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env.local"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"

# Functions
print_header() {
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}  SkausWatch Development Environment Setup${NC}"
    echo -e "${BLUE}===========================================${NC}\n"
}

print_section() {
    echo -e "\n${YELLOW}>>> $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

check_requirements() {
    print_section "Checking Requirements"
    
    local missing_deps=()
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    else
        print_success "Docker is installed"
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        missing_deps+=("docker-compose")
    else
        print_success "Docker Compose is installed"
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    else
        print_success "Docker is running"
    fi
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        missing_deps+=("node")
    else
        print_success "Node.js is installed ($(node --version))"
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        missing_deps+=("npm")
    else
        print_success "npm is installed ($(npm --version))"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        echo -e "\nPlease install the missing dependencies and try again."
        exit 1
    fi
}

setup_environment() {
    print_section "Setting up Environment"
    
    # Copy environment file if it doesn't exist
    if [[ ! -f "$ENV_FILE" ]]; then
        if [[ -f "${PROJECT_ROOT}/.env.local.example" ]]; then
            cp "${PROJECT_ROOT}/.env.local.example" "$ENV_FILE"
            print_success "Created .env.local from template"
        else
            print_warning ".env.local.example not found, using .env.example as fallback"
            if [[ -f "${PROJECT_ROOT}/.env.example" ]]; then
                cp "${PROJECT_ROOT}/.env.example" "$ENV_FILE"
                print_success "Created .env.local from .env.example"
            else
                print_error "No environment template found"
                exit 1
            fi
        fi
    else
        print_success ".env.local already exists"
    fi
}

create_directories() {
    print_section "Creating Required Directories"
    
    local directories=(
        "data/manager/dev"
        "data/pki/dev"
        "data/ssh-ca/dev"
        "data/aaa-monitor/dev"
        "logs/manager"
        "logs/pki-server"
        "logs/ssh-ca"
        "logs/aaa-monitor"
        "logs/nginx"
        "config/postgres/dev"
        "config/redis"
        "config/rabbitmq"
        "config/nginx/dev-conf.d"
        "config/prometheus"
        "config/grafana/dev/provisioning/datasources"
        "config/grafana/dev/provisioning/dashboards"
        "config/grafana/dashboards"
        "config/ssl/dev"
        "config/manager"
        "config/pki-server"
        "config/ssh-ca"
        "config/aaa-monitor"
        "secrets/dev"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "${PROJECT_ROOT}/${dir}"
        print_success "Created directory: ${dir}"
    done
}

generate_ssl_certificates() {
    print_section "Generating SSL Certificates for Development"
    
    local ssl_dir="${PROJECT_ROOT}/config/ssl/dev"
    
    # Check if certificates already exist
    if [[ -f "${ssl_dir}/cert.pem" && -f "${ssl_dir}/key.pem" ]]; then
        print_success "SSL certificates already exist"
        return
    fi
    
    # Generate CA private key
    openssl genrsa -out "${ssl_dir}/ca-key.pem" 4096
    
    # Generate CA certificate
    openssl req -new -x509 -sha256 -days 365 -key "${ssl_dir}/ca-key.pem" -out "${ssl_dir}/ca.pem" \
        -subj "/C=US/ST=Dev/L=Dev/O=SkausWatch Dev/OU=IT/CN=SkausWatch Dev CA"
    
    # Generate server private key
    openssl genrsa -out "${ssl_dir}/key.pem" 4096
    
    # Generate server certificate signing request
    openssl req -new -sha256 -key "${ssl_dir}/key.pem" -out "${ssl_dir}/server.csr" \
        -subj "/C=US/ST=Dev/L=Dev/O=SkausWatch Dev/OU=IT/CN=localhost"
    
    # Create extensions file for SAN
    cat > "${ssl_dir}/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = skauswatch.local
DNS.4 = *.skauswatch.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    
    # Generate server certificate
    openssl x509 -req -sha256 -days 365 -in "${ssl_dir}/server.csr" -CA "${ssl_dir}/ca.pem" \
        -CAkey "${ssl_dir}/ca-key.pem" -out "${ssl_dir}/cert.pem" -extensions v3_req -extfile "${ssl_dir}/server.ext"
    
    # Set appropriate permissions
    chmod 600 "${ssl_dir}"/*.pem "${ssl_dir}"/*.key 2>/dev/null || true
    chmod 644 "${ssl_dir}/cert.pem" "${ssl_dir}/ca.pem" 2>/dev/null || true
    
    # Clean up
    rm -f "${ssl_dir}/server.csr" "${ssl_dir}/server.ext"
    
    print_success "Generated SSL certificates for development"
}

create_config_files() {
    print_section "Creating Configuration Files"
    
    # Redis development configuration
    cat > "${PROJECT_ROOT}/config/redis/dev.conf" << 'EOF'
# Redis configuration for development
save 60 1000
stop-writes-on-bgsave-error no
rdbcompression yes
rdbchecksum yes
dir /data
appendonly yes
appendfsync everysec
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
maxmemory 256mb
maxmemory-policy allkeys-lru
EOF
    
    # RabbitMQ enabled plugins for development
    cat > "${PROJECT_ROOT}/config/rabbitmq/dev_enabled_plugins" << 'EOF'
[rabbitmq_management,rabbitmq_prometheus,rabbitmq_web_dispatch].
EOF
    
    # Prometheus development configuration
    cat > "${PROJECT_ROOT}/config/prometheus/dev.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'skauswatch-manager'
    static_configs:
      - targets: ['manager:8080']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'skauswatch-pki-server'
    static_configs:
      - targets: ['pki-server:8081']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'skauswatch-ssh-ca'
    static_configs:
      - targets: ['ssh-ca:8082']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'skauswatch-aaa-monitor'
    static_configs:
      - targets: ['aaa-monitor:8083']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']
    scrape_interval: 60s

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
    scrape_interval: 60s

  - job_name: 'rabbitmq'
    static_configs:
      - targets: ['rabbitmq:15692']
    scrape_interval: 60s
EOF
    
    # Grafana datasource configuration
    mkdir -p "${PROJECT_ROOT}/config/grafana/dev/provisioning/datasources"
    cat > "${PROJECT_ROOT}/config/grafana/dev/provisioning/datasources/prometheus.yml" << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF
    
    # Grafana dashboard provisioning
    cat > "${PROJECT_ROOT}/config/grafana/dev/provisioning/dashboards/default.yml" << 'EOF'
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    folderUid: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF
    
    # Basic Nginx configuration
    cat > "${PROJECT_ROOT}/config/nginx/dev.conf" << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream backend {
        server web-portal:3000;
    }
    
    upstream api {
        server manager:8080;
    }
    
    server {
        listen 80;
        server_name localhost;
        
        location /nginx-health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
        
        location /api/ {
            proxy_pass http://api/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        location / {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF
    
    print_success "Created configuration files"
}

pull_docker_images() {
    print_section "Pulling Docker Images"
    
    # Pull base images that are always needed
    local base_images=(
        "postgres:15-alpine"
        "redis:7-alpine"
        "rabbitmq:3-management-alpine"
        "minio/minio:latest"
        "docker.elastic.co/elasticsearch/elasticsearch:8.11.0"
        "prom/prometheus:latest"
        "grafana/grafana:latest"
        "nginx:alpine"
        "adminer:latest"
        "rediscommander/redis-commander:latest"
        "mailhog/mailhog:latest"
    )
    
    for image in "${base_images[@]}"; do
        print_success "Pulling ${image}..."
        docker pull "$image" || print_warning "Failed to pull ${image}"
    done
}

create_docker_network() {
    print_section "Setting up Docker Network"
    
    # Remove existing network if it exists
    docker network rm skauswatch-net 2>/dev/null || true
    
    # Create network
    docker network create --driver bridge --subnet=172.20.0.0/16 skauswatch-net || true
    print_success "Created Docker network: skauswatch-net"
}

install_npm_dependencies() {
    print_section "Installing NPM Dependencies"
    
    cd "$PROJECT_ROOT"
    
    if [[ -f "package.json" ]]; then
        npm install
        print_success "Installed NPM dependencies"
    else
        print_warning "No package.json found, skipping NPM install"
    fi
}

create_initial_data() {
    print_section "Creating Initial Development Data"
    
    # Create a simple SQL script for initial data
    cat > "${PROJECT_ROOT}/config/postgres/dev/01_init_dev_data.sql" << 'EOF'
-- Development initialization script
-- This will be executed when the PostgreSQL container starts

-- Create development database extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Insert initial development data (if tables exist)
-- Note: This script runs before application migrations
-- so we use DO blocks to check for table existence

DO $$
BEGIN
    -- Example: Insert development user if users table exists
    IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users') THEN
        INSERT INTO users (id, email, first_name, last_name, role, created_at)
        VALUES (
            uuid_generate_v4(),
            'admin@skauswatch.local',
            'Development',
            'Admin',
            'super-admin',
            NOW()
        ) ON CONFLICT (email) DO NOTHING;
    END IF;
END $$;
EOF
    
    print_success "Created initial development data scripts"
}

display_summary() {
    print_section "Setup Complete!"
    
    echo -e "\n${GREEN}Development environment is ready!${NC}\n"
    echo -e "Next steps:"
    echo -e "  1. Review and customize ${BLUE}.env.local${NC} if needed"
    echo -e "  2. Run ${BLUE}./scripts/dev-start.sh${NC} to start all services"
    echo -e "  3. Wait for services to be healthy (may take a few minutes)"
    echo -e "  4. Access the application at ${BLUE}http://localhost:3000${NC}"
    echo -e "\nUseful URLs:"
    echo -e "  • Web Portal:      ${BLUE}http://localhost:3000${NC}"
    echo -e "  • API Gateway:     ${BLUE}http://localhost:8080${NC}"
    echo -e "  • Grafana:         ${BLUE}http://localhost:3001${NC} (admin/admin)"
    echo -e "  • Prometheus:      ${BLUE}http://localhost:9090${NC}"
    echo -e "  • RabbitMQ Mgmt:   ${BLUE}http://localhost:15672${NC} (dev/devpassword)"
    echo -e "  • MinIO Console:   ${BLUE}http://localhost:9001${NC} (devuser/devpassword123)"
    echo -e "  • Adminer (DB):    ${BLUE}http://localhost:8084${NC}"
    echo -e "  • Redis Commander: ${BLUE}http://localhost:8085${NC}"
    echo -e "  • MailHog:         ${BLUE}http://localhost:8025${NC}"
    echo -e "\nAvailable scripts:"
    echo -e "  • ${BLUE}./scripts/dev-start.sh${NC}  - Start all services"
    echo -e "  • ${BLUE}./scripts/dev-stop.sh${NC}   - Stop all services"
    echo -e "  • ${BLUE}./scripts/dev-reset.sh${NC}  - Reset all data"
}

# Main execution
main() {
    print_header
    
    check_requirements
    setup_environment
    create_directories
    generate_ssl_certificates
    create_config_files
    create_docker_network
    pull_docker_images
    install_npm_dependencies
    create_initial_data
    
    display_summary
    
    echo -e "\n${GREEN}Setup completed successfully!${NC}\n"
}

# Run main function
main "$@"