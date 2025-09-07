#!/bin/bash

# SkausWatch Development Start Script
# This script starts all development services

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

# Functions
print_header() {
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}     SkausWatch Development Services      ${NC}"
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

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_prerequisites() {
    print_section "Checking Prerequisites"
    
    # Check if setup has been run
    if [[ ! -f "${PROJECT_ROOT}/.env.local" ]]; then
        print_error "Environment not set up. Please run ./scripts/dev-setup.sh first."
        exit 1
    fi
    
    # Check Docker
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    
    # Check for docker-compose file
    if [[ ! -f "${PROJECT_ROOT}/docker-compose.yml" ]]; then
        print_error "docker-compose.yml not found in project root."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

start_infrastructure_services() {
    print_section "Starting Infrastructure Services"
    
    cd "$PROJECT_ROOT"
    
    # Start core infrastructure services first
    local infrastructure_services=(
        "postgres"
        "redis"
        "rabbitmq"
        "minio"
        "elasticsearch"
    )
    
    print_info "Starting infrastructure services: ${infrastructure_services[*]}"
    docker-compose up -d "${infrastructure_services[@]}"
    
    print_success "Infrastructure services started"
}

wait_for_infrastructure() {
    print_section "Waiting for Infrastructure Services"
    
    local max_attempts=60
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        local ready_count=0
        
        # Check PostgreSQL
        if docker-compose exec -T postgres pg_isready -U skauswatch_dev -d skauswatch_dev &> /dev/null; then
            ((ready_count++))
        fi
        
        # Check Redis
        if docker-compose exec -T redis redis-cli ping &> /dev/null; then
            ((ready_count++))
        fi
        
        # Check RabbitMQ
        if docker-compose exec -T rabbitmq rabbitmq-diagnostics ping &> /dev/null; then
            ((ready_count++))
        fi
        
        # Check MinIO
        if curl -f http://localhost:9000/minio/health/live &> /dev/null; then
            ((ready_count++))
        fi
        
        # Check Elasticsearch
        if curl -s http://localhost:9200/_cluster/health | grep -q '"status":"green\\|yellow"'; then
            ((ready_count++))
        fi
        
        if [[ $ready_count -eq 5 ]]; then
            print_success "All infrastructure services are ready"
            break
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    if [[ $attempt -eq $max_attempts ]]; then
        print_warning "Some infrastructure services may not be fully ready"
        print_info "Continuing with service startup..."
    fi
}

start_monitoring_services() {
    print_section "Starting Monitoring Services"
    
    cd "$PROJECT_ROOT"
    
    local monitoring_services=(
        "prometheus"
        "grafana"
    )
    
    print_info "Starting monitoring services: ${monitoring_services[*]}"
    docker-compose up -d "${monitoring_services[@]}"
    
    print_success "Monitoring services started"
}

start_application_services() {
    print_section "Starting Application Services"
    
    cd "$PROJECT_ROOT"
    
    local app_services=(
        "manager"
        "pki-server"
        "ssh-ca"
        "aaa-monitor"
        "web-portal"
    )
    
    print_info "Starting application services: ${app_services[*]}"
    docker-compose up -d "${app_services[@]}"
    
    print_success "Application services started"
}

start_development_tools() {
    print_section "Starting Development Tools"
    
    cd "$PROJECT_ROOT"
    
    local dev_tools=(
        "adminer"
        "redis-commander"
        "mailhog"
    )
    
    print_info "Starting development tools: ${dev_tools[*]}"
    docker-compose up -d "${dev_tools[@]}"
    
    print_success "Development tools started"
}

start_reverse_proxy() {
    print_section "Starting Reverse Proxy"
    
    cd "$PROJECT_ROOT"
    
    print_info "Starting nginx reverse proxy"
    docker-compose up -d nginx
    
    print_success "Reverse proxy started"
}

wait_for_application_services() {
    print_section "Waiting for Application Services"
    
    local max_attempts=30
    local attempt=0
    
    local services=(
        "manager:8080"
        "pki-server:8081"
        "ssh-ca:8082"
        "aaa-monitor:8083"
        "web-portal:3000"
    )
    
    while [[ $attempt -lt $max_attempts ]]; do
        local ready_count=0
        
        for service in "${services[@]}"; do
            local name="${service%%:*}"
            local port="${service##*:}"
            
            if curl -f "http://localhost:${port}/health" &> /dev/null || \
               curl -f "http://localhost:${port}/" &> /dev/null; then
                ((ready_count++))
            fi
        done
        
        if [[ $ready_count -eq ${#services[@]} ]]; then
            print_success "All application services are ready"
            break
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    if [[ $attempt -eq $max_attempts ]]; then
        print_warning "Some application services may not be fully ready"
        print_info "Check service logs if needed: docker-compose logs <service-name>"
    fi
}

display_service_status() {
    print_section "Service Status"
    
    cd "$PROJECT_ROOT"
    docker-compose ps
}

display_urls() {
    print_section "Service URLs"
    
    echo -e "\n${GREEN}Development services are running!${NC}\n"
    echo -e "${BLUE}Application URLs:${NC}"
    echo -e "  • Web Portal:        ${GREEN}http://localhost:3000${NC}"
    echo -e "  • Manager API:       ${GREEN}http://localhost:8080${NC}"
    echo -e "  • PKI Server:        ${GREEN}http://localhost:8081${NC}"
    echo -e "  • SSH CA:            ${GREEN}http://localhost:8082${NC}"
    echo -e "  • AAA Monitor:       ${GREEN}http://localhost:8083${NC}"
    echo -e "\n${BLUE}Monitoring & Observability:${NC}"
    echo -e "  • Grafana:           ${GREEN}http://localhost:3001${NC} (admin/admin)"
    echo -e "  • Prometheus:        ${GREEN}http://localhost:9090${NC}"
    echo -e "\n${BLUE}Infrastructure Services:${NC}"
    echo -e "  • RabbitMQ Management: ${GREEN}http://localhost:15672${NC} (dev/devpassword)"
    echo -e "  • MinIO Console:     ${GREEN}http://localhost:9001${NC} (devuser/devpassword123)"
    echo -e "  • Elasticsearch:     ${GREEN}http://localhost:9200${NC}"
    echo -e "\n${BLUE}Development Tools:${NC}"
    echo -e "  • Adminer (Database): ${GREEN}http://localhost:8084${NC}"
    echo -e "  • Redis Commander:   ${GREEN}http://localhost:8085${NC}"
    echo -e "  • MailHog (Email):   ${GREEN}http://localhost:8025${NC}"
}

display_logs_info() {
    print_section "Viewing Logs"
    
    echo -e "\nTo view logs for specific services:"
    echo -e "  • All services:      ${BLUE}docker-compose logs -f${NC}"
    echo -e "  • Specific service:  ${BLUE}docker-compose logs -f <service-name>${NC}"
    echo -e "  • Application logs:  ${BLUE}docker-compose logs -f manager pki-server ssh-ca aaa-monitor${NC}"
    echo -e "  • Infrastructure:    ${BLUE}docker-compose logs -f postgres redis rabbitmq${NC}"
}

display_development_info() {
    print_section "Development Information"
    
    echo -e "\nDevelopment commands:"
    echo -e "  • Stop services:     ${BLUE}./scripts/dev-stop.sh${NC}"
    echo -e "  • Reset data:        ${BLUE}./scripts/dev-reset.sh${NC}"
    echo -e "  • Service status:    ${BLUE}docker-compose ps${NC}"
    echo -e "  • Restart service:   ${BLUE}docker-compose restart <service-name>${NC}"
    echo -e "\nDebugging:"
    echo -e "  • Manager service has Delve debugger on port 40000"
    echo -e "  • PKI Server service has Delve debugger on port 40001" 
    echo -e "  • SSH CA service has Delve debugger on port 40002"
    echo -e "  • AAA Monitor service has Delve debugger on port 40003"
    echo -e "\nHot reload is enabled for:"
    echo -e "  • Web Portal (React/Next.js)"
    echo -e "  • Go services (with proper setup)"
}

cleanup_on_exit() {
    echo -e "\n${YELLOW}Services are still running. Use ${BLUE}./scripts/dev-stop.sh${NC} ${YELLOW}to stop them.${NC}"
}

# Trap to show cleanup message
trap cleanup_on_exit EXIT

# Main execution
main() {
    print_header
    
    check_prerequisites
    start_infrastructure_services
    wait_for_infrastructure
    start_monitoring_services
    start_application_services
    start_development_tools
    start_reverse_proxy
    wait_for_application_services
    
    display_service_status
    display_urls
    display_logs_info
    display_development_info
    
    echo -e "\n${GREEN}All services started successfully!${NC}"
    echo -e "${YELLOW}Press Ctrl+C to return to shell (services will continue running)${NC}\n"
    
    # Optional: Follow logs
    read -p "Follow application logs? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd "$PROJECT_ROOT"
        docker-compose logs -f manager pki-server ssh-ca aaa-monitor web-portal
    fi
}

# Run main function
main "$@"