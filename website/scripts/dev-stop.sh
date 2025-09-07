#!/bin/bash

# SkausWatch Development Stop Script
# This script stops all development services

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
    echo -e "${BLUE}     SkausWatch Development Stop         ${NC}"
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

check_docker() {
    print_section "Checking Docker"
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker is not running"
        exit 1
    fi
    
    print_success "Docker is available"
}

stop_services() {
    print_section "Stopping Services"
    
    cd "$PROJECT_ROOT"
    
    # Check if docker-compose file exists
    if [[ ! -f "docker-compose.yml" ]]; then
        print_error "docker-compose.yml not found"
        exit 1
    fi
    
    # Get list of running services
    local running_services
    running_services=$(docker-compose ps --services --filter "status=running" 2>/dev/null || echo "")
    
    if [[ -z "$running_services" ]]; then
        print_info "No running services found"
        return
    fi
    
    print_info "Stopping running services: $(echo "$running_services" | tr '\n' ' ')"
    
    # Stop services gracefully
    if ! docker-compose stop; then
        print_warning "Graceful stop failed, forcing stop..."
        docker-compose kill
    fi
    
    print_success "Services stopped"
}

stop_specific_service() {
    local service_name="$1"
    
    print_section "Stopping Service: $service_name"
    
    cd "$PROJECT_ROOT"
    
    if docker-compose ps --services | grep -q "^${service_name}$"; then
        if docker-compose ps "$service_name" | grep -q "Up"; then
            docker-compose stop "$service_name"
            print_success "Stopped $service_name"
        else
            print_info "$service_name is not running"
        fi
    else
        print_error "Service $service_name not found in docker-compose.yml"
        return 1
    fi
}

remove_containers() {
    print_section "Removing Containers"
    
    cd "$PROJECT_ROOT"
    
    local containers
    containers=$(docker-compose ps -q 2>/dev/null || echo "")
    
    if [[ -z "$containers" ]]; then
        print_info "No containers to remove"
        return
    fi
    
    print_info "Removing stopped containers"
    docker-compose rm -f
    
    print_success "Containers removed"
}

display_status() {
    print_section "Service Status"
    
    cd "$PROJECT_ROOT"
    
    local running_services
    running_services=$(docker-compose ps --services --filter "status=running" 2>/dev/null || echo "")
    
    if [[ -z "$running_services" ]]; then
        print_success "All services are stopped"
    else
        print_warning "Some services are still running:"
        docker-compose ps
    fi
}

display_cleanup_options() {
    print_section "Cleanup Options"
    
    echo -e "\nAdditional cleanup options:"
    echo -e "  • Remove containers:     ${BLUE}docker-compose rm -f${NC}"
    echo -e "  • Remove volumes:        ${BLUE}docker-compose down -v${NC}"
    echo -e "  • Full cleanup:          ${BLUE}./scripts/dev-reset.sh${NC}"
    echo -e "  • Remove images:         ${BLUE}docker-compose down --rmi all${NC}"
    echo -e "  • Remove everything:     ${BLUE}docker-compose down -v --rmi all${NC}"
}

show_running_containers() {
    print_section "Still Running"
    
    local project_name
    project_name=$(basename "$PROJECT_ROOT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
    
    local running_containers
    running_containers=$(docker ps --filter "name=${project_name}" --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | tail -n +2 || echo "")
    
    if [[ -n "$running_containers" ]]; then
        print_warning "The following containers are still running:"
        echo "$running_containers"
        echo -e "\nTo stop them manually:"
        echo -e "  ${BLUE}docker stop \$(docker ps --filter \"name=${project_name}\" -q)${NC}"
    fi
}

usage() {
    echo -e "\nUsage: $0 [OPTIONS] [SERVICE_NAME]"
    echo -e "\nOptions:"
    echo -e "  -h, --help        Show this help message"
    echo -e "  -f, --force       Force stop (kill instead of stop)"
    echo -e "  -r, --remove      Remove containers after stopping"
    echo -e "  -c, --cleanup     Full cleanup (stop, remove containers and networks)"
    echo -e "\nExamples:"
    echo -e "  $0                      # Stop all services"
    echo -e "  $0 manager              # Stop only manager service"
    echo -e "  $0 --force              # Force stop all services"
    echo -e "  $0 --cleanup            # Stop and cleanup everything"
}

cleanup_all() {
    print_section "Full Cleanup"
    
    cd "$PROJECT_ROOT"
    
    print_info "Stopping and removing all containers, networks..."
    docker-compose down --remove-orphans
    
    # Remove project-specific networks if they exist
    local networks=("skauswatch-net" "skauswatch-backend-net" "skauswatch-frontend-net")
    for network in "${networks[@]}"; do
        if docker network ls | grep -q "$network"; then
            docker network rm "$network" 2>/dev/null || true
            print_success "Removed network: $network"
        fi
    done
    
    print_success "Full cleanup completed"
}

force_stop() {
    print_section "Force Stopping Services"
    
    cd "$PROJECT_ROOT"
    
    print_info "Force stopping all services..."
    docker-compose kill
    
    print_success "Services force stopped"
}

# Main execution
main() {
    local FORCE=false
    local REMOVE=false
    local CLEANUP=false
    local SERVICE_NAME=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_header
                usage
                exit 0
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -r|--remove)
                REMOVE=true
                shift
                ;;
            -c|--cleanup)
                CLEANUP=true
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                SERVICE_NAME="$1"
                shift
                ;;
        esac
    done
    
    print_header
    check_docker
    
    # Handle specific service
    if [[ -n "$SERVICE_NAME" ]]; then
        stop_specific_service "$SERVICE_NAME"
        display_status
        exit 0
    fi
    
    # Handle full cleanup
    if [[ "$CLEANUP" == true ]]; then
        cleanup_all
        exit 0
    fi
    
    # Handle force stop
    if [[ "$FORCE" == true ]]; then
        force_stop
    else
        stop_services
    fi
    
    # Handle container removal
    if [[ "$REMOVE" == true ]]; then
        remove_containers
    fi
    
    display_status
    show_running_containers
    display_cleanup_options
    
    echo -e "\n${GREEN}Stop operation completed!${NC}"
}

# Run main function
main "$@"