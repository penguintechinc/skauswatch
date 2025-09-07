#!/bin/bash

# SkausWatch Development Reset Script
# This script resets the development environment by clearing all data

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
    echo -e "${BLUE}     SkausWatch Development Reset         ${NC}"
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

confirm_reset() {
    print_section "Confirmation Required"
    
    echo -e "${RED}WARNING: This will completely reset your development environment!${NC}"
    echo -e "\nThis will:"
    echo -e "  • Stop all running services"
    echo -e "  • Remove all containers"
    echo -e "  • Delete all persistent data (databases, logs, certificates, etc.)"
    echo -e "  • Remove Docker volumes"
    echo -e "  • Clear generated configuration files"
    echo -e "\nThis action ${RED}CANNOT BE UNDONE${NC}!"
    
    echo -e "\nType 'RESET' to continue, or anything else to cancel:"
    read -r confirmation
    
    if [[ "$confirmation" != "RESET" ]]; then
        echo -e "${GREEN}Reset cancelled.${NC}"
        exit 0
    fi
    
    print_warning "Proceeding with reset in 5 seconds... Press Ctrl+C to cancel"
    sleep 5
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

stop_all_services() {
    print_section "Stopping All Services"
    
    cd "$PROJECT_ROOT"
    
    if [[ -f "docker-compose.yml" ]]; then
        print_info "Stopping Docker Compose services..."
        docker-compose kill 2>/dev/null || true
        docker-compose down --remove-orphans 2>/dev/null || true
        print_success "Services stopped"
    else
        print_warning "docker-compose.yml not found"
    fi
}

remove_containers() {
    print_section "Removing Containers"
    
    cd "$PROJECT_ROOT"
    
    # Remove compose containers
    if [[ -f "docker-compose.yml" ]]; then
        print_info "Removing Docker Compose containers..."
        docker-compose rm -f 2>/dev/null || true
        print_success "Docker Compose containers removed"
    fi
    
    # Remove any remaining containers with skauswatch in the name
    local project_containers
    project_containers=$(docker ps -a --filter "name=skauswatch" -q 2>/dev/null || echo "")
    
    if [[ -n "$project_containers" ]]; then
        print_info "Removing remaining SkausWatch containers..."
        # shellcheck disable=SC2086
        docker rm -f $project_containers 2>/dev/null || true
        print_success "Remaining containers removed"
    fi
}

remove_volumes() {
    print_section "Removing Docker Volumes"
    
    cd "$PROJECT_ROOT"
    
    # Remove compose volumes
    if [[ -f "docker-compose.yml" ]]; then
        print_info "Removing Docker Compose volumes..."
        docker-compose down -v 2>/dev/null || true
        print_success "Docker Compose volumes removed"
    fi
    
    # Remove any remaining volumes with skauswatch in the name
    local project_volumes
    project_volumes=$(docker volume ls --filter "name=skauswatch" -q 2>/dev/null || echo "")
    
    if [[ -n "$project_volumes" ]]; then
        print_info "Removing remaining SkausWatch volumes..."
        # shellcheck disable=SC2086
        docker volume rm $project_volumes 2>/dev/null || true
        print_success "Remaining volumes removed"
    fi
}

remove_networks() {
    print_section "Removing Docker Networks"
    
    local networks=("skauswatch-net" "skauswatch-backend-net" "skauswatch-frontend-net")
    
    for network in "${networks[@]}"; do
        if docker network ls | grep -q "$network"; then
            print_info "Removing network: $network"
            docker network rm "$network" 2>/dev/null || true
            print_success "Removed network: $network"
        fi
    done
}

clear_data_directories() {
    print_section "Clearing Data Directories"
    
    local data_dirs=(
        "data"
        "logs"
    )
    
    for dir in "${data_dirs[@]}"; do
        if [[ -d "${PROJECT_ROOT}/${dir}" ]]; then
            print_info "Clearing ${dir} directory..."
            rm -rf "${PROJECT_ROOT:?}/${dir}"/*
            print_success "Cleared ${dir} directory"
        fi
    done
}

clear_generated_config() {
    print_section "Clearing Generated Configuration"
    
    local config_files=(
        "config/ssl/dev"
        "config/postgres/dev"
        "config/redis/dev.conf"
        "config/rabbitmq/dev_enabled_plugins"
        "config/prometheus/dev.yml"
        "config/grafana/dev"
        "config/nginx/dev.conf"
        "config/nginx/dev-conf.d"
    )
    
    for item in "${config_files[@]}"; do
        local full_path="${PROJECT_ROOT}/${item}"
        if [[ -e "$full_path" ]]; then
            print_info "Removing $item..."
            rm -rf "$full_path"
            print_success "Removed $item"
        fi
    done
}

clear_environment_files() {
    print_section "Clearing Environment Files"
    
    local env_files=(
        ".env.local"
        ".env.test"
    )
    
    for env_file in "${env_files[@]}"; do
        if [[ -f "${PROJECT_ROOT}/${env_file}" ]]; then
            print_info "Do you want to remove ${env_file}? [y/N]"
            read -r -n 1 remove_env
            echo
            if [[ $remove_env =~ ^[Yy]$ ]]; then
                rm -f "${PROJECT_ROOT}/${env_file}"
                print_success "Removed ${env_file}"
            else
                print_info "Kept ${env_file}"
            fi
        fi
    done
}

clear_node_modules() {
    print_section "Clearing Node.js Dependencies"
    
    if [[ -d "${PROJECT_ROOT}/node_modules" ]]; then
        print_info "Do you want to remove node_modules? [y/N]"
        read -r -n 1 remove_node_modules
        echo
        if [[ $remove_node_modules =~ ^[Yy]$ ]]; then
            print_info "Removing node_modules..."
            rm -rf "${PROJECT_ROOT}/node_modules"
            print_success "Removed node_modules"
        else
            print_info "Kept node_modules"
        fi
    fi
    
    if [[ -f "${PROJECT_ROOT}/package-lock.json" ]]; then
        print_info "Do you want to remove package-lock.json? [y/N]"
        read -r -n 1 remove_package_lock
        echo
        if [[ $remove_package_lock =~ ^[Yy]$ ]]; then
            rm -f "${PROJECT_ROOT}/package-lock.json"
            print_success "Removed package-lock.json"
        else
            print_info "Kept package-lock.json"
        fi
    fi
}

clear_docker_images() {
    print_section "Clearing Docker Images"
    
    print_info "Do you want to remove SkausWatch Docker images? [y/N]"
    read -r -n 1 remove_images
    echo
    
    if [[ $remove_images =~ ^[Yy]$ ]]; then
        # Remove images with skauswatch in the name
        local skauswatch_images
        skauswatch_images=$(docker images --filter "reference=*skauswatch*" -q 2>/dev/null || echo "")
        
        if [[ -n "$skauswatch_images" ]]; then
            print_info "Removing SkausWatch images..."
            # shellcheck disable=SC2086
            docker rmi -f $skauswatch_images 2>/dev/null || true
            print_success "Removed SkausWatch images"
        fi
        
        print_info "Do you want to remove unused Docker images? [y/N]"
        read -r -n 1 remove_unused
        echo
        
        if [[ $remove_unused =~ ^[Yy]$ ]]; then
            print_info "Removing unused Docker images..."
            docker image prune -af
            print_success "Removed unused Docker images"
        fi
    fi
}

recreate_basic_structure() {
    print_section "Recreating Basic Structure"
    
    # Recreate essential directories
    local essential_dirs=(
        "data"
        "logs" 
        "config"
        "scripts"
    )
    
    for dir in "${essential_dirs[@]}"; do
        mkdir -p "${PROJECT_ROOT}/${dir}"
        print_success "Created ${dir} directory"
    done
}

display_next_steps() {
    print_section "Next Steps"
    
    echo -e "\n${GREEN}Development environment has been reset!${NC}\n"
    echo -e "To set up the development environment again:"
    echo -e "  1. Run ${BLUE}./scripts/dev-setup.sh${NC} to initialize the environment"
    echo -e "  2. Run ${BLUE}./scripts/dev-start.sh${NC} to start all services"
    echo -e "\nAlternatively, you can:"
    echo -e "  • Set up manually by copying ${BLUE}.env.local.example${NC} to ${BLUE}.env.local${NC}"
    echo -e "  • Use ${BLUE}docker-compose up${NC} to start specific services"
    echo -e "  • Restore from a backup if you have one"
}

verify_reset() {
    print_section "Verifying Reset"
    
    local issues=()
    
    # Check for remaining containers
    local remaining_containers
    remaining_containers=$(docker ps -a --filter "name=skauswatch" -q 2>/dev/null || echo "")
    if [[ -n "$remaining_containers" ]]; then
        issues+=("Remaining containers found")
    fi
    
    # Check for remaining volumes
    local remaining_volumes
    remaining_volumes=$(docker volume ls --filter "name=skauswatch" -q 2>/dev/null || echo "")
    if [[ -n "$remaining_volumes" ]]; then
        issues+=("Remaining volumes found")
    fi
    
    # Check for data directories
    if [[ -d "${PROJECT_ROOT}/data" ]] && [[ -n "$(find "${PROJECT_ROOT}/data" -type f 2>/dev/null)" ]]; then
        issues+=("Data files still exist")
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        print_success "Reset verification passed"
    else
        print_warning "Reset verification issues:"
        for issue in "${issues[@]}"; do
            echo -e "  • $issue"
        done
        echo -e "\nYou may need to manually clean up these items."
    fi
}

usage() {
    echo -e "\nUsage: $0 [OPTIONS]"
    echo -e "\nOptions:"
    echo -e "  -h, --help        Show this help message"
    echo -e "  -y, --yes         Skip confirmation (dangerous!)"
    echo -e "  --keep-config     Keep configuration files"
    echo -e "  --keep-env        Keep environment files"
    echo -e "  --keep-deps       Keep node_modules and package-lock.json"
    echo -e "  --keep-images     Keep Docker images"
    echo -e "\nThis script will:"
    echo -e "  • Stop all services"
    echo -e "  • Remove containers and volumes"
    echo -e "  • Clear all data directories"
    echo -e "  • Remove generated configuration"
    echo -e "  • Optionally remove dependencies and images"
    echo -e "\nUse with caution - this action cannot be undone!"
}

# Main execution
main() {
    local SKIP_CONFIRMATION=false
    local KEEP_CONFIG=false
    local KEEP_ENV=false
    local KEEP_DEPS=false
    local KEEP_IMAGES=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_header
                usage
                exit 0
                ;;
            -y|--yes)
                SKIP_CONFIRMATION=true
                shift
                ;;
            --keep-config)
                KEEP_CONFIG=true
                shift
                ;;
            --keep-env)
                KEEP_ENV=true
                shift
                ;;
            --keep-deps)
                KEEP_DEPS=true
                shift
                ;;
            --keep-images)
                KEEP_IMAGES=true
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                print_error "Unexpected argument: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    print_header
    check_docker
    
    # Confirmation
    if [[ "$SKIP_CONFIRMATION" == false ]]; then
        confirm_reset
    fi
    
    # Reset operations
    stop_all_services
    remove_containers
    remove_volumes
    remove_networks
    clear_data_directories
    
    if [[ "$KEEP_CONFIG" == false ]]; then
        clear_generated_config
    fi
    
    if [[ "$KEEP_ENV" == false ]]; then
        clear_environment_files
    fi
    
    if [[ "$KEEP_DEPS" == false ]]; then
        clear_node_modules
    fi
    
    if [[ "$KEEP_IMAGES" == false ]]; then
        clear_docker_images
    fi
    
    recreate_basic_structure
    verify_reset
    display_next_steps
    
    echo -e "\n${GREEN}Development environment reset completed!${NC}"
}

# Run main function
main "$@"