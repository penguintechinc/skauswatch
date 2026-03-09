#!/bin/bash
# SkausWatch EDR Agent Installation Script for Linux

set -e

# Configuration
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/skauswatch"
SERVICE_FILE="/etc/systemd/system/edr-agent.service"
BINARY_NAME="edr-agent"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v systemctl &> /dev/null; then
        log_error "systemctl not found. This script requires systemd."
        exit 1
    fi
}

install_binary() {
    log_info "Installing EDR agent binary..."

    if [ ! -f "./${BINARY_NAME}" ]; then
        log_error "Binary not found. Please build the agent first."
        exit 1
    fi

    cp "./${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    log_info "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

create_config() {
    log_info "Creating configuration directory..."

    mkdir -p "${CONFIG_DIR}"

    if [ ! -f "${CONFIG_DIR}/edr-agent.yaml" ]; then
        cat > "${CONFIG_DIR}/edr-agent.yaml" << 'EOF'
# SkausWatch EDR Agent Configuration

manager_url: "https://manager.example.com:5000"
api_key: ""  # Set via environment variable EDR_API_KEY

heartbeat_interval: 60
event_buffer_size: 1000
debug: false

collectors:
  process:
    enabled: true
  file:
    enabled: true
    watch_paths:
      - "/etc"
      - "/usr/bin"
      - "/usr/sbin"
  network:
    enabled: true
EOF
        log_info "Default configuration created at ${CONFIG_DIR}/edr-agent.yaml"
    else
        log_warn "Configuration already exists, skipping..."
    fi

    # Create environment file
    if [ ! -f "${CONFIG_DIR}/edr-agent.env" ]; then
        cat > "${CONFIG_DIR}/edr-agent.env" << 'EOF'
# Environment variables for EDR Agent
EDR_API_KEY=
EDR_MANAGER_URL=
EDR_DEBUG=false
EOF
        chmod 600 "${CONFIG_DIR}/edr-agent.env"
        log_info "Environment file created at ${CONFIG_DIR}/edr-agent.env"
    fi
}

install_service() {
    log_info "Installing systemd service..."

    cat > "${SERVICE_FILE}" << 'EOF'
[Unit]
Description=SkausWatch EDR Agent
Documentation=https://github.com/penguintech/skauswatch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=-/etc/skauswatch/edr-agent.env
ExecStart=/usr/local/bin/edr-agent --config /etc/skauswatch/edr-agent.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edr-agent
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service installed"
}

enable_service() {
    log_info "Enabling EDR agent service..."
    systemctl enable edr-agent
}

start_service() {
    log_info "Starting EDR agent service..."
    systemctl start edr-agent
}

show_status() {
    echo ""
    log_info "Installation complete!"
    echo ""
    echo "Service status:"
    systemctl status edr-agent --no-pager || true
    echo ""
    echo "Configuration file: ${CONFIG_DIR}/edr-agent.yaml"
    echo "Environment file:   ${CONFIG_DIR}/edr-agent.env"
    echo ""
    echo "Commands:"
    echo "  Start:   systemctl start edr-agent"
    echo "  Stop:    systemctl stop edr-agent"
    echo "  Status:  systemctl status edr-agent"
    echo "  Logs:    journalctl -u edr-agent -f"
}

uninstall() {
    log_info "Uninstalling EDR agent..."

    systemctl stop edr-agent 2>/dev/null || true
    systemctl disable edr-agent 2>/dev/null || true

    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -f "${SERVICE_FILE}"

    systemctl daemon-reload

    log_info "EDR agent uninstalled"
    log_warn "Configuration files in ${CONFIG_DIR} were not removed"
}

main() {
    case "${1:-install}" in
        install)
            check_root
            check_dependencies
            install_binary
            create_config
            install_service
            enable_service
            start_service
            show_status
            ;;
        uninstall)
            check_root
            uninstall
            ;;
        *)
            echo "Usage: $0 {install|uninstall}"
            exit 1
            ;;
    esac
}

main "$@"
