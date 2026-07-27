#!/bin/bash
# SkausWatch ENDPOINT Agent Installation Script for Linux

set -e

# Configuration
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/skauswatch"
SERVICE_FILE="/etc/systemd/system/endpoint-agent.service"
BINARY_NAME="endpoint-agent"

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
    log_info "Installing ENDPOINT agent binary..."

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

    if [ ! -f "${CONFIG_DIR}/endpoint-agent.yaml" ]; then
        cat > "${CONFIG_DIR}/endpoint-agent.yaml" << 'EOF'
# SkausWatch ENDPOINT Agent Configuration

manager_url: "https://manager.example.com:5000"
api_key: ""  # Set via environment variable ENDPOINT_API_KEY

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
        log_info "Default configuration created at ${CONFIG_DIR}/endpoint-agent.yaml"
    else
        log_warn "Configuration already exists, skipping..."
    fi

    # Create environment file
    if [ ! -f "${CONFIG_DIR}/endpoint-agent.env" ]; then
        cat > "${CONFIG_DIR}/endpoint-agent.env" << 'EOF'
# Environment variables for ENDPOINT Agent
ENDPOINT_API_KEY=
ENDPOINT_MANAGER_URL=
ENDPOINT_DEBUG=false
EOF
        chmod 600 "${CONFIG_DIR}/endpoint-agent.env"
        log_info "Environment file created at ${CONFIG_DIR}/endpoint-agent.env"
    fi
}

install_service() {
    log_info "Installing systemd service..."

    cat > "${SERVICE_FILE}" << 'EOF'
[Unit]
Description=SkausWatch ENDPOINT Agent
Documentation=https://github.com/penguintech/skauswatch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=-/etc/skauswatch/endpoint-agent.env
ExecStart=/usr/local/bin/endpoint-agent --config /etc/skauswatch/endpoint-agent.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=endpoint-agent
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service installed"
}

enable_service() {
    log_info "Enabling ENDPOINT agent service..."
    systemctl enable endpoint-agent
}

start_service() {
    log_info "Starting ENDPOINT agent service..."
    systemctl start endpoint-agent
}

show_status() {
    echo ""
    log_info "Installation complete!"
    echo ""
    echo "Service status:"
    systemctl status endpoint-agent --no-pager || true
    echo ""
    echo "Configuration file: ${CONFIG_DIR}/endpoint-agent.yaml"
    echo "Environment file:   ${CONFIG_DIR}/endpoint-agent.env"
    echo ""
    echo "Commands:"
    echo "  Start:   systemctl start endpoint-agent"
    echo "  Stop:    systemctl stop endpoint-agent"
    echo "  Status:  systemctl status endpoint-agent"
    echo "  Logs:    journalctl -u endpoint-agent -f"
}

uninstall() {
    log_info "Uninstalling ENDPOINT agent..."

    systemctl stop endpoint-agent 2>/dev/null || true
    systemctl disable endpoint-agent 2>/dev/null || true

    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -f "${SERVICE_FILE}"

    systemctl daemon-reload

    log_info "ENDPOINT agent uninstalled"
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
