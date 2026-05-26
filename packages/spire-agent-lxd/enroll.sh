#!/bin/sh
# Enrolls LXD/VM node into the SkausWatch SPIFFE trust domain.
# Usage: enroll.sh --server <addr> --token <join-token> [--trust-domain <td>] [--port <port>]
set -e

# Defaults
SPIRE_SERVER_PORT=8081
SPIRE_TRUST_DOMAIN=penguintech.io

# Parse arguments (Bash 3.2 compatible)
while [ $# -gt 0 ]; do
  case "$1" in
    --server)
      SPIRE_SERVER_ADDRESS="$2"
      shift 2
      ;;
    --token)
      JOIN_TOKEN="$2"
      shift 2
      ;;
    --trust-domain)
      SPIRE_TRUST_DOMAIN="$2"
      shift 2
      ;;
    --port)
      SPIRE_SERVER_PORT="$2"
      shift 2
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      echo "Usage: $0 --server <addr> --token <join-token> [--trust-domain <td>] [--port <port>]" >&2
      exit 1
      ;;
  esac
done

# Validate required arguments
if [ -z "$SPIRE_SERVER_ADDRESS" ]; then
  echo "ERROR: --server <address> is required" >&2
  exit 1
fi
if [ -z "$JOIN_TOKEN" ]; then
  echo "ERROR: --token <join-token> is required" >&2
  exit 1
fi

echo "[INFO] Enrolling node into SkausWatch SPIFFE trust domain"
echo "[INFO] Server: $SPIRE_SERVER_ADDRESS:$SPIRE_SERVER_PORT"
echo "[INFO] Trust domain: $SPIRE_TRUST_DOMAIN"

# Create required directories
echo "[INFO] Creating directories..."
mkdir -p /etc/spire-agent
mkdir -p /var/lib/spire-agent/keys
mkdir -p /run/spire/sockets

# Ensure ownership
if id spire > /dev/null 2>&1; then
  chown -R spire:spire /var/lib/spire-agent /run/spire/sockets || true
fi

# Generate config from template using envsubst or sed
echo "[INFO] Generating agent configuration..."
if command -v envsubst > /dev/null 2>&1; then
  SPIRE_SERVER_ADDRESS="$SPIRE_SERVER_ADDRESS" \
  SPIRE_SERVER_PORT="$SPIRE_SERVER_PORT" \
  SPIRE_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" \
    envsubst < /etc/spire-agent/agent.conf.template > /etc/spire-agent/agent.conf
else
  # Fallback to sed for systems without envsubst
  sed -e "s|\${SPIRE_SERVER_ADDRESS}|$SPIRE_SERVER_ADDRESS|g" \
      -e "s|\${SPIRE_SERVER_PORT}|$SPIRE_SERVER_PORT|g" \
      -e "s|\${SPIRE_TRUST_DOMAIN}|$SPIRE_TRUST_DOMAIN|g" \
      /etc/spire-agent/agent.conf.template > /etc/spire-agent/agent.conf
fi
chmod 644 /etc/spire-agent/agent.conf

# Fetch bootstrap bundle from server
echo "[INFO] Fetching bootstrap trust bundle from server..."
if /usr/local/bin/spire-agent bundle fetch \
  -server "$SPIRE_SERVER_ADDRESS:$SPIRE_SERVER_PORT" \
  -trustDomain "$SPIRE_TRUST_DOMAIN" \
  -joinToken "$JOIN_TOKEN" \
  -write /etc/spire-agent/bundle.crt; then
  echo "[INFO] Bootstrap bundle fetched successfully"
else
  echo "[WARN] Failed to fetch bootstrap bundle (may be expected on first run)"
fi

# Enable and start systemd service
echo "[INFO] Enabling and starting spire-agent systemd service..."
if command -v systemctl > /dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable spire-agent || true
  systemctl restart spire-agent || true
  echo "[INFO] Service started"
else
  echo "[WARN] systemctl not found; service management unavailable" >&2
fi

echo "[INFO] Enrollment complete!"
echo "[INFO] Check status: systemctl status spire-agent"
echo "[INFO] View logs: journalctl -u spire-agent -f"
