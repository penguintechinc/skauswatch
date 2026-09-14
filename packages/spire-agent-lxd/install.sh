#!/bin/sh
# One-line installer for skauswatch-spire-agent on LXD/VM nodes.
# Usage: curl -fsSL https://skauswatch.example.com/install/spire-agent | sh -s -- --server <addr> --token <token>
set -e

SPIRE_VERSION="${SPIRE_VERSION:-1.9.4}"
RELEASE_URL="${RELEASE_URL:-https://github.com/penguintechinc/skauswatch/releases/download}"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)
    DEB_ARCH=amd64
    ;;
  aarch64)
    DEB_ARCH=arm64
    ;;
  *)
    echo "ERROR: Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

echo "[INFO] Installing skauswatch-spire-agent v${SPIRE_VERSION} for ${DEB_ARCH}..."

# Check for required tools
if ! command -v dpkg > /dev/null 2>&1; then
  echo "ERROR: dpkg not found. This installer requires a Debian-based system." >&2
  exit 1
fi

if ! command -v curl > /dev/null 2>&1; then
  echo "ERROR: curl not found. Please install curl and try again." >&2
  exit 1
fi

# Create temporary directory
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Download .deb package
DOWNLOAD_URL="${RELEASE_URL}/v${SPIRE_VERSION}/skauswatch-spire-agent_${SPIRE_VERSION}_${DEB_ARCH}.deb"
echo "[INFO] Downloading from: $DOWNLOAD_URL"

if ! curl -fsSL -o "$TMPDIR/spire-agent.deb" "$DOWNLOAD_URL"; then
  echo "ERROR: Failed to download package from $DOWNLOAD_URL" >&2
  exit 1
fi

echo "[INFO] Installing package..."
if ! dpkg -i "$TMPDIR/spire-agent.deb"; then
  echo "ERROR: Failed to install .deb package" >&2
  exit 1
fi

echo "[INFO] Package installed successfully!"
echo "[INFO] Running enrollment script..."

# Forward remaining args to enroll.sh
/usr/local/bin/spire-enroll "$@"
