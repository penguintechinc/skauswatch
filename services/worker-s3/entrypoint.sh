#!/bin/bash
set -e

# Start ClamAV daemon in background
echo "Starting ClamAV daemon..."
/etc/init.d/clamav-daemon start || true

# Wait for ClamAV socket to be ready
echo "Waiting for ClamAV daemon to be ready..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if [ -S /var/run/clamav/clamd.ctl ]; then
        echo "ClamAV daemon is ready"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "Warning: ClamAV daemon failed to start after $max_attempts seconds"
    echo "Continuing anyway..."
fi

# Execute the main command
exec "$@"
