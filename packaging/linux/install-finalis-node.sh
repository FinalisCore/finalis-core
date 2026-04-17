#!/bin/bash
# Bootstrap Finalis Node on Linux
# This script installs finalis-node as a systemd service and configures it to use SEEDS.json

set -e

BINDIR="${BINDIR:-.}"
CONFDIR="${CONFDIR:-.}"
GENESISFILE="${GENESISFILE:-./mainnet/genesis.bin}"
SEEDS_JSON="${SEEDS_JSON:-./mainnet/SEEDS.json}"
OPTDIR="${OPTDIR:-/opt/finalis-core}"
DATADIR="${DATADIR:-/var/lib/finalis}"
P2PPORT="${P2PPORT:-19440}"
LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-19444}"

# Ensure running as root for systemd service install
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use: sudo $0)"
   exit 1
fi

echo "=== Finalis Node Bootstrap ==="
echo "Install directory: $OPTDIR"
echo "Data directory: $DATADIR"
echo "P2P Port: $P2PPORT"
echo "Lightserver Port: $LIGHTSERVER_PORT"
echo ""

# Create directories
mkdir -p "$OPTDIR/bin" "$OPTDIR/mainnet" "$DATADIR/keystore" "$DATADIR/logs"

# Copy binaries and configs
echo "Installing binaries..."
if [ -f "$BINDIR/finalis-node" ]; then
    cp "$BINDIR/finalis-node" "$OPTDIR/bin/"
    chmod +x "$OPTDIR/bin/finalis-node"
fi
if [ -f "$BINDIR/finalis-lightserver" ]; then
    cp "$BINDIR/finalis-lightserver" "$OPTDIR/bin/"
    chmod +x "$OPTDIR/bin/finalis-lightserver"
fi

# Copy genesis and seeds
echo "Installing configuration..."
if [ -f "$GENESISFILE" ]; then
    cp "$GENESISFILE" "$OPTDIR/mainnet/"
fi
if [ -f "$SEEDS_JSON" ]; then
    cp "$SEEDS_JSON" "$OPTDIR/mainnet/"
    echo "Seeds loaded from: $SEEDS_JSON"
fi

# Install systemd service
echo "Installing systemd service..."
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SERVICE_FILE="$SCRIPT_DIR/finalis-node.service"

if [ ! -f "$SERVICE_FILE" ]; then
    echo "ERROR: finalis-node.service not found at $SERVICE_FILE"
    exit 1
fi

# Customize service file with actual paths
sed -e "s|/opt/finalis-core|$OPTDIR|g" \
    -e "s|/var/lib/finalis|$DATADIR|g" \
    "$SERVICE_FILE" > "/etc/systemd/system/finalis-node.service"

chmod 644 "/etc/systemd/system/finalis-node.service"

# Create finalis user and group if not exists
if ! id -u finalis > /dev/null 2>&1; then
    echo "Creating finalis system user..."
    useradd -r -s /bin/false -d "$DATADIR" finalis
fi

# Set permissions
chown -R finalis:finalis "$DATADIR"
chown -R finalis:finalis "$OPTDIR"

# Enable and start service
echo "Enabling and starting finalis-node service..."
systemctl daemon-reload
systemctl enable finalis-node

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Available commands:"
echo "  systemctl start finalis-node     - Start the service"
echo "  systemctl stop finalis-node      - Stop the service"
echo "  systemctl restart finalis-node   - Restart the service"
echo "  systemctl status finalis-node    - Show service status"
echo "  journalctl -u finalis-node -f    - View logs in real-time"
echo ""
echo "Configuration:"
echo "  Service file: /etc/systemd/system/finalis-node.service"
echo "  Data dir:     $DATADIR"
echo "  Binary:       $OPTDIR/bin/finalis-node"
echo "  Seeds file:   $OPTDIR/mainnet/SEEDS.json"
echo ""
echo "To start: sudo systemctl start finalis-node"
