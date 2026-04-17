# Finalis Node Deployment Guide

## Overview

This guide covers deploying `finalis-node` on Linux and Windows with defaults configured for multi-node P2P connectivity using `SEEDS.json`.

## Key Defaults

- **Outbound connections:** `--outbound-target 8` (connects to up to 8 peers)
- **Peer discovery:** Automatic via `SEEDS.json` (no hardcoded peer addresses in binary/service)
- **P2P port:** 19440
- **Lightserver RPC port:** 19444
- **Public mode:** Enabled (node is discoverable via DNS seeds)

## Linux Deployment

### Using the Bootstrap Script

```bash
# From the finalis-core repository root
cd packaging/linux
sudo ./install-finalis-node.sh
```

Environment variables:
- `BINDIR` – Location of compiled binaries (default: `.` – current directory)
- `GENESISFILE` – Path to genesis.bin (default: `./mainnet/genesis.bin`)
- `SEEDS_JSON` – Path to SEEDS.json (default: `./mainnet/SEEDS.json`)
- `OPTDIR` – Installation directory (default: `/opt/finalis-core`)
- `DATADIR` – Data directory (default: `/var/lib/finalis`)

Example:
```bash
sudo BINDIR=../../../build/linux-release OPTDIR=/opt/finalis DATADIR=/data/finalis ./install-finalis-node.sh
```

### Manual Service Setup

Copy the service file:
```bash
sudo cp finalis-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable finalis-node
sudo systemctl start finalis-node
```

Edit the service to match your paths:
```bash
sudo systemctl edit finalis-node
```

### View Logs

```bash
# Real-time logs
journalctl -u finalis-node -f

# Last 50 lines
journalctl -u finalis-node -n 50

# Since last boot
journalctl -u finalis-node -b
```

## Windows Deployment

Run the `Start-Finalis.ps1` script from the installer, or manually:

```powershell
# From installer/app directory
powershell -ExecutionPolicy Bypass -File ".\scripts\Start-Finalis.ps1" -PublicNode $true
```

The script will:
1. Create firewall rules for ports 19440, 19444
2. Load `SEEDS.json` from `mainnet/SEEDS.json`
3. Configure `--outbound-target 8`
4. Start finalis-node with automatic P2P connectivity

## SEEDS.json Format

```json
{
  "network": "mainnet",
  "seeds_p2p": [
    "192.168.0.104:19440",
    "192.168.0.106:19440",
    "192.168.0.103:19440"
  ],
  "lightservers_rpc": [
    "http://192.168.0.104:19444/rpc",
    "http://192.168.0.106:19444/rpc",
    "http://192.168.0.103:19444/rpc"
  ]
}
```

The node automatically reads `seeds_p2p` and connects to these addresses for P2P networking.

## Configuration Verification

Check that the service is running correctly:

```bash
# Linux
sudo systemctl status finalis-node
journalctl -u finalis-node -f | grep -E "peers|outbound"

# Windows (check log file)
type %APPDATA%\.finalis\mainnet\logs\node.log | findstr "peers outbound"
```

Expected output:
```
mainnet h=1763 transition=debe1e32 peers=1 outbound=1/8 inbound=0 established=1 addrman=0
```

- `peers=N` – Number of connected peers
- `outbound=M/8` – M active outbound connections (target 8)
- `established=1` – Successfully established at least one connection

## Customization

### Change P2P Port

**Linux (systemd):**
```bash
sudo systemctl edit finalis-node
# Edit ExecStart line: change --port 19440 to desired port
sudo systemctl daemon-reload
sudo systemctl restart finalis-node
```

**Windows:**
```powershell
.\scripts\Start-Finalis.ps1 -P2PPort 19441
```

### Disable DNS Seed Discovery

Add to service:
```
--no-dns-seeds
```

(Already included in default templates)

### Custom Seed List

Create custom `SEEDS.json` and deploy it before starting:

```bash
# Linux
sudo cp custom-seeds.json /opt/finalis-core/mainnet/SEEDS.json
sudo systemctl restart finalis-node
```

### Run as Inbound-Only Node (No Outbound)

Set `--outbound-target 0` in the service:

```
ExecStart=...--outbound-target 0...
```

This node will only accept inbound connections.

## Troubleshooting

### Node not connecting to peers

1. Check `SEEDS.json` is being loaded:
   ```bash
   journalctl -u finalis-node | grep -i seed
   ```

2. Verify firewall allows outbound connections on port 19440:
   ```bash
   sudo ufw allow out 19440
   ```

3. Check node logs for connection errors:
   ```bash
   journalctl -u finalis-node -f | grep -E "connecting|connect|refused|timeout"
   ```

### High CPU/Memory Usage

- Limit concurrent connections: reduce `--outbound-target` (default 8)
- Check for stuck processes: `systemctl restart finalis-node`

### Database Corruption

If the node fails to start with DB errors:

```bash
# Backup current DB
sudo cp -r /var/lib/finalis/mainnet /var/lib/finalis/mainnet.backup

# Clear and restart (will resync from peers)
sudo rm -rf /var/lib/finalis/mainnet
sudo systemctl start finalis-node

# Monitor sync progress
journalctl -u finalis-node -f | grep -E "height|finalized"
```

## Performance Tips

1. **Increase file descriptors** (for many peers):
   ```bash
   sudo cat > /etc/security/limits.d/finalis.conf << EOF
   finalis soft nofile 65536
   finalis hard nofile 65536
   EOF
   # Then restart the service
   ```

2. **Use SSD** for database storage (faster sync)

3. **Allocate sufficient memory** (2GB minimum, 4GB+ recommended)

4. **Run multiple nodes** on separate machines for redundancy
