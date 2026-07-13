# TrustEdge Snap Package - Developer Guide

This document covers debugging, developer workflows, and troubleshooting for the TrustEdge snap package. For basic build and installation instructions, see [samples/trustedge/BUILD_RUN.md](samples/trustedge/BUILD_RUN.md).

## DEB to Snap Migration

### Command Mapping

| DEB Command | Snap Equivalent |
|-------------|-----------------|
| `sudo dpkg -i trustedge.deb` | `sudo snap install trustedge_*.snap --dangerous` |
| `sudo dpkg -i trustedge.deb` (upgrade) | `sudo snap refresh trustedge` or `sudo snap install trustedge_*.snap --dangerous` |
| `sudo dpkg --remove trustedge` | `sudo snap remove trustedge` |
| `sudo dpkg --purge trustedge` | `sudo snap remove trustedge --purge` |

### Data Path Mapping

| DEB Path | Snap Path | Description |
|----------|-----------|-------------|
| `/etc/digicert/` | `/var/snap/trustedge/common/digicert/` | Configuration directory |
| `/etc/digicert/conf/` | `/var/snap/trustedge/common/digicert/conf/` | Config files |
| `/etc/digicert/keystore/` | `/var/snap/trustedge/common/digicert/keystore/` | Certificate keystore |
| `/var/lib/trustedge/` | `/var/snap/trustedge/current/trustedge/` | Runtime data |
| `/usr/bin/trustedge` | `/snap/bin/trustedge` | Binary location |

### Hook Lifecycle (matches DEB behavior)

| DEB Script | Snap Hook | Description |
|------------|-----------|-------------|
| `preinst` | - | EULA handled differently (snap store or skip) |
| `postinst` (install) | `install` | Create directories, copy default config |
| `postinst` (upgrade) | `post-refresh` | Restore config, update version files |
| `prerm` (upgrade) | `pre-refresh` | Backup configuration before upgrade |
| `prerm` (remove) | `remove` | Backup configuration to /tmp |
| `postrm` (purge) | `--purge` flag | Removes all data including $SNAP_COMMON |
| `postrm` (remove) | - | Config preserved in $SNAP_COMMON (one snapshot kept) |

---

## Developer Workflows

### Build Options

```bash
# Standard build
snapcraft

# Build with LXD (recommended for clean environment)
snapcraft --use-lxd

# Build for debugging (drops into shell on failure)
snapcraft --debug

# Clean build (removes previous build artifacts)
snapcraft clean
snapcraft

# Build with verbose output
snapcraft --verbosity=verbose

# Build without cleanup (faster iteration, use with caution)
snapcraft --destructive-mode
```

### Inspecting the Built Snap

```bash
# List snap contents
unsquashfs -l trustedge_*.snap

# Extract snap for inspection
unsquashfs trustedge_*.snap -d snap-contents/

# Check the binary
ls -la snap-contents/usr/bin/
```

### Testing Snap Locally

```bash
# Install with dangerous flag (for unsigned local snaps)
sudo snap install trustedge_*.snap --dangerous

# Reinstall after rebuilding
sudo snap remove trustedge
sudo snap install trustedge_*.snap --dangerous
```

### Inspecting Snap Environment

```bash
# Run a shell inside the snap's confinement
sudo snap run --shell trustedge

# Check environment variables
snap run --shell trustedge -c 'env | grep SNAP'

# Verify paths
snap run --shell trustedge -c 'ls -la /etc/digicert'
```

### Checking Snap Version and Info

```bash
# Installed version
snap info trustedge

# Detailed revision info
snap list trustedge --all

# Check snap assertions
snap known snap-declaration snap-name=trustedge
```

### Service Management

```bash
# View service status
sudo snap services trustedge

# Enable/disable the daemon
sudo snap start --enable trustedge.trustedged
sudo snap stop --disable trustedge.trustedged

# Restart after config changes
sudo snap restart trustedge.trustedged

# Check service logs
sudo snap logs trustedge.trustedged -n=50
```

### Cleaning Up

```bash
# Remove snap but keep data (default)
sudo snap remove trustedge

# Remove snap and all data
sudo snap remove trustedge --purge

# Clean snapcraft build artifacts
snapcraft clean
```

---

## Troubleshooting

### Check Interface Connections

```bash
# View connected interfaces
snap connections trustedge

# List all available interfaces
snap interfaces

# Check specific interface status
snap interface tpm
```

### File Access Issues (Confinement)

Snaps cannot access arbitrary files on the host. To pass files to the snap:

```bash
# Copy files to the snap's writable directory
sudo cp ./bootstrap.zip /var/snap/trustedge/common/

# Reference them using the snap path
sudo trustedge agent --configure --bootstrap-zip /var/snap/trustedge/common/bootstrap.zip
```

### View Detailed Logs

```bash
# Service logs
sudo journalctl -u snap.trustedge.trustedged.service -f

# All snap logs
sudo snap logs trustedge -f

# Logs with timestamps
sudo snap logs trustedge -n=100
```

### Enable Debug Logging

Edit the TrustEdge configuration:

```bash
sudo nano /var/snap/trustedge/common/digicert/trustedge.json
```

Set `"logLevel": "DEBUG"` and restart the service.

### Running in Devmode (Bypasses Confinement)

For debugging confinement issues:

```bash
sudo snap install trustedge_*.snap --dangerous --devmode
```

### Debugging Confinement Denials

```bash
# Watch for AppArmor denials in real-time
sudo journalctl -k | grep DENIED

# Or use snappy-debug (install if needed: sudo snap install snappy-debug)
sudo snappy-debug
```

---

## Features Included

This snap build includes:
- **TPM2 Support** - Hardware-backed key storage
- **PQC Support** - Post-Quantum Cryptography
- **PQC Composite** - PQC composite certificates
- **Proxy Support** - HTTP/HTTPS proxy configuration
- **CVC Support** - CV Certificate handling
- **EST/SCEP** - Enrollment protocols

## Directory Layout

The snap uses the following layout:

| Snap Path | Mapped To |
|-----------|-----------|
| `$SNAP_COMMON/digicert` | `/etc/digicert` |
| `$SNAP_DATA/trustedge` | `/var/lib/trustedge` |

## Architecture Support

Currently supported:
- amd64 (x86_64)

For ARM builds, modify the `platforms` section in `snapcraft.yaml`.
