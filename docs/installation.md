# Installation

Proxyt is a Go binary, so it can be run very easily as a standalone process or via Docker. The recommended way to install Proxyt is via Docker.

## Docker

ProxyT Docker images are available on GitHub Container Registry with the following features:
- **Minimal size**: Based on distroless images for security and efficiency
- **Multi-architecture**: Supports both AMD64 and ARM64
- **Non-root user**: Runs as user 65532 for security
- **Signal handling**: Uses dumb-init as PID 1 for proper signal forwarding
- **Pre-created directories**: Certificate directory `/certs` ready for use

```bash
# Pull the latest image
docker pull ghcr.io/jaxxstorm/proxyt:latest
```

## macOS (via Homebrew)

```bash
brew tap jaxxstorm/tap
brew install proxyt
```

## Windows (via Scoop)

```bash
scoop bucket add jaxxstorm https://github.com/jaxxstorm/scoop-bucket.git
scoop install proxyt
```

## Linux (Download Binary)

### Quick Install Script

```bash
# Auto-detect architecture and install latest version to /usr/local/bin (requires sudo)
ARCH=$(uname -m)
case $ARCH in
  x86_64) ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

VERSION=$(curl -s https://api.github.com/repos/jaxxstorm/proxyt/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//')
curl -fsSL "https://github.com/jaxxstorm/proxyt/releases/latest/download/proxyt_${VERSION}_linux_${ARCH}.tar.gz" | sudo tar xz -C /usr/local/bin/ proxyt
```

### Manual Download

Download the latest release for your architecture:

```bash
# For x86_64/amd64
wget https://github.com/jaxxstorm/proxyt/releases/latest/download/proxyt_$(curl -s https://api.github.com/repos/jaxxstorm/proxyt/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//')_linux_amd64.tar.gz
tar -xzf proxyt_*_linux_amd64.tar.gz

# For ARM64
wget https://github.com/jaxxstorm/proxyt/releases/latest/download/proxyt_$(curl -s https://api.github.com/repos/jaxxstorm/proxyt/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//')_linux_arm64.tar.gz
tar -xzf proxyt_*_linux_arm64.tar.gz

# Make executable and move to PATH
chmod +x proxyt
sudo mv proxyt /usr/local/bin/
```

Or manually download from the [releases page](https://github.com/jaxxstorm/proxyt/releases).

