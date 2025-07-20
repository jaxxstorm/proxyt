# ProxyT - Tailscale Login Server Proxy

A reverse proxy server that enables using a custom domain as a Tailscale login server when Tailscale domains are blocked or restricted in your environment.

## Overview

Tailscale is pretty good at forging connections in lots of environments, but if you block Taislcale's controlplane via DNS or external proxy, you can't login.

This project builds a very simple Go proxy which can be hosted externally and will proxy requests to Tailscale's control plane.

## Installation

### macOS (via Homebrew)

```bash
brew tap jaxxstorm/tap
brew install proxyt
```

### Windows (via Scoop)

```bash
scoop bucket add jaxxstorm https://github.com/jaxxstorm/scoop-bucket.git
scoop install proxyt
```

### Linux (Download Binary)

#### Quick Install Script

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

#### Manual Download

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

### Docker

ProxyT Docker images are available on GitHub Container Registry with the following features:
- **Minimal size**: Based on distroless images for security and efficiency
- **Multi-architecture**: Supports both AMD64 and ARM64
- **Non-root user**: Runs as user 65532 for security
- **Signal handling**: Uses dumb-init as PID 1 for proper signal forwarding
- **Pre-created directories**: Certificate directory `/certs` ready for use

```bash
# Pull the latest image
docker pull ghcr.io/jaxxstorm/proxyt:latest

# Run with automatic certificates (requires volumes for certificate storage)
docker run -d \
  --name proxyt \
  -p 80:80 \
  -p 443:443 \
  -v proxyt-certs:/certs \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --email admin@example.com --cert-dir /certs

# Run in HTTP-only mode (behind reverse proxy)
docker run -d \
  --name proxyt \
  -p 8080:8080 \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --http-only --port 8080 --bind 0.0.0.0

# Quick test without persistent storage (certificates won't persist)
docker run -d \
  --name proxyt \
  -p 80:80 \
  -p 443:443 \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --email admin@example.com --cert-dir /certs

# With Docker Compose
cat > docker-compose.yml << EOF
version: '3.8'
services:
  proxyt:
    image: ghcr.io/jaxxstorm/proxyt:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - proxyt-certs:/certs
    command: serve --domain proxy.example.com --email admin@example.com --cert-dir /certs
    restart: unless-stopped

volumes:
  proxyt-certs:
EOF

docker compose up -d
```

### From Source

```bash
git clone https://github.com/jaxxstorm/proxyt.git
cd proxyt
go build -o proxyt .
```

### Using Go Install

```bash
go install github.com/jaxxstorm/proxyt@latest
```

### Verify Installation

After installation, verify ProxyT is working:

```bash
proxyt --version
proxyt serve --help
```

## Usage

### Basic Usage with Automatic Certificates

```bash
proxyt serve \
  --domain proxy.example.com \
  --email admin@example.com \
  --cert-dir /etc/proxyt/certs
```

### Using Existing Certificates

```bash
proxyt serve \
  --domain proxy.example.com \
  --cert-dir /etc/proxyt/certs \
  --issue=false
```

### Debug Mode

```bash
proxyt serve \
  --domain proxy.example.com \
  --email admin@example.com \
  --cert-dir /etc/proxyt/certs \
  --debug
```

### Behind HTTPS Reverse Proxy (Tailscale Funnel, Pangolin, etc.)

When deploying behind an HTTPS reverse proxy that handles TLS termination:

```bash
proxyt serve \
  --domain proxy.example.com \
  --http-only \
  --port 8080 \
  --bind 127.0.0.1
```

This mode is perfect for:
- **Tailscale Funnel**: Expose via `tailscale funnel 8080`
- **Pangolin**: Let Pangolin handle TLS termination 
- **Nginx/Apache**: Traditional reverse proxy setup

## Configuration Options

| Flag | Description | Default | Required |
|------|-------------|---------|----------|
| `--domain` | Your custom domain name | - | Yes |
| `--email` | Email for Let's Encrypt registration | - | Yes (when --issue=true) |
| `--cert-dir` | Directory for SSL certificates | - | Yes (when not --http-only) |
| `--issue` | Auto-issue Let's Encrypt certificates | `true` | No |
| `--port` | HTTP port for challenges or main port in HTTP-only mode | `80` | No |
| `--https-port` | HTTPS port for the proxy | `443` | No |
| `--debug` | Enable debug logging | `false` | No |
| `--http-only` | Run behind HTTPS proxy (no TLS termination) | `false` | No |
| `--bind` | Address to bind the server to | `0.0.0.0` | No |

## Deployment Scenarios

### Standalone with Let's Encrypt (Default)

Direct deployment with automatic certificate management:

```bash
proxyt serve --domain proxy.example.com --email admin@example.com --cert-dir /etc/proxyt/certs
```

**Requirements:**
- Domain points to your server
- Ports 80 and 443 accessible from internet
- Valid email for Let's Encrypt

### Behind Tailscale Funnel

Deploy ProxyT on your Tailscale network and expose via Funnel:

```bash
# Start ProxyT in HTTP-only mode
proxyt serve --domain proxy.tailXXXX.ts.net --http-only --port 8080 --bind 127.0.0.1

# In another terminal, expose via Tailscale Funnel
tailscale funnel 8080
```

**Benefits:**
- No need for public IP or port forwarding
- Automatic TLS via Tailscale
- Only accessible via your Tailscale network initially
- Can be made publicly accessible via Funnel

### Behind Pangolin or Similar Proxy

When using a service that provides TLS termination:

```bash
proxyt serve --domain proxy.example.com --http-only --port 3000
```

Then configure your proxy to forward `https://proxy.example.com` to `http://localhost:3000`.

### Behind Traditional Reverse Proxy (Nginx/Apache)

```bash
proxyt serve --domain proxy.example.com --http-only --port 8080 --bind 127.0.0.1
```

**Nginx configuration example:**
```nginx
server {
    listen 443 ssl;
    server_name proxy.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Important for Tailscale protocol upgrades
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Docker Deployment

#### Standalone with Let's Encrypt

```bash
# With persistent certificate storage
docker run -d \
  --name proxyt \
  -p 80:80 \
  -p 443:443 \
  -v proxyt-certs:/certs \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --email admin@example.com --cert-dir /certs

# Quick test (certificates won't persist across container restarts)
docker run -d \
  --name proxyt \
  -p 80:80 \
  -p 443:443 \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --email admin@example.com --cert-dir /certs
```

#### Behind Reverse Proxy

```bash
docker run -d \
  --name proxyt \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --http-only --port 8080 --bind 0.0.0.0
```

## Tailscale Integration

### Interactive Login

Once your proxy is running, configure Tailscale clients to use your custom domain:

```bash
tailscale login --login-server https://proxy.example.com
```

> [!WARNING]  
> This will generate a login URL like https://login.tailscale.com/a/something - you should use an external device to login to Tailscale.


### Auth Key Login

For automated deployments with pre-authorized keys:

```bash
tailscale login --login-server https://proxy.example.com --auth-key tskey-auth-xxxxx
```

### Web Interface

Users can also access the Tailscale web interface directly by visiting your custom domain in a browser.

## Architecture

The proxy intelligently routes requests based on path patterns and headers:

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────────────┐
│  Tailscale      │    │   ProxyT     │    │     Tailscale Cloud     │
│  Client/Browser │───▶│   Proxy      │───▶│                         │
│                 │    │              │    │ ┌─────────────────────┐ │
└─────────────────┘    └──────────────┘    │ │ login.tailscale.com │ │
                                           │ │ controlplane.ts.com │ │
                                           │ │ derp.tailscale.com  │ │
                                           │ └─────────────────────┘ │
                                           └─────────────────────────┘
```

### Request Routing Logic

- **Control Protocol** (`/ts2021`): Custom protocol upgrade handler for Tailscale's control protocol
- **Key Exchange** (`/key`): Routes to `controlplane.tailscale.com`
- **API Endpoints** (`/api/*`, `/machine/*`): Routes to `controlplane.tailscale.com`
- **DERP Traffic** (`/derp/*`): Routes to `derp.tailscale.com`
- **Authentication** (`/login`, `/auth`, `/a/*`): Routes to `login.tailscale.com`
- **Default/Web**: Routes to `login.tailscale.com`

## DNS Configuration

Point your custom domain to the server running ProxyT:

```dns
proxy.example.com.    300    IN    A    203.0.113.10
```

Ensure ports 80 (HTTP) and 443 (HTTPS) are accessible from the internet.

## Certificate Management

### Automatic (Let's Encrypt)

When `--issue=true` (default), ProxyT automatically:
- Obtains SSL certificates from Let's Encrypt
- Handles ACME HTTP-01 challenges on port 80
- Automatically renews certificates before expiration
- Stores certificates in the specified `--cert-dir`

### Manual Certificates

When `--issue=false`, provide your own certificates:
- Place `domain.crt` and `domain.key` in `--cert-dir`
- Ensure certificates are valid and properly formatted
- Handle certificate renewal manually

## Monitoring

### Health Checks

ProxyT provides health check endpoints:

- HTTP: `http://proxy.example.com/health`
- HTTPS: `https://proxy.example.com/health`

Both return `200 OK` with response body: `OK - Tailscale Proxy is running`

### Logging

Structured JSON logging (production) or console logging (debug mode):

```json
{
  "level": "info",
  "ts": "2025-07-16T13:35:12.123Z",
  "msg": "Reverse proxying request",
  "host": "proxy.example.com",
  "path": "/key",
  "target": "controlplane.tailscale.com"
}
```

## Troubleshooting

### Common Issues

**Port 80/443 Access**
- Ensure firewall allows inbound connections
- Check if other services are using these ports
- Verify DNS resolution points to correct IP

**Certificate Issues**
- Check email address is valid for Let's Encrypt
- Ensure domain resolves to proxy server
- Verify port 80 is accessible for ACME challenges

**Tailscale Connection Failures**
- Enable debug mode (`--debug`) to see detailed request logs
- Check that Tailscale client can resolve your domain
- Verify proxy can reach `*.tailscale.com` domains

**HTTP-Only Mode Issues**
- Ensure your reverse proxy is properly forwarding X-Forwarded headers
- Verify the reverse proxy supports HTTP/1.1 upgrades for `/ts2021` endpoints
- Check that the bind address and port are correct
- Confirm your reverse proxy is handling TLS termination properly

**Protocol Upgrade Failures**
- Ensure reverse proxy supports WebSocket/HTTP upgrades
- Check that `Connection: upgrade` and `Upgrade` headers are forwarded
- Verify no intermediate proxies are stripping upgrade headers

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
proxyt serve --domain proxy.example.com --email admin@example.com --cert-dir /tmp/certs --debug
```

This provides detailed request/response logging including headers and routing decisions.

## Security Considerations

- **TLS Termination**: ProxyT terminates TLS and re-encrypts to Tailscale services
- **Certificate Storage**: Protect the certificate directory with appropriate file permissions
- **Network Access**: Restrict access to the proxy server as needed
- **Logging**: Debug mode logs sensitive headers; use carefully in production
- **Docker Security**: 
  - Images run as non-root user (65532)
  - Based on distroless images with minimal attack surface
  - Use dumb-init for proper signal handling
  - Regular security updates via automated builds

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

See [LICENSE](LICENSE) for details.

## Support

For issues and questions:
- GitHub Issues: [Repository Issues](https://github.com/jaxxstorm/proxyt/issues)
- Documentation: This README and inline code comments
