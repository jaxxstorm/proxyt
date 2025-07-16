# ProxyT - Tailscale Login Server Proxy

A reverse proxy server that enables using a custom domain as a Tailscale login server when Tailscale domains are blocked or restricted in your environment.

## Overview

Tailscale is pretty good at forging connections in lots of environments, but if you block Taislcale's controlplane via DNS or external proxy, you can't login.

This project builds a very simple Go proxy which can be hosted externally and will proxy requests to Tailscale's control plane.

## Installation

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

## Configuration Options

| Flag | Description | Default | Required |
|------|-------------|---------|----------|
| `--domain` | Your custom domain name | - | Yes |
| `--email` | Email for Let's Encrypt registration | - | Yes (when --issue=true) |
| `--cert-dir` | Directory for SSL certificates | - | Yes |
| `--issue` | Auto-issue Let's Encrypt certificates | `true` | No |
| `--port` | HTTP port for Let's Encrypt challenges | `80` | No |
| `--https-port` | HTTPS port for the proxy | `443` | No |
| `--debug` | Enable debug logging | `false` | No |

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
