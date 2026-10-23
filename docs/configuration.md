# Configuration

Once you have installed proxyt, you can either run it directly, or host it behind a reverse proxy.

Proxyt can handle issuing a valid certificate for you via Let's Encrypt - for this to work correctly, you'll need a valid DNS entry pointing to your `domain`

## Configuration Options

All flags can be set via environment variables with the `PROXYT_` prefix (e.g., `PROXYT_DOMAIN`, `PROXYT_HTTP_ONLY`).

## YAML Configuration

ProxyT loads YAML settings from `--config /path/to/proxyt.yaml`. If `--config` is omitted, it loads `$HOME/.proxyt.yaml` when that file exists; no file is required for flag-only or environment-only deployments.

Configuration precedence is: changed command flags, `PROXYT_*` environment variables, YAML values, then built-in defaults. An explicitly supplied missing, unreadable, or malformed `--config` file stops startup with an error.

YAML keys match the flag names without the leading `--`:

```yaml
domain: proxy.example.com
email: admin@example.com
cert-dir: /etc/proxyt/certs
issue: true
port: "80"
https-port: "443"
bind: 0.0.0.0
debug: false
http-only: false
```

ProxyT validates the final values after precedence is applied. When using automatic certificate issuance, `domain` and `email` are required. Manual TLS also needs `domain` to locate and validate its certificate. `cert-dir` is required unless `http-only` is true. See [compatibility and upgrade notes](upgrading.md) for the 0.1.0 changes and planned stable interfaces.

| Flag | Environment Variable | Description | Default | Required |
|------|---------------------|-------------|---------|----------|
| `--domain` | `PROXYT_DOMAIN` | Your custom domain name | - | Required for automatic issuance and manual certificate hostname validation; optional in HTTP-only mode |
| `--email` | `PROXYT_EMAIL` | Email for Let's Encrypt registration | - | Yes (when --issue=true) |
| `--cert-dir` | `PROXYT_CERT_DIR` | Directory for SSL certificates | - | Yes (when not --http-only) |
| `--issue` | `PROXYT_ISSUE` | Auto-issue Let's Encrypt certificates | `true` | No |
| `--port` | `PROXYT_PORT` | HTTP port for challenges or main port in HTTP-only mode | `80` | No |
| `--https-port` | `PROXYT_HTTPS_PORT` | HTTPS port for the proxy | `443` | No |
| `--debug` | `PROXYT_DEBUG` | Enable debug logging | `false` | No |
| `--http-only` | `PROXYT_HTTP_ONLY` | Run behind HTTPS proxy (no TLS termination) | `false` | No |
| `--bind` | `PROXYT_BIND` | Address to bind the server to | `0.0.0.0` | No |
| `--shutdown-delay` | `PROXYT_SHUTDOWN_DELAY` | Routing propagation delay before listener shutdown | `5s` | No |
| `--shutdown-timeout` | `PROXYT_SHUTDOWN_TIMEOUT` | Shared request/tunnel drain budget after the delay | `25s` | No |
| `--upstream-connect-timeout` | `PROXYT_UPSTREAM_CONNECT_TIMEOUT` | Entire `/ts2021` upstream setup: dial, TLS handshake, request write, and response headers | `10s` | No |
| `--cert-reload-interval` | `PROXYT_CERT_RELOAD_INTERVAL` | External TLS certificate polling interval | `30s` | No |

Durations use Go duration syntax, such as `500ms` or `30s`. Only
`shutdown-delay` permits zero; all other durations must be positive. Invalid or
overflowing values fail startup. The upstream setup timeout does not limit an
established tunnel's lifetime. Certificate polling applies to TLS mode with
`--issue=false`.

For multiple instances, load-balancer requirements, certificate distribution,
and shutdown budgeting, see [High Availability](high-availability.md).

## Docker

### Run with automatic certificates (requires volumes for certificate storage)

Prepare the volume once for the release image's non-root user (also required
before the Compose example below):

```bash
docker volume create proxyt-certs
docker run --rm --user 0 -v proxyt-certs:/certs alpine:3 \
  sh -c 'chown 65532:65532 /certs && chmod 700 /certs'
```

For bind mounts, set equivalent ownership and permissions on the host. Manual
certificate mounts only need to be readable by UID 65532 and can be read-only.

```bash
docker run -d \
  --name proxyt \
  -p 80:80 \
  -p 443:443 \
  -v proxyt-certs:/certs \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --email admin@example.com --cert-dir /certs
```

### Run in HTTP-only mode (behind reverse proxy)

If you host your own reverse proxy, or you're using funnel to expose proxyt, you'll need to run proxyt in HTTP only mode\

```bash
docker run -d \
  --name proxyt \
  -p 8080:8080 \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --http-only --port 8080 --bind 0.0.0.0
```

### With Docker Compose
```yaml
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
    external: true
    name: proxyt-certs
```

```bash
docker compose up -d
```
