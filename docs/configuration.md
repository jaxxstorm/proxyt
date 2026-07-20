# Configuration

Once you have installed proxyt, you can either run it directly, or host it behind a reverse proxy.

Proxyt can handle issuing a valid certificate for you via Let's Encrypt - for this to work correctly, you'll need a valid DNS entry pointing to your `domain`

## Configuration Options

All flags can be set via environment variables with the `PROXYT_` prefix (e.g., `PROXYT_DOMAIN`, `PROXYT_HTTP_ONLY`).

| Flag | Environment Variable | Description | Default | Required |
|------|---------------------|-------------|---------|----------|
| `--domain` | `PROXYT_DOMAIN` | Your custom domain name | - | Yes |
| `--email` | `PROXYT_EMAIL` | Email for Let's Encrypt registration | - | Yes (when --issue=true) |
| `--cert-dir` | `PROXYT_CERT_DIR` | Directory for SSL certificates | - | Yes (when not --http-only) |
| `--issue` | `PROXYT_ISSUE` | Auto-issue Let's Encrypt certificates | `true` | No |
| `--port` | `PROXYT_PORT` | HTTP port for challenges or main port in HTTP-only mode | `80` | No |
| `--https-port` | `PROXYT_HTTPS_PORT` | HTTPS port for the proxy | `443` | No |
| `--debug` | `PROXYT_DEBUG` | Enable debug logging | `false` | No |
| `--http-only` | `PROXYT_HTTP_ONLY` | Run behind HTTPS proxy (no TLS termination) | `false` | No |
| `--bind` | `PROXYT_BIND` | Address to bind the server to | `0.0.0.0` | No |
| `--ha` | `PROXYT_HA` | Enable stateless HA session continuity across replicas | `false` | No |
| `--ha-secret` | `PROXYT_HA_SECRET` | Shared secret used to sign proxyt HA session cookies | - | Yes (when `--ha=true`) |
| `--ha-cookie-name` | `PROXYT_HA_COOKIE_NAME` | Cookie name used for proxyt HA session continuity | `__Host-proxyt-ha` | No |
| `--ha-cookie-ttl` | `PROXYT_HA_COOKIE_TTL` | Lifetime for proxyt HA session continuity cookies | `12h` | No |

## High Availability Configuration

Proxyt's HA mode is opt-in. When enabled, proxyt issues its own signed, stateless session cookie so multiple replicas behind the same public DNS name can validate and continue the same browser-facing flow without a shared database or cache.

Minimum HA configuration:

```bash
proxyt serve \
  --domain proxy.example.com \
  --http-only \
  --port 8080 \
  --ha \
  --ha-secret "replace-with-a-long-random-shared-secret"
```

All replicas in the same HA deployment must use:

- the same `--domain`
- the same `--ha-secret`
- the same externally visible DNS name

Recommended defaults:

- Keep `--ha-cookie-name` at the default unless you have a strong reason to change it.
- Use a long random `--ha-secret` with at least 32 characters.
- Prefer `--http-only` behind a load balancer or reverse proxy that terminates TLS for the shared public domain.

### HA limitations

HA mode is intentionally stateless, which keeps deployment simple but comes with boundaries:

- active `/ts2021` upgraded connections stay on the instance that accepted them
- rotating `--ha-secret` invalidates existing proxyt HA continuity cookies
- server-side revocation is limited because proxyt does not keep an external session store in this mode
- continuity data must stay small enough to fit in proxyt's signed cookie

## Docker

### Run with automatic certificates (requires volumes for certificate storage)

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
```

```bash
docker compose up -d
```
