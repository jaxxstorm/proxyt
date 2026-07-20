# Hosting

Railway is by far the easiest way to deploy Proxyt. It's preconfigured, and provides a valid domain and certificate for you.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.app/template/proxyt?referralCode=ftkvtR)

# Deployment Scenarios

## Standalone with Let's Encrypt (Default)

Direct deployment with automatic certificate management:

```bash
proxyt serve --domain proxy.example.com --email admin@example.com --cert-dir /etc/proxyt/certs
```

**Requirements:**
- Domain points to your server
- Ports 80 and 443 accessible from internet
- Valid email for Let's Encrypt

## Behind Tailscale Funnel

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


## Behind Pangolin or Similar Proxy

When using a service that provides TLS termination:

```bash
proxyt serve --domain proxy.example.com --http-only --port 3000
```

Then configure your proxy to forward `https://proxy.example.com` to `http://localhost:3000`.

## Behind Traditional Reverse Proxy (Nginx/Apache)

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

## Docker Deployment

### Standalone with Let's Encrypt

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

### Behind Reverse Proxy

```bash
docker run -d \
  --name proxyt \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/jaxxstorm/proxyt:latest \
  serve --domain proxy.example.com --http-only --port 8080 --bind 0.0.0.0
```

## High Availability

Proxyt can run in a simple HA shape without Redis or another external coordination service. In HA mode, proxyt issues its own signed session cookie and any replica with the same public domain and shared secret can validate it.

The recommended deployment model is:

- run proxyt with `--http-only`
- terminate TLS at your load balancer, ingress controller, or reverse proxy
- route one public DNS name to multiple proxyt instances
- configure the same `--ha-secret` on every replica

### Kubernetes

Typical Kubernetes deployment shape:

- an `Ingress` or `LoadBalancer` terminates TLS for `proxy.example.com`
- a `Deployment` runs multiple proxyt pods
- every pod receives the same `PROXYT_HA=true` and `PROXYT_HA_SECRET=...`
- traffic is forwarded to proxyt with `X-Forwarded-Proto: https`

Example container args:

```bash
proxyt serve \
  --domain proxy.example.com \
  --http-only \
  --port 8080 \
  --ha \
  --ha-secret "${PROXYT_HA_SECRET}"
```

### Docker or Compose

Run multiple containers behind a reverse proxy such as Caddy, Traefik, or Nginx and provide the same HA secret to each container:

```yaml
version: '3.8'
services:
  proxyt-a:
    image: ghcr.io/jaxxstorm/proxyt:latest
    command: serve --domain proxy.example.com --http-only --port 8080 --ha --ha-secret ${PROXYT_HA_SECRET}
  proxyt-b:
    image: ghcr.io/jaxxstorm/proxyt:latest
    command: serve --domain proxy.example.com --http-only --port 8080 --ha --ha-secret ${PROXYT_HA_SECRET}
```

### Other environments

The same pattern applies elsewhere:

- one shared public DNS name
- one shared HA secret
- external TLS termination preferred
- multiple proxyt instances behind the same frontend

### HA limitations

The stateless HA model is portable, but it has explicit limits:

- active `/ts2021` upgraded connections are not handed off between replicas mid-stream
- rotating the shared secret invalidates active proxyt HA continuity cookies
- proxyt does not provide strong server-side session revocation in this mode
- built-in Let's Encrypt issuance is not the recommended multi-replica path; external TLS termination is simpler and more predictable

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
