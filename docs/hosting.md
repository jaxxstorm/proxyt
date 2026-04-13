# Hosting

ProxyT works best when the frontend either terminates TLS directly on ProxyT or preserves arbitrary HTTP/1.1 upgrade requests all the way through to `/ts2021`.
## Compatibility Matrix

The Tailscale control protocol uses a non-standard upgrade flow on `/ts2021`. Some CDNs and managed reverse proxies only support standard WebSocket `GET` handshakes or specific upgrade tokens, which breaks login flows before the request reaches ProxyT.

| Frontend | Status | Notes |
| --- | --- | --- |
| Direct public host | Supported | Best option if you control ports 80/443 |
| Nginx / Apache / Caddy | Supported | Must preserve HTTP/1.1 upgrade semantics |
| Tailscale Funnel | Supported | Known-good path for exposing ProxyT |
| L4 TCP/TLS passthrough load balancer | Supported | Avoids HTTP upgrade rewriting at the edge |
| Railway / other managed HTTP edge proxies | Fragile / provider-dependent | Works only if the platform forwards `POST` upgrade requests unchanged |
| Cloudflare proxy / tunnel / workers | Not supported | Cloudflare does not support the Tailscale control protocol upgrade flow |
| AWS CloudFront | Not supported | CloudFront commonly drops or normalizes the `/ts2021` upgrade request |
| Fastly free tier | Not supported | Free-tier feature limits commonly block the required upgrade flow |

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

This only works when the proxy preserves `/ts2021` as an HTTP/1.1 upgrade request. If the provider rewrites or rejects `POST` upgrades, mobile and browser login will fail.

## Behind Traditional Reverse Proxy (Nginx/Apache)

```bash
proxyt serve --domain proxy.example.com --http-only --port 8080 --bind 127.0.0.1
```

**Nginx configuration example:**
```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

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
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;
    }
}
```

Important requirements for any reverse proxy:

- Preserve the original HTTP method for `/ts2021`
- Forward `Connection` and `Upgrade` headers unchanged
- Allow non-standard upgrade tokens used by the Tailscale client
- Do not force HTTP/2 or transform the request before it reaches ProxyT

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
