# Architecture

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

## Encryption boundaries

ProxyT terminates the outer TLS connection and opens a separate TLS connection
to Tailscale. In HTTP-only mode the frontend handles incoming TLS instead.
After the `/ts2021` upgrade, the inner Noise session remains end-to-end between
the client and Tailscale; ProxyT relays its encrypted bytes without decrypting
the control payload.

```text
Outer TLS:  client <----> ProxyT <----> Tailscale
Inner Noise: client <----------------> Tailscale
```

This opacity applies to the upgraded Noise stream, not ordinary browser/API
HTTP traffic. ProxyT can inspect or rewrite ordinary HTTP requests and responses.

## Request Routing Logic

- **Control Protocol** (`/ts2021`): Custom protocol upgrade handler for Tailscale's control protocol
- **Key Exchange** (`/key`): Routes to `controlplane.tailscale.com`
- **API Endpoints** (`/api/*`, `/machine/*`): Routes to `controlplane.tailscale.com`
- **DERP Traffic** (`/derp/*`): Routes to `derp.tailscale.com`
- **Authentication** (`/login`, `/auth`, `/a/*`): Routes to `login.tailscale.com`
- **Default/Web**: Routes to `login.tailscale.com`

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
