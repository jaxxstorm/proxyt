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

## Request Routing Logic

- **Control Protocol** (`/ts2021`): Custom protocol upgrade handler for Tailscale's control protocol
- **Key Exchange** (`/key`): Routes to `controlplane.tailscale.com`
- **API Endpoints** (`/api/*`, `/machine/*`): Routes to `controlplane.tailscale.com`
- **DERP Traffic** (`/derp/*`): Routes to `derp.tailscale.com`
- **Authentication** (`/login`, `/auth`, `/a/*`): Routes to `login.tailscale.com`
- **Default/Web**: Routes to `login.tailscale.com`

## High Availability Model

Proxyt's HA support is intentionally stateless.

- Proxyt issues its own signed session continuity cookie for the public proxy domain.
- Any replica with the same configured `--domain` and `--ha-secret` can validate that cookie.
- Proxyt strips its own HA cookie before forwarding requests upstream, so Tailscale does not see proxyt-specific session state.
- Response rewriting continues to keep redirects, rewritten URLs, and rewritten cookie domains on the public proxyt domain.

This keeps HA support portable across Kubernetes, Docker, and other platforms without requiring Redis or another external session store.

### HA boundaries

- HA continuity applies to new or resumed HTTP requests that can be revalidated by another replica.
- An active `/ts2021` upgraded connection stays attached to the replica that accepted it until that connection closes.
- If the shared HA secret changes, existing proxyt HA continuity cookies become invalid and clients will need to establish a new proxyt session.

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
