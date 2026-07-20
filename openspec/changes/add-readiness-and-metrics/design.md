## Context

ProxyT exposes only `/health`, which returns success without contacting any upstream or inspecting TLS state. The HTTP handler owns both ordinary reverse-proxy requests and the long-lived `/ts2021` tunnel, so it is the natural place to expose request and tunnel metrics.

## Goals / Non-Goals

**Goals:**
- Keep liveness independent of Tailscale and certificate state.
- Make readiness depend on one bounded control-plane connectivity check and ProxyT-owned certificate validity.
- Expose Prometheus metrics without global registration conflicts between handler tests.
- Keep labels bounded and avoid tunnel payload inspection.

**Non-Goals:**
- Check client authentication, DERP reachability, or each routed Tailscale host.
- Manage certificates owned by a reverse proxy in HTTP-only mode.
- Add a separate metrics listener, authentication, tracing, or alert rules.

## Decisions

### Keep observability state local to each handler

`buildMainHandler` will create an observability bundle containing a dedicated Prometheus registry, collectors, and readiness dependencies. This prevents duplicate global collector registration when tests create multiple handlers and exposes `/metrics` through the same listener as the proxy.

Alternative considered: use the default Prometheus registry. It is simpler in production but causes cross-test collector conflicts and makes metric assertions depend on global process state.

### Define readiness as control-plane reachability plus managed certificate validity

`/ready` will perform one context-bounded HTTP request to `controlplane.tailscale.com`; receiving any HTTP response proves network/TLS connectivity, while a transport error produces HTTP 503. When ProxyT terminates TLS, it will obtain its configured certificate and reject absent, unparsable, or expired certificates. In HTTP-only mode, certificate readiness succeeds because TLS is intentionally owned by the fronting proxy.

Alternative considered: only validate configuration at startup. This cannot detect a later-expired manual certificate or a managed certificate that has not been obtained.

### Use bounded metric labels and direct instrumentation

Request counters and duration histograms will use method, route, and status labels, where routes are a fixed endpoint name or routed upstream host rather than unbounded URL paths. The reverse proxy and `/ts2021` handler will increment an upstream-error counter on transport failures. The active-tunnel gauge increments only after a successful `101` handoff and decrements when the tunnel finishes. Certificate expiry is published as a Unix timestamp only when ProxyT owns a valid local certificate.

Alternative considered: label metrics by raw request path or client address. These values create unbounded cardinality and are unsuitable for a public proxy.

## Risks / Trade-offs

- [Readiness probes add upstream traffic] -> Use a single lightweight request with a short timeout and no internal retries.
- [Automatic certificate lookup can contact ACME] -> Reuse the configured certificate getter and fail readiness rather than claiming TLS is ready when no certificate can be supplied.
- [Metrics shares the public proxy listener] -> Document that deployments needing access restriction must enforce it at the network or fronting-proxy layer.
- [Tunnel completion closes either direction] -> Retain the existing lifecycle and only observe its active duration.

## Migration Plan

The new paths are additive. Deploy the binary, configure liveness probes to use `/health`, readiness probes to use `/ready`, and scrape `/metrics`; roll back by restoring the previous binary and probes. No data migration is required.

## Open Questions

None.
