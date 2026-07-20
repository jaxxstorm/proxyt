## Why

`/health` only confirms that ProxyT's HTTP server is running, so orchestrators cannot distinguish a live process from one unable to serve Tailscale traffic. Operators also lack machine-readable visibility into proxy traffic, upstream failures, certificate lifetime, and active control-protocol tunnels.

## What Changes

- Retain `/health` as an upstream-independent liveness endpoint.
- Add `/ready`, which returns success only when the control-plane upstream is reachable and ProxyT-managed TLS has a currently valid certificate; HTTP-only deployments delegate certificate readiness to their TLS terminator.
- Add a Prometheus `/metrics` endpoint exposing request totals, request duration and status, upstream failures, locally managed certificate expiry, and active `/ts2021` tunnels.
- Instrument reverse-proxy and `/ts2021` upstream failures without logging tunnel payloads.
- Add deterministic local tests and monitoring documentation for the new endpoints and metrics.
- Readiness checks perform one bounded request per probe and do not retry internally; probes may retry according to their own policy.

## Capabilities

### New Capabilities
- `runtime-observability`: Liveness, readiness, and Prometheus telemetry for ProxyT runtime health and traffic.

### Modified Capabilities
- `proxy-testing`: Requires deterministic local coverage for readiness and Prometheus endpoint behavior.

## Impact

- Affects request handling and startup wiring in `cmd/serve.go`, tests in `cmd/serve_test.go`, `go.mod` and `go.sum`, and monitoring documentation in `docs/hosting.md`.
- Adds the Prometheus Go client dependency and the public `/ready` and `/metrics` HTTP endpoints.
