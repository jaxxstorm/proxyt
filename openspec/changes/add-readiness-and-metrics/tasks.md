## 1. Runtime Observability Foundation

- [x] 1.1 Add the Prometheus Go client dependency and a handler-local metrics registry with bounded request, upstream-error, certificate-expiry, and active-tunnel collectors.
- [x] 1.2 Add response-status and duration instrumentation that preserves HTTP hijacking for `/ts2021`.

## 2. Health And Readiness Endpoints

- [x] 2.1 Wire TLS certificate inspection for manual and ACME-managed certificates, treating HTTP-only mode as externally terminated TLS.
- [x] 2.2 Add `/ready` with a bounded control-plane connectivity check and keep `/health` upstream-independent.
- [x] 2.3 Expose the handler-local Prometheus registry at `/metrics` and instrument reverse-proxy and `/ts2021` upstream errors and active tunnels.

## 3. Tests And Documentation

- [x] 3.1 Add local tests for liveness, readiness success and failure, Prometheus request/error/certificate metrics, and active `/ts2021` tunnel tracking.
- [x] 3.2 Document liveness, readiness, metrics, metric behavior, and HTTP-only certificate semantics in the hosting guide.

## 4. Verification

- [x] 4.1 Run `gofmt -w cmd/serve.go cmd/serve_test.go`, `go test ./...`, and `go build ./...`.
