## Context

The current proxy behavior lives almost entirely inside [`cmd/serve.go`](/home/lbriggs/src/github/jaxxstorm/proxyt/cmd/serve.go). A few helper functions such as `getTailscaleTarget`, `rewriteTailscaleURL`, `rewriteTailscaleURLsInBody`, and `setupXForwardedHeaders` are already pure enough for straightforward unit tests, but the main handler wiring and `/ts2021` control-plane path are tightly coupled to runtime globals and real network calls. There is currently only logger coverage in [`cmd/logging_test.go`](/home/lbriggs/src/github/jaxxstorm/proxyt/cmd/logging_test.go), so the core proxy contract is largely untested.

## Goals / Non-Goals

**Goals:**

- Add meaningful automated coverage for the core proxy contract.
- Keep all new tests runnable under `go test ./...` without live Tailscale dependencies.
- Introduce only the smallest production seams needed to test handler behavior end to end.
- Cover both deterministic helper behavior and realistic HTTP proxy flows.

**Non-Goals:**

- End-to-end testing against the real Tailscale control plane.
- Large architectural changes unrelated to testability.
- Full system or container orchestration tests in this change.

## Decisions

### Decision 1: Start with pure helper unit tests

The first layer of coverage should target the deterministic helpers that already exist:

- `getTailscaleTarget`
- `rewriteTailscaleURL`
- `rewriteTailscaleURLsInBody`
- `setupXForwardedHeaders`

These tests provide quick confidence in routing and rewrite behavior without forcing production refactors first.

### Decision 2: Extract a testable HTTP handler builder

To cover health handling, reverse proxy forwarding, and response rewriting end to end, proxyt should expose a small handler-construction seam rather than testing `runProxy` directly. A helper that builds the main HTTP handler and reverse proxy from explicit dependencies will let integration tests drive requests through proxyt with `httptest` while production still calls the same logic.

The seam should remain narrow: enough to inject the selected upstream transport or proxy target mapping for tests, but not a full framework or major redesign.

### Decision 3: Make `/ts2021` backend dialing injectable

The `/ts2021` handler currently calls `tls.Dial` directly against `controlplane.tailscale.com:443`, which prevents deterministic tests. Introduce a narrow package-level variable or helper for backend dialing so tests can replace it with an in-process TLS server or fake connection while production continues to use the real dial path.

This is the minimum change needed to validate the control-plane upgrade flow without external dependencies.

### Decision 4: Use standard-library integration tests first

Use `net/http/httptest`, `net`, and `crypto/tls` from the standard library for integration coverage wherever possible. That keeps the test harness lightweight and reduces long-term maintenance compared to heavier external test frameworks.

## Affected Components

- `cmd/serve.go`
- New or expanded `cmd/serve_test.go` and related test files
- Potential small helper extraction files in `cmd/`
- `go.mod` only if additional test dependencies become necessary

## Migration Concerns

- The current code relies on package-level globals such as `domain`, `httpOnly`, `debug`, and `logger`, so tests must either restore global state carefully or drive behavior through newly extracted helper inputs.
- Refactors for testability must not accidentally change runtime routing or TLS behavior.
- `/ts2021` coverage is valuable but riskier than pure HTTP flows, so the change should land deterministic seams before deep protocol assertions.

## Verification Plan

- Add table-driven unit tests for routing, URL rewriting, and forwarded headers.
- Add `httptest`-based integration coverage for health, proxied HTTP requests, and response rewriting through the main handler.
- Add focused tests for `/ts2021` once backend dialing can be replaced locally.
- Run `go test ./...` as the verification baseline.
