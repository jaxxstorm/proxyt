## Why

Proxyt currently has very little automated coverage around the code that actually decides where requests go, rewrites Tailscale URLs, preserves forwarded headers, and handles the `/ts2021` control-plane upgrade path. That makes it hard to prove the proxy still behaves correctly as routing logic evolves, and it leaves regressions detectable only through manual testing against live Tailscale endpoints.

## What Changes

- Add unit tests for the current pure proxy helpers and routing decisions.
- Add integration-style tests that exercise proxyt handlers against fake upstream services instead of the live Tailscale control plane.
- Introduce the minimum test seams needed to build proxy handlers and protocol-upgrade behavior without opening real external network connections.
- Keep the production proxy behavior unchanged while making it observable and repeatable under `go test`.

## Capabilities

### New Capabilities

- `proxy-testing`: Proxyt can be validated with automated unit and integration tests that prove request routing, response rewriting, forwarded-header behavior, and selected control-plane proxy flows.

## Behavior

- Proxyt MUST have unit tests covering request target selection, URL rewriting, and forwarded-header setup.
- Proxyt MUST have integration tests that verify proxied HTTP requests reach the expected fake upstream service and preserve or rewrite key request and response details.
- Automated tests MUST run without requiring access to live Tailscale infrastructure.
- The new test harness MUST preserve the existing runtime behavior of proxyt in production code paths.

## Idempotency And Retry Semantics

- Running the new unit and integration tests repeatedly on the same source tree MUST produce consistent results without relying on external service state.
- Integration tests MUST create and clean up their own in-process servers and temporary resources on each run.
- Test helpers MAY retry transient in-process startup synchronization, but MUST NOT hide assertion failures behind broad retries.

## Failure Modes And Recovery

- If a routing rule regresses, the relevant unit or integration test MUST fail with enough context to identify the mismatched target or rewritten value.
- If a protocol-upgrade flow cannot be tested with the current code structure, proxyt MUST first expose a narrow seam for backend dialing or handler construction rather than skipping coverage entirely.
- If a test requires behavior that cannot be made deterministic without calling the live Tailscale control plane, that behavior MUST be documented as out of scope for this change instead of being approximated silently.

## Observability And Audit

- Test failures SHOULD make it clear which route, header, or response rewrite behavior regressed.
- Integration coverage SHOULD include assertions for the observable proxy contract, such as upstream host selection, forwarded headers, health responses, and URL rewrite results.
- The test suite SHOULD be runnable with the normal `go test ./...` workflow used by contributors and CI.

## Test Plan Summary

- Prioritize unit tests for `getTailscaleTarget`, `rewriteTailscaleURL`, `rewriteTailscaleURLsInBody`, and `setupXForwardedHeaders`.
- Add integration tests using `httptest` servers to verify proxied request routing and rewritten responses without external dependencies.
- Add targeted coverage for the `/ts2021` handler only after introducing a deterministic seam for backend dialing or handler construction.

## Impact

- `cmd/serve.go`: extract or expose minimal seams needed to test handlers without changing production behavior.
- `cmd/*_test.go`: add unit and integration tests for routing, rewriting, health, and selected proxy flows.
- `go.mod`: only if additional test-only dependencies become necessary.
- Contributor workflow and CI: benefit from automated verification of core proxy behavior.
