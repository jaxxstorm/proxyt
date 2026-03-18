## ADDED Requirements

### Requirement: Deterministic Unit Coverage For Proxy Decisions

Proxyt MUST provide unit tests for deterministic proxy logic that does not require live Tailscale infrastructure.

#### Scenario: Route selection is validated

- **WHEN** `go test` runs the proxy unit test suite
- **THEN** it MUST verify that representative request paths, headers, and user agents route to the expected Tailscale upstream host
- **AND** regressions in route selection MUST fail the test suite

#### Scenario: URL rewrite helpers are validated

- **WHEN** `go test` runs the proxy unit test suite
- **THEN** it MUST verify that login and control-plane URLs are rewritten to the configured custom domain in headers and bodies
- **AND** non-matching content MUST remain unchanged

#### Scenario: Forwarded header behavior is validated

- **WHEN** proxyt is in HTTP-only mode under test
- **THEN** the unit test suite MUST verify how `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` are preserved or synthesized
- **AND** the tests MUST cover both pre-existing and missing forwarded headers

### Requirement: Integration Coverage For HTTP Proxy Flows

Proxyt MUST provide integration tests that exercise its HTTP proxy behavior against in-process fake upstream services.

#### Scenario: Health requests stay local

- **WHEN** an integration test sends a request to `/health`
- **THEN** proxyt MUST respond locally with HTTP 200
- **AND** it MUST NOT forward the request to an upstream service

#### Scenario: Proxied requests reach the expected upstream

- **WHEN** an integration test sends representative HTTP requests such as `/key`, `/api/...`, `/login`, or default web paths through proxyt
- **THEN** proxyt MUST forward the request to the expected fake upstream endpoint
- **AND** the integration test MUST verify the chosen upstream host and important forwarded request properties

#### Scenario: Response rewriting is preserved end to end

- **WHEN** a fake upstream responds with Tailscale URLs in headers or body content
- **THEN** proxyt MUST rewrite those URLs to the configured custom domain before returning the response
- **AND** the integration test MUST assert the rewritten response visible to the client

### Requirement: Control-Plane Upgrade Tests Use Local Seams

Proxyt MUST make the `/ts2021` control-plane handler testable without requiring live network access to `controlplane.tailscale.com`.

#### Scenario: Upgrade backend can be faked in tests

- **WHEN** integration or focused handler tests exercise `/ts2021`
- **THEN** proxyt MUST allow the backend dial or handler construction path to be replaced with a local fake during tests
- **AND** the production path MUST continue to use the real control-plane target outside tests
