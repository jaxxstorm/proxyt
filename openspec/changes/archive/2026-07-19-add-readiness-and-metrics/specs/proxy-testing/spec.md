## ADDED Requirements

### Requirement: Runtime observability uses local test seams

Proxyt MUST provide deterministic local tests for readiness and Prometheus endpoint behavior without requiring live Tailscale infrastructure.

#### Scenario: Readiness dependencies are faked
- **WHEN** tests exercise `/ready`
- **THEN** they MUST be able to supply local successful and failing control-plane dependencies

#### Scenario: Metrics are asserted locally
- **WHEN** tests send representative requests through a locally constructed ProxyT handler
- **THEN** they MUST assert the expected Prometheus metric output without relying on process-global collectors
