## ADDED Requirements

### Requirement: Liveness remains local

Proxyt MUST continue to expose `/health` as an upstream-independent liveness endpoint.

#### Scenario: Upstream is unavailable
- **WHEN** the control-plane upstream cannot be reached
- **THEN** `/health` MUST return HTTP 200

### Requirement: Readiness verifies serving dependencies

Proxyt MUST expose `/ready` and return HTTP 200 only when a bounded request can reach the control-plane upstream and any certificate terminated by Proxyt is present and currently valid. In HTTP-only mode, `/ready` MUST not evaluate a certificate owned by the external TLS terminator.

#### Scenario: Dependencies are ready
- **WHEN** the control plane is reachable and Proxyt-managed TLS has a valid certificate, or ProxyT is in HTTP-only mode
- **THEN** `/ready` MUST return HTTP 200

#### Scenario: Control plane is unavailable
- **WHEN** the bounded control-plane request fails
- **THEN** `/ready` MUST return HTTP 503

#### Scenario: Managed certificate is not ready
- **WHEN** Proxyt terminates TLS and its certificate is missing, unparsable, or expired
- **THEN** `/ready` MUST return HTTP 503

### Requirement: Prometheus metrics are exposed

Proxyt MUST expose Prometheus-format metrics at `/metrics` for request count, request duration, request status, upstream errors, locally managed certificate expiry, and active `/ts2021` tunnels. Request labels MUST use bounded route values rather than raw request paths, and tunnel payloads MUST NOT be recorded.

#### Scenario: Metrics describe handled traffic
- **WHEN** ProxyT handles an HTTP request or an upstream failure
- **THEN** `/metrics` MUST expose the corresponding request or upstream-error metric with bounded labels

#### Scenario: Active tunnel is tracked
- **WHEN** a `/ts2021` request receives `101 Switching Protocols`
- **THEN** the active-tunnel metric MUST increment for the tunnel lifetime and decrement when the tunnel ends

#### Scenario: Managed certificate expiry is available
- **WHEN** ProxyT terminates TLS with a valid certificate
- **THEN** `/metrics` MUST expose that certificate's expiry as a Unix timestamp in seconds
