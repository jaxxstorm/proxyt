## ADDED Requirements

### Requirement: Liveness remains local

Proxyt MUST continue to expose `/health` as an upstream-independent liveness endpoint.

#### Scenario: Upstream is unavailable
- **WHEN** the control-plane upstream cannot be reached
- **THEN** `/health` MUST return HTTP 200

### Requirement: Readiness verifies serving dependencies

Proxyt MUST expose `/ready` and return HTTP 200 only when the runtime is serving, a bounded request can reach the control-plane upstream, and any certificate terminated by Proxyt is present and currently valid. In HTTP-only mode, `/ready` MUST not evaluate a certificate owned by the external TLS terminator. While draining, readiness MUST return HTTP 503 without starting a dependency check. A check already in progress MUST recheck lifecycle state before reporting success. External-certificate readiness MUST evaluate the active loaded snapshot rather than a startup snapshot or replacement files not yet published.

#### Scenario: Dependencies are ready
- **WHEN** the runtime is serving, the control plane is reachable, and Proxyt-managed TLS has a valid certificate, or the serving runtime is in HTTP-only mode with a reachable control plane
- **THEN** `/ready` MUST return HTTP 200

#### Scenario: Control plane is unavailable
- **WHEN** the bounded control-plane request fails
- **THEN** `/ready` MUST return HTTP 503

#### Scenario: Managed certificate is not ready
- **WHEN** Proxyt terminates TLS and its active certificate is missing, unparsable, expired, or not yet valid
- **THEN** `/ready` MUST return HTTP 503

#### Scenario: Runtime is draining
- **WHEN** a readiness request arrives after drain entry
- **THEN** `/ready` MUST return HTTP 503 without an upstream request
- **AND** `/health` MUST continue returning HTTP 200 while its listener remains open

#### Scenario: Drain starts during a readiness check
- **WHEN** a dependency check succeeds but the runtime has entered draining before the final lifecycle check
- **THEN** `/ready` MUST return HTTP 503

### Requirement: Prometheus metrics are exposed

Proxyt MUST expose Prometheus-format metrics at `/metrics` for request count, request duration, request status, upstream errors, locally managed certificate expiry, and active `/ts2021` tunnels. Request labels MUST use bounded route values rather than raw request paths, and tunnel payloads MUST NOT be recorded. Certificate expiry MUST describe the active certificate snapshot, including its expiry timestamp after that certificate expires.

#### Scenario: Metrics describe handled traffic
- **WHEN** ProxyT handles an HTTP request or an upstream failure
- **THEN** `/metrics` MUST expose the corresponding request or upstream-error metric with bounded labels

#### Scenario: Active tunnel is tracked
- **WHEN** a `/ts2021` request receives `101 Switching Protocols`
- **THEN** the active-tunnel metric MUST increment for the tunnel lifetime and decrement when the tunnel ends

#### Scenario: Managed certificate expiry is available
- **WHEN** ProxyT terminates TLS with a loaded parseable certificate
- **THEN** `/metrics` MUST expose that active certificate's expiry as a Unix timestamp in seconds, even if it has expired

### Requirement: Replica lifecycle and reload outcomes are observable

ProxyT MUST expose `proxyt_draining` as 0 while serving and 1 after drain begins, `proxyt_shutdown_forced_tunnels_total` counting established tunnels forcibly closed by shutdown once per tunnel, and `proxyt_certificate_reload_total` with only `success` and `error` result labels. Reload success MUST count changed-certificate publication, not unchanged polling; error MUST count failed reload attempts. Structured logs MUST describe lifecycle transitions, shutdown timing and summary counts, and certificate reload failures and recovery without payloads or private keys. Repeated identical reload-error logs MUST be bounded by transition-based reporting or rate limiting.

#### Scenario: Drain forces a tunnel closed
- **WHEN** a tunnel remains open at the drain deadline and is forcibly closed
- **THEN** the draining gauge MUST be 1 and the forced-tunnel counter MUST increment once for that tunnel
- **AND** lifecycle logs MUST identify the shutdown transition and forced cleanup summary

#### Scenario: Certificate reload fails then succeeds
- **WHEN** a failed replacement attempt is followed by a valid changed pair
- **THEN** reload metrics MUST record one error and one success for those attempts and structured logs MUST report failure and recovery

#### Scenario: Repeated failure or unchanged content
- **WHEN** repeated polls encounter the same invalid replacement or unchanged valid content
- **THEN** failures MUST remain counted without unbounded repeated log messages, and unchanged valid content MUST NOT increment reload success
