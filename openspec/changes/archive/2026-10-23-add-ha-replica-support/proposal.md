## Why

ProxyT can distribute new connections across independent replicas, but its current HTTP shutdown does not manage hijacked tunnels and externally supplied certificates are loaded only at startup. Reliable container and Kubernetes operation requires bounded connection lifecycles, shutdown-aware readiness, and certificate rotation without restarting healthy replicas.

## What Changes

- ProxyT SHALL manage an idempotent serving-to-draining-to-stopped lifecycle, reject new proxy work during drain, and close remaining connections within configured shutdown bounds.
- ProxyT SHALL track in-progress upgrades and established tunnels so shutdown cannot lose connections during hijack transitions. Existing opaque streams SHALL remain usable until completion or the drain deadline.
- Control-protocol establishment SHALL have a configurable deadline covering dial, TLS handshake, request forwarding, and response headers. Failed requests SHALL NOT be replayed; clients reconnect to any healthy replica.
- Readiness SHALL include lifecycle state, while liveness remains independent of upstream availability. Lifecycle transitions, forced closures, and certificate reload outcomes SHALL be observable without recording payloads, keys, or unbounded identifiers.
- Externally managed certificates SHALL reload atomically from mounted files. Invalid replacement files SHALL retain the last valid loaded pair and be retried on subsequent polls; invalid initial files SHALL prevent startup. Expiry of the active certificate SHALL make the replica unready.
- **BREAKING**: Manual-certificate startup SHALL reject expired, not-yet-valid, and wrong-host certificates rather than opening listeners with them; deployments must supply a currently valid certificate for the configured domain.
- New duration settings SHALL follow the existing flag/environment/YAML precedence and be validated before serving. Existing direct, HTTP-only, and automatic-certificate modes SHALL remain available.
- The runtime SHALL remain cloud-provider agnostic. Compatible TCP/TLS passthrough or upgrade-preserving HTTP frontends are required; arbitrary HTTP edges cannot be made compatible inside ProxyT.
- DigitalOcean/DOKS deployment manifests, cloud validation, and deployment documentation are deferred to a separate change. This change includes hermetic product tests.

## Capabilities

### New Capabilities
- `replica-lifecycle`: Independent replicas, idempotent draining, explicit connection ownership, and bounded shutdown.
- `external-certificate-reload`: Atomic reload and last-known-good recovery for externally supplied TLS certificates.

### Modified Capabilities
- `control-plane-upgrade-tunneling`: Bounded, cancelable establishment without retries or deadlines leaking into established tunnels.
- `runtime-observability`: Lifecycle-aware readiness, current certificate visibility, and bounded lifecycle/reload metrics and logs.
- `configuration-file`: Duration configuration and validation for shutdown, establishment, and certificate polling.

## Impact

Affected areas include `cmd/serve.go`, serve configuration bindings, TLS certificate loading, signal handling, metrics, and focused runtime helpers and tests in `cmd/`. No distributed state store, leader election, cloud SDK, Noise termination, or proprietary Tailscale implementation is required. All implementation will be original and use public Go interfaces; internal source inspection informs architectural understanding only.

Recovery is connection-scoped: broken tunnels require client reconnection, never transparent migration or replay. Repeated drain requests are no-ops after the first transition and MUST NOT extend shutdown deadlines. Repeated certificate polls are safe and only replace active state after a complete valid pair is available.

Verification prioritizes deterministic unit tests for lifecycle transitions, configuration precedence, certificate validation, and metrics. Hermetic socket/TLS tests will cover active-tunnel survival during drain, forced closure, stalled setup, concurrent hijack/shutdown races, byte preservation, and certificate rotation on new handshakes. Run the existing suite and race detector; actual cloud deployment testing belongs to the follow-up change.
