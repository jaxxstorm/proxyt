## Why

Proxyt currently behaves like a single-instance edge service. It can proxy requests statelessly, but it does not yet define how related login and control-plane HTTP requests should keep flowing correctly when multiple proxyt replicas sit behind one shared DNS name, and its current certificate flow is documented primarily around standalone deployments. That makes high-availability rollouts in Kubernetes, Docker, or other environments under-specified and risky, especially if operators want HA without introducing extra infrastructure.

## What Changes

- Add an explicit high-availability mode that uses a shared-secret, stateless session mechanism so related proxied requests can continue across replicas without an external coordination service.
- Introduce a client-visible session identifier scoped to the configured public domain while keeping internal instance details out of client-facing traffic.
- Preserve the existing single-instance behavior by making HA coordination opt-in through shared configuration.
- Expand documentation to explain supported HA deployment patterns for Kubernetes, Docker, and other environments, including TLS termination expectations and explicit operational caveats.

## Capabilities

### New Capabilities

- `high-availability`: Proxyt can run multiple instances behind the same DNS name while preserving session continuity for proxied HTTP flows through stateless shared-secret session data and documented deployment guidance.

## Behavior

- Proxyt MUST support an HA configuration that allows multiple instances to participate in the same client session flow without relying on per-process memory or an external session store.
- HA session continuity MUST use the configured public domain and MUST NOT expose internal pod, container, or node addresses to clients.
- Single-instance deployments MUST continue to work without requiring HA configuration.
- Documentation MUST explain how to deploy proxyt in HA mode on Kubernetes, Docker, or other reverse-proxy environments.
- Documentation MUST clarify the TLS and certificate expectations for HA deployments and the limitations of the stateless HA model, including active upgraded connections and session invalidation tradeoffs.

## Idempotency And Retry Semantics

- Repeated requests carrying the same valid HA session identifier MUST resolve consistently on any correctly configured replica until that identifier expires or is invalidated.
- Starting multiple proxyt instances with the same HA configuration MUST be safe and MUST NOT require manual session migration between replicas.
- Session creation and refresh logic SHOULD be safe to retry across replicas without creating conflicting client-visible state.

## Failure Modes And Recovery

- If HA mode is enabled but its required secret material is missing or invalid, proxyt MUST fail clearly rather than silently falling back to local-only behavior.
- If an HA session identifier expires, cannot be validated, or no longer contains usable continuity data, proxyt MUST create or negotiate a new session path in a controlled way and log enough context for troubleshooting.
- Active upgraded `/ts2021` connections MAY remain bound to the instance that accepted them; this change does not require live mid-stream connection transfer between replicas.

## Observability And Audit

- Proxyt SHOULD emit structured logs for HA session creation, validation, refresh, and signature or decode failures without leaking sensitive token material.
- Operators SHOULD be able to distinguish normal single-instance behavior from HA-enabled behavior through startup and runtime logs.
- Documentation SHOULD describe how to validate HA behavior and which symptoms indicate misconfiguration of the shared secret, cookie scope, or load balancer.

## Test Plan Summary

- Add focused unit tests for HA configuration parsing, session cookie handling, and signed or encrypted session payload validation behavior.
- Add integration coverage that exercises at least two proxyt handler instances sharing the same HA secret and verifies session continuity across replicas behind one public domain.
- Verify single-instance behavior remains unchanged when HA configuration is absent.
- Run `go test ./...` after implementation.

## Impact

- `cmd/serve.go`: wire HA configuration and session-aware request handling into the main proxy path.
- `cmd/`: add stateless session helpers and tests for multi-instance behavior.
- `docs/hosting.md`: document HA deployment patterns and TLS/load balancer expectations.
- `docs/configuration.md`: document new HA flags or environment variables.
- `docs/architecture.md`: describe how stateless session continuity works across replicas.
- `docs/troubleshooting.md`: add HA-specific troubleshooting guidance and limitations.
