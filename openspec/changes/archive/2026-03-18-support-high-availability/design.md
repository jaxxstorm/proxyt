## Context

Proxyt currently routes and proxies requests inside [`cmd/serve.go`](/home/lbriggs/src/github/jaxxstorm/proxyt/cmd/serve.go) with effectively no cross-request or cross-instance coordination. That is fine for a single process, but it leaves HA behavior undefined once multiple proxyt replicas sit behind the same public DNS name. The `/ts2021` path upgrades to a long-lived tunneled connection, and the current certificate guidance is centered on standalone or single-instance hosting. If we want operators to run proxyt on Kubernetes, Docker, or other platforms in an HA shape, the product needs an explicit session continuity model and documentation that explains the supported deployment boundary without assuming extra infrastructure.

## Goals / Non-Goals

**Goals:**

- Let multiple proxyt instances participate in the same client-facing deployment behind one shared DNS name.
- Preserve logical session continuity for proxied HTTP flows even when related requests hit different replicas.
- Keep the client-visible hostname stable and avoid exposing internal instance identities.
- Avoid introducing a mandatory external state service for the first HA iteration.
- Provide deployment guidance that works across Kubernetes, Docker, and generic reverse-proxy environments.

**Non-Goals:**

- Live migration of an already-upgraded `/ts2021` connection between running replicas.
- Shipping full Kubernetes manifests, Helm charts, or Docker Compose bundles in this change.
- Solving distributed Let's Encrypt issuance inside proxyt's built-in standalone TLS flow in the first HA iteration.

## Decisions

### Decision 1: Use an opt-in stateless HA session design

HA support should be explicit rather than automatic. The initial design should avoid Redis or another external session store and instead use proxyt-issued client state protected by a shared secret. Each replica can validate and refresh the same session continuity data as long as it shares the configured secret and public-domain settings.

Single-instance deployments continue to operate without this mechanism. HA behavior turns on only when the operator provides the required shared secret material.

### Decision 2: Use an opaque, public-domain session cookie for continuity

Each client participating in an HA-managed flow should receive a proxyt-owned session identifier scoped to the configured public domain. The cookie or token should be opaque or cryptographically protected so it does not reveal internal instance details. The protected client state should carry only the minimum continuity data needed for another replica to resume the flow safely.

This keeps the browser or client pinned to the same logical session while allowing any correctly configured replica to recover the state it needs for the next related HTTP request.

### Decision 3: Keep active upgraded `/ts2021` streams instance-local

The `/ts2021` endpoint currently upgrades into a long-lived bidirectional tunnel. Supporting mid-stream transfer between replicas would require a much larger distributed connection-handoff system that does not fit this change. Instead, the design explicitly scopes HA continuity to new or resumed requests. Once a `/ts2021` connection is accepted, it remains bound to that replica until it closes.

This still fits normal HA expectations because load balancers generally keep an accepted TCP or upgraded HTTP connection on the backend that owns it. If that replica dies, the client must reconnect and start a new upstream connection, which the HA session model can then resume for subsequent HTTP requests.

### Decision 4: Target HA deployments behind external TLS termination first

Proxyt's built-in Let's Encrypt flow relies on local process and filesystem behavior that is awkward to coordinate across multiple replicas. For the first HA iteration, the documented deployment target should be `--http-only` behind an external TLS terminator or load balancer that owns certificates for the shared public DNS name.

The docs can still mention that operators may choose their own shared certificate strategy, but proxyt's explicit HA guidance should recommend platform-managed TLS termination rather than promising multi-replica ACME coordination that the code does not yet implement.

### Decision 5: Add tests that exercise two logical replicas with one shared secret

The implementation should add tests that spin up at least two proxyt handlers configured as separate logical instances while sharing the same HA secret and public domain. Those tests should prove that a session created on one instance can be resumed on another without changing the client-visible hostname or restarting the flow.

### Decision 6: Document the limits of stateless HA explicitly

The docs should be clear that the stateless design trades off some server-side control in exchange for portability. In particular:

- active `/ts2021` upgraded connections are not moved between replicas
- session continuity data must stay small enough to fit safely in the chosen client-visible mechanism
- rotating the shared secret invalidates existing HA continuity state
- server-side revocation is limited without adding new coordination infrastructure later

These limitations are acceptable for the first HA iteration as long as they are described plainly in the operator documentation.

## Affected Components

- `cmd/serve.go` for HA configuration wiring and request/session handling
- New HA session helpers in `cmd/` for configuration, cookie handling, and protected stateless session operations
- `cmd/*_test.go` for unit and integration coverage of multi-instance continuity
- `docs/configuration.md` for HA flags and environment variables
- `docs/hosting.md` for deployment guidance across Kubernetes, Docker, and generic reverse proxies
- `docs/architecture.md` and `docs/troubleshooting.md` for runtime behavior and operational caveats

## Migration Concerns

- HA mode should be opt-in so existing single-instance deployments do not break or gain new required dependencies.
- Shared secret rotation will likely invalidate existing HA sessions, so the docs should call that out clearly.
- Stateless continuity data must be carefully bounded so cookie or token size does not balloon unexpectedly.
- Cookie handling needs to preserve secure defaults appropriate for a public login-adjacent service.
- Documentation must be careful to distinguish HTTP session continuity from active upgraded connection transfer, which remains out of scope.
- If future requirements demand server-side revocation or larger continuity state, the design may need a second phase with optional shared infrastructure.

## Verification Plan

- Add unit tests for HA configuration validation, session ID issuance and verification, and protected stateless payload handling.
- Add integration tests that simulate two proxyt instances behind the same public domain using the same shared secret and verify continuity across replicas.
- Verify that the single-instance path still behaves as before when HA configuration is disabled.
- Run `go test ./...` after implementation.
