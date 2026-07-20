## ADDED Requirements

### Requirement: Session Continuity Across Replicas

Proxyt MUST support a high-availability mode that preserves logical session continuity when requests from the same client reach different proxyt instances behind one public DNS name.

#### Scenario: A later request lands on a different replica

- **WHEN** a client begins a proxied login or control-plane HTTP flow through one proxyt instance and a later related request reaches a different instance that shares the same HA configuration
- **THEN** the receiving instance MUST recover the session context from stateless client-presented HA data instead of depending on local process memory
- **AND** the client MUST be able to continue the flow without restarting from the beginning

#### Scenario: Single-instance deployments remain simple

- **WHEN** proxyt is started without HA configuration
- **THEN** it MUST continue to serve requests in its current single-instance mode
- **AND** operators MUST NOT be required to configure shared HA dependencies for non-HA deployments

### Requirement: Public-Domain Session Identity

Any client-visible session identity used for HA continuity MUST remain scoped to proxyt's configured public domain and MUST NOT reveal internal instance addressing.

#### Scenario: Session cookie or token is issued

- **WHEN** proxyt creates or refreshes HA session continuity state for a client
- **THEN** it MUST issue a session identifier scoped to the configured `--domain`
- **AND** the identifier MUST be opaque, signed, encrypted, or otherwise protected such that internal pod, container, or host identities are not exposed to the client

#### Scenario: Rewritten responses stay on the public domain

- **WHEN** proxyt rewrites Tailscale URLs or emits session-related headers while HA mode is enabled
- **THEN** the client-visible hostnames MUST continue to use the configured public domain
- **AND** proxyt MUST NOT leak backend or replica-specific hostnames in redirects, cookies, or similar response metadata

### Requirement: Shared Secret Configuration Enables Cross-Replica Continuity

Cross-replica session continuity MUST be possible with only shared proxyt configuration and MUST NOT require an external coordination service in the initial HA design.

#### Scenario: Shared secret is configured correctly

- **WHEN** multiple proxyt instances start with the same HA secret material and public-domain configuration
- **THEN** each instance MUST be able to validate and refresh the same client session continuity data
- **AND** request continuity MUST remain valid even if different HTTP requests from the same client are served by different replicas

#### Scenario: Shared secret configuration is invalid

- **WHEN** HA mode is enabled but proxyt cannot initialize the required HA secret configuration
- **THEN** proxyt MUST fail clearly rather than silently degrading into local-only session handling
- **AND** the failure MUST be observable to operators through startup or runtime error reporting

### Requirement: HA Deployment Guidance Is Documented

Proxyt documentation MUST describe how to deploy the service in HA mode across common environments and explain the operational boundaries of that support.

#### Scenario: Documentation covers common deployment targets

- **WHEN** an operator reads the proxyt deployment and configuration documentation
- **THEN** the docs MUST explain how to run multiple proxyt instances behind one DNS name in Kubernetes, Docker, and other reverse-proxy environments
- **AND** the docs MUST document the required shared secret configuration and recommended TLS termination model

#### Scenario: Documentation explains upgraded-connection behavior

- **WHEN** an operator plans HA support for `/ts2021` traffic
- **THEN** the docs MUST explain that an active upgraded connection remains bound to the accepting proxyt instance for its lifetime
- **AND** the docs MUST clarify that HA continuity applies to new or resumed requests rather than mid-stream handoff of an existing upgraded connection

#### Scenario: Documentation explains stateless HA limitations

- **WHEN** an operator evaluates proxyt's HA behavior
- **THEN** the docs MUST explain the limits of the stateless design, including session-size constraints, shared-secret rotation impact, and the absence of server-side revocation without additional coordination
- **AND** the docs MUST clearly distinguish those limits from the supported cross-replica continuity behavior
