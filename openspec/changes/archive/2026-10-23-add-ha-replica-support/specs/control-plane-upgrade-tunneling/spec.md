## ADDED Requirements

### Requirement: Control-protocol establishment is bounded and cancelable

Each `/ts2021` request MUST use one `upstream-connect-timeout` deadline covering upstream TCP connection, TLS handshake, request write, and response-header read. Request cancellation and forced shutdown MUST interrupt pending establishment. Failure MUST remain request-scoped, close owned resources, and preserve the existing error response behavior where a response remains possible. ProxyT MUST NOT replay the request or open a second upstream connection.

#### Scenario: Upstream stalls during establishment
- **WHEN** the upstream stalls during dial, TLS handshake, request write, or response-header read
- **THEN** ProxyT MUST terminate establishment by its configured deadline and release its resources
- **AND** it MUST NOT retry the request

#### Scenario: Establishment is canceled
- **WHEN** the request context is canceled or forced shutdown occurs during establishment
- **THEN** ProxyT MUST interrupt the pending operation and close any allocated upstream connection

### Requirement: Setup bounds do not limit established tunnel lifetime

After a successful upgrade, ProxyT MUST clear establishment I/O deadlines before relaying bytes and retain explicit lifecycle ownership until tunnel cleanup. Tunnel lifetime MUST NOT be tied to cancellation caused solely by the upgrade handler returning. Existing buffered-byte preservation and opaque bidirectional relay requirements MUST continue to hold.

#### Scenario: Healthy tunnel exceeds setup timeout
- **WHEN** a successful tunnel remains active longer than `upstream-connect-timeout`
- **THEN** ProxyT MUST continue relaying bytes in both directions unless a peer closes, a transport error occurs, or shutdown reaches its deadline

#### Scenario: Upgrade response contains buffered payload
- **WHEN** setup succeeds with payload already buffered on either peer
- **THEN** clearing setup bounds and registering the tunnel MUST preserve those bytes and their ordering
