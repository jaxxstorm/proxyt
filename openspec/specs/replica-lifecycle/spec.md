# Replica lifecycle

## Purpose

Define independent replica operation, idempotent draining, and bounded connection cleanup for container deployments.

## Requirements

### Requirement: Replicas accept connections independently

ProxyT MUST serve new connections without inter-replica coordination, session affinity across connections, a shared state store, or provider-specific runtime APIs. Established tunnels MUST remain attached to their original replica for their lifetime. Frontends MUST preserve the required protocol upgrade and opaque bidirectional stream; ProxyT MUST NOT claim to compensate for incompatible frontend protocol processing.

#### Scenario: Client reconnects through another replica
- **WHEN** a client's tunnel to one replica ends and the client establishes a new connection through a second healthy replica with the same public-domain configuration
- **THEN** the second replica MUST handle that connection without retrieving state from the first replica

### Requirement: Drain entry is immediate and idempotent

On SIGTERM or SIGINT, ProxyT MUST enter a monotonic draining state, immediately become unready, and reject newly admitted proxy requests with HTTP 503 without opening upstream connections. It MUST keep listeners open for `shutdown-delay` while already-admitted work continues. Repeated drain requests MUST NOT reset the schedule or repeat cleanup. Health and metrics requests MUST remain available while their listener is open.

#### Scenario: New work arrives during propagation
- **WHEN** ProxyT is draining and receives a new proxy request, including on an existing keep-alive connection
- **THEN** it MUST return HTTP 503 without forwarding the request
- **AND** an already-established tunnel MUST remain usable until it ends or the shutdown deadline is reached

#### Scenario: Drain is requested repeatedly
- **WHEN** shutdown is requested more than once
- **THEN** ProxyT MUST retain the original propagation and drain deadlines and perform cleanup once

### Requirement: Shutdown owns all admitted connections

ProxyT MUST track in-progress upgrades before upstream establishment and retain ownership through hijack, established tunneling, and cleanup. Generic reverse-proxy upgraded connections MUST also be covered. After `shutdown-delay`, all HTTP servers MUST stop accepting connections and drain concurrently under one shared `shutdown-timeout` budget. ProxyT MUST wait for admitted HTTP and upgrade work to complete, or at deadline cancel pending work and close remaining client and upstream sockets. Owned workers MUST terminate during cleanup; completed registrations MUST be released exactly once.

#### Scenario: Work completes before the deadline
- **WHEN** propagation has finished and all admitted requests and tunnels complete before the drain deadline
- **THEN** ProxyT MUST finish shutdown without waiting for the unused remainder of the timeout

#### Scenario: Tunnel outlives the deadline
- **WHEN** an established tunnel remains active at the shutdown deadline
- **THEN** ProxyT MUST close its client and upstream sides and unblock both relay directions
- **AND** it MUST NOT wait indefinitely for natural tunnel completion

#### Scenario: Shutdown overlaps upgrade establishment
- **WHEN** shutdown races an upstream dial, handshake, response read, or client hijack
- **THEN** the admitted operation MUST remain owned until completion or forced cleanup
- **AND** no socket or registration MUST escape the shutdown lifecycle

#### Scenario: Multiple listeners and generic upgrades are active
- **WHEN** multiple HTTP listeners and a generic reverse-proxy upgraded connection remain active during shutdown
- **THEN** they MUST share the same drain deadline
- **AND** the generic upgraded connection MUST be closed at that deadline if it has not completed
