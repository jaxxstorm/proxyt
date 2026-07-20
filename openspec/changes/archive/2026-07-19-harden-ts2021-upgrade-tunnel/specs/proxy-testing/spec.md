## ADDED Requirements

### Requirement: Integration Coverage For Switched Control-Plane Tunnels

Proxyt MUST provide a deterministic local integration test for a genuine `/ts2021` HTTP `101 Switching Protocols` exchange using a fake control-plane upstream.

#### Scenario: Buffered tunnel data is covered end to end
- **WHEN** the integration test sends client data with the upgrade request and the fake upstream sends data with the switching response
- **THEN** the test MUST assert that both buffered payloads reach their intended peer
- **AND** the test MUST require no live Tailscale infrastructure
