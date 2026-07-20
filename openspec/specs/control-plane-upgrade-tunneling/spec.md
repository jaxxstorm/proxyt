## ADDED Requirements

### Requirement: Control-plane upgrade tunnel preserves buffered bytes

When the upstream control plane accepts a `/ts2021` request with HTTP `101 Switching Protocols`, Proxyt MUST forward all bytes already buffered while parsing the upstream response or hijacking the client connection before forwarding subsequently received tunnel bytes.

#### Scenario: Upstream sends bytes with the switching response
- **WHEN** the upstream sends tunnel payload bytes immediately after its `101 Switching Protocols` response
- **THEN** Proxyt MUST deliver those bytes to the client after the switching response

#### Scenario: Client sends bytes with the upgrade request
- **WHEN** the client sends tunnel payload bytes that are buffered with its `/ts2021` upgrade request
- **THEN** Proxyt MUST deliver those bytes to the upstream after establishing the tunnel

### Requirement: Control-plane upgrade tunnel relays bidirectionally

After a successful `/ts2021` protocol switch, Proxyt MUST relay opaque tunnel payloads in both directions without interpreting or logging their contents.

#### Scenario: Bidirectional payload exchange
- **WHEN** a client and local control-plane upstream exchange payloads after a successful `101 Switching Protocols` response
- **THEN** each peer MUST receive the payload sent by the other peer

### Requirement: Upgrade failures remain request-scoped

Proxyt MUST create no more than one upstream connection for a `/ts2021` request and MUST NOT retry a failed connection, request write, response parse, or client hijack internally.

#### Scenario: Tunnel setup fails
- **WHEN** tunnel setup fails before the protocol switch completes
- **THEN** Proxyt MUST terminate that request using its existing error response behavior where possible
- **AND** it MUST NOT create another upstream connection for the request
