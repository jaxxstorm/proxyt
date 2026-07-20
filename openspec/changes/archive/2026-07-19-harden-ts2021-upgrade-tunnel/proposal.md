## Why

The `/ts2021` handler loses bytes already buffered while parsing the upstream HTTP response or while hijacking the client connection. A successful `101 Switching Protocols` exchange is therefore not reliably end-to-end despite the existing test coverage for a non-upgrade response.

## What Changes

- Preserve buffered client and upstream bytes when transitioning a `/ts2021` request from HTTP handling to its bidirectional tunnel.
- Require the tunnel to forward data in both directions after a successful `101 Switching Protocols` response.
- Add deterministic local integration coverage for a genuine `101` control-protocol upgrade, including bytes sent immediately after the response and immediately after client upgrade.
- Keep the existing non-upgrade response behavior and Bad Gateway failure behavior intact.
- Tunnel setup remains idempotent per request: it creates exactly one upstream connection and no retry is attempted after a connection, write, parse, or hijack failure; the client may retry the request.
- Log tunnel setup, successful protocol switching, and setup failures with existing structured request context without logging tunneled payloads.

## Capabilities

### New Capabilities
- `control-plane-upgrade-tunneling`: Reliably establishes and relays the `/ts2021` switched-protocol connection, including bytes buffered at the HTTP-to-raw-connection boundary.

### Modified Capabilities
- `proxy-testing`: Requires local integration coverage of a genuine bidirectional `/ts2021` `101 Switching Protocols` exchange.

## Impact

- Affects the `/ts2021` handler in `cmd/serve.go` and its connection-copying behavior.
- Expands local fake-upstream test coverage in `cmd/serve_test.go`; no public CLI, configuration, or dependency changes are expected.
