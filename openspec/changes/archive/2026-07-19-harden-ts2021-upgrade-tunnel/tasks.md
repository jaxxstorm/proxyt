## 1. Upgrade Tunnel Handling

- [x] 1.1 Retain and flush the `bufio.ReadWriter` returned when hijacking the `/ts2021` client connection.
- [x] 1.2 Relay client-to-upstream data through the hijacked buffered reader and upstream-to-client data through the buffered upstream reader.
- [x] 1.3 Preserve the existing non-101 response and request-scoped setup failure behavior.

## 2. Integration Coverage

- [x] 2.1 Add a local TLS fake control-plane upstream that performs a genuine `101 Switching Protocols` exchange.
- [x] 2.2 Add a raw `/ts2021` client test that verifies payload bytes buffered with both the upgrade request and switching response are delivered end to end.

## 3. Verification

- [x] 3.1 Run `go test ./...` and confirm the complete proxy test suite passes without live Tailscale access.
