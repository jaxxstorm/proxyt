## Context

`handleTailscaleControlProtocol` parses the upstream response with a new `bufio.Reader`, then discards that reader when it starts the backend-to-client copy. It likewise discards the `bufio.ReadWriter` returned by `http.Hijacker`. Either buffer can contain protocol bytes that arrived with the HTTP upgrade and must be included in the raw tunnel.

The current handler test verifies that the original POST method and upgrade headers reach a local TLS upstream, but the upstream returns HTTP 200. It cannot exercise the transition to a persistent switched-protocol connection.

## Goals / Non-Goals

**Goals:**
- Preserve all already-buffered bytes on both sides of a successful `/ts2021` upgrade.
- Maintain bidirectional streaming after the `101 Switching Protocols` response.
- Prove the behavior with a deterministic local integration test using no live Tailscale service.
- Retain existing non-upgrade and setup-failure behavior.

**Non-Goals:**
- Change request routing, public configuration, retry policy, or upstream selection.
- Interpret, log, buffer beyond the HTTP handoff, or otherwise inspect tunneled protocol payloads.
- Add support for upgrades through HTTP/2 or incompatible CDN frontends.

## Decisions

### Retain the readers created at each protocol boundary

The handler will keep the upstream `bufio.Reader` used by `http.ReadResponse` and the client-side `bufio.ReadWriter` returned by `Hijack`. Client-to-upstream copying will read from the hijacked reader; upstream-to-client copying will read from the upstream buffered reader. This forwards data consumed ahead of the raw connection by either HTTP parser.

The handler will flush the hijacked writer before raw upstream-to-client copying so the already-written status line and response headers reach the client. Raw connection writes will be used for subsequent upstream bytes to avoid introducing a new unflushed output buffer.

Alternative considered: bypass `http.ReadResponse` and relay upstream bytes verbatim. This would avoid the upstream read buffer but would lose the existing parsed status/header handling and make non-upgrade responses more complex.

### Preserve existing lifecycle and failure behavior

One upstream TLS connection is established per `/ts2021` request. Connection, request-write, response-parse, and hijack failures remain terminal for that request, with no server-side retry; the existing HTTP error path applies where the response is still writable. Either completed copy direction ends the tunnel and closes both connections through the existing deferred cleanup.

Alternative considered: wait for both copy directions before closing. This risks retaining hung connections when one peer has already closed and is unnecessary for the current simple tunnel lifecycle.

### Test through raw local connections

The new integration test will use a local TLS upstream supplied through `dialControlPlane` and a raw client connection to ProxyT. The fake upstream will return a real `101 Switching Protocols` response followed immediately by payload bytes. The raw client will send payload bytes in the same write as its upgrade request, ensuring they are available in the hijacked reader, then assert both the immediate upstream payload and its own buffered payload are relayed.

Alternative considered: use `http.Client` and `httptest.NewTLSServer` only. Standard HTTP client behavior abstracts the upgraded stream and does not reliably let the test control payload bytes buffered with the request or response.

## Risks / Trade-offs

- [Writing the HTTP response before hijacking leaves headers buffered] -> Flush the returned hijacked writer before tunneling.
- [A test can deadlock while each endpoint waits to read] -> Use explicit payload ordering, deadlines, and bounded completion channels.
- [Concurrent copies can obscure a lost-byte regression] -> Assert distinct payloads deliberately sent immediately after each HTTP boundary.
- [Closing after one copy ends can truncate a peer still writing] -> Preserve the current behavior for this narrow reliability fix and keep the test exchange finite.

## Migration Plan

No deployment or configuration migration is required. Release the handler and test together; rollback is a normal binary rollback because the external endpoint and protocol contract remain unchanged.

## Open Questions

None.
