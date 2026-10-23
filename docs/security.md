# Security

You should never use another user's proxyt instance for authentication. Use your own self-hosted instance of proxyt.

- **TLS Termination**: ProxyT terminates the outer client TLS connection and establishes a separate TLS connection to Tailscale. In HTTP-only mode, the frontend terminates client TLS instead.
- **Noise encryption**: After the `/ts2021` upgrade, ProxyT relays an opaque Noise-encrypted stream between the Tailscale client and control plane. Terminating outer TLS does not decrypt that Noise payload. Ordinary HTTP requests, headers, and browser authentication traffic are not covered by this inner encryption and are visible to the proxy.
- **Certificate Storage**: Protect the certificate directory with appropriate file permissions
- **Network Access**: Restrict access to the proxy server as needed
- **Logging**: Debug mode logs sensitive headers; use carefully in production
- **Docker Security**: 
  - Images run as non-root user (65532)
  - Based on distroless images with minimal attack surface
  - Tagged release images run the Go binary directly; it handles shutdown signals
  - Rebuild and redeploy to receive Go and base-image security fixes

## Go certificate verification

Builds require **Go 1.27.3 or newer**. This includes the `crypto/x509` mitigation
for compromised eMudhra intermediates in
[GO-2026-6809 / CVE-2026-111943](https://pkg.go.dev/vuln/GO-2026-6809).
The upstream fix is available in Go 1.26.10 and 1.27.3; this project uses the
1.27.3 baseline consistently for source, CI, and Docker builds.

The fix is compiled into the binary. Updating the host Go installation or CA
bundle alone does not patch an already-built ProxyT binary: rebuild and redeploy
it. Keep system/container trust stores current as well. Inspect an artifact's
compiler version with `go version -m /path/to/proxyt`.

The denylist protects certificate chain verification on outgoing TLS
connections. Loading ProxyT's own certificate checks its key, validity dates,
and hostname; it does not establish public CA trust. Clients still validate the
certificate served by ProxyT and need their own security updates.
