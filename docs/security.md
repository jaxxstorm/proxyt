# Security

You should never use another user's proxyt instance for authentication. Use your own self-hosted instance of proxyt.

- **TLS Termination**: ProxyT terminates TLS and re-encrypts to Tailscale services
- **Certificate Storage**: Protect the certificate directory with appropriate file permissions
- **Network Access**: Restrict access to the proxy server as needed
- **Logging**: Debug mode logs sensitive headers; use carefully in production
- **Docker Security**: 
  - Images run as non-root user (65532)
  - Based on distroless images with minimal attack surface
  - Use dumb-init for proper signal handling
  - Regular security updates via automated builds