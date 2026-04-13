# Troubleshooting

## Common Issues

**Port 80/443 Access**
- Ensure firewall allows inbound connections
- Check if other services are using these ports
- Verify DNS resolution points to correct IP

**Certificate Issues**
- Check email address is valid for Let's Encrypt
- Ensure domain resolves to proxy server
- Verify port 80 is accessible for ACME challenges

**Tailscale Connection Failures**
- Enable debug mode (`--debug`) to see detailed request logs
- Check that Tailscale client can resolve your domain
- Verify proxy can reach `*.tailscale.com` domains
- Verify your frontend actually forwards `/ts2021` to ProxyT

**HTTP-Only Mode Issues**
- Ensure your reverse proxy is properly forwarding X-Forwarded headers
- Verify the reverse proxy supports HTTP/1.1 upgrades for `/ts2021` endpoints
- Verify the reverse proxy preserves the original request method for `/ts2021`
- Check that the bind address and port are correct
- Confirm your reverse proxy is handling TLS termination properly

**Protocol Upgrade Failures**
- Ensure reverse proxy supports WebSocket/HTTP upgrades
- Check that `Connection: upgrade` and `Upgrade` headers are forwarded
- Check whether your provider only supports standard WebSocket `GET` handshakes
- Check whether your provider only allows `Upgrade: websocket` and rejects other upgrade tokens
- Verify no intermediate proxies are stripping upgrade headers

**Known Unsupported Frontends**
- Cloudflare proxy, Cloudflare Tunnel, and Cloudflare Workers are not supported for `/ts2021`
- CloudFront and some managed edge platforms may also fail because they do not forward the control-protocol upgrade intact
- If ProxyT works behind Nginx, Caddy, or Funnel but fails behind a CDN, the CDN is the likely incompatibility point

## Debug Mode

Enable debug logging to troubleshoot issues:

```bash
proxyt serve --domain proxy.example.com --email admin@example.com --cert-dir /tmp/certs --debug
```

This provides detailed request/response logging including headers and routing decisions.

For `/ts2021`, debug logs are most useful when they show:

- The incoming request method
- The `Connection` and `Upgrade` headers from the client-facing side
- Whether ProxyT received a `101 Switching Protocols` response from upstream
- Any non-101 status returned before tunneling started
