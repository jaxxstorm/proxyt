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

**HTTP-Only Mode Issues**
- Ensure your reverse proxy is properly forwarding X-Forwarded headers
- Verify the reverse proxy supports HTTP/1.1 upgrades for `/ts2021` endpoints
- Check that the bind address and port are correct
- Confirm your reverse proxy is handling TLS termination properly

**Protocol Upgrade Failures**
- Ensure reverse proxy supports WebSocket/HTTP upgrades
- Check that `Connection: upgrade` and `Upgrade` headers are forwarded
- Verify no intermediate proxies are stripping upgrade headers

## Debug Mode

Enable debug logging to troubleshoot issues:

```bash
proxyt serve --domain proxy.example.com --email admin@example.com --cert-dir /tmp/certs --debug
```

This provides detailed request/response logging including headers and routing decisions.