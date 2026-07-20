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

**High Availability Issues**
- Confirm every replica uses the same `PROXYT_HA_SECRET` or `--ha-secret`
- Confirm every replica is configured with the same public `--domain`
- Prefer `--http-only` behind external TLS termination for HA deployments
- Check that your load balancer forwards `X-Forwarded-Proto: https` so proxyt can mark its HA cookie as secure

**Cookie Or Redirect Issues**
- If browser flows break, inspect `Set-Cookie` and `Location` headers and confirm they reference your public proxyt domain rather than `*.tailscale.com`
- If proxyt HA cookies are missing, confirm HA mode is enabled and the request reaches proxyt over HTTPS or with `X-Forwarded-Proto: https`

## Debug Mode

Enable debug logging to troubleshoot issues:

```bash
proxyt serve --domain proxy.example.com --email admin@example.com --cert-dir /tmp/certs --debug
```

This provides detailed request/response logging including headers and routing decisions.

HA-specific symptoms to look for:

- Repeated re-login prompts after traffic shifts between replicas usually mean the HA secret differs between instances or the public domain is inconsistent.
- Clients losing continuity immediately after a rollout often means the HA secret was rotated, which invalidates existing proxyt HA cookies.
- An in-flight `/ts2021` stream dropping during a pod or container restart is expected; proxyt does not transfer a live upgraded connection to another replica mid-stream.
