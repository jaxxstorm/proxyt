# Clients

Once you have configured proxyt, you'll need to configure your client to use it.

One of the issues with client configuration is that when logging in via your SSO provider, the login URL generated still contains the tailscale.com domain, such as https://login.tailscale.com/a/something

There are several ways to solve this.

## Interactive Login

Once your proxy is running, configure Tailscale clients to use your custom domain:

```bash
tailscale login --login-server https://proxy.example.com
```

Use a different device to login to Tailscale using the provider URL.

## QR code login

Use the tailscale CLI to login

```bash
tailscale up --login-server https://proxyt.example.com --qr
```

Specifying `--qr` generates a QR code you can scan with your mobile device. This will authenticate you successfully - ensure your mobile device is **not** using the same network as the Tailscale client you're trying to authenticate

## Auth Key Login

For automated deployments with pre-authorized keys:

```bash
tailscale login --login-server https://proxy.example.com --auth-key tskey-auth-xxxxx
```

