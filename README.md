# ProxyT

A lightweight, preconfigured proxy for the Tailscale control plane that enables Tailscale access in the event the Tailscale control plane is being blocked.


[![Deploy on Railway](https://railway.com/button.svg)](https://railway.app/template/proxyt?referralCode=ftkvtR)

## Overview

Tailscale connections between peers are incredible resiliant. If you are authenticated to Tailscale, it will endeavour to use all mechanisms at its disposal to forge connections it needs between clients.

However, some networks block the Tailscale _control plane_ (ie, the tailscale.com domain) either via DNS blackholing or SNI interception.

Proxyt allows you to host a proxy to the Tailscale control plane which can be used by clients. You can host Proxyt anywhere, register your own domain or even expose it via [Funnel](https://tailscale.com/kb/1223/funnel) giving you a reliable way of accessing the Tailscale control plane to authenticate clients.

## 📖 Documentation

**Full documentation:** [proxyt.io](https://proxyt.io)

### Quick Links

- 📦 [Installation](https://proxyt.io/#/installation) - Install ProxyT on your platform
- ⚙️ [Configuration](https://proxyt.io/#/configuration) - Configure ProxyT with flags or environment variables
- 🚀 [Deployment](https://proxyt.io/#/deployment) - Deploy to Railway, Docker, or your own server
- 🔧 [Tailscale Setup](https://proxyt.io/#/clients) - Configure Tailscale clients to use ProxyT
- 🛠️ [Troubleshooting](https://proxyt.io/#/troubleshooting) - Common issues and solutions
- 🔒 [Security](https://proxyt.io/#/security) - Security considerations and best practices
- 🏗️ [Architecture](https://proxyt.io/#/architecture) - How ProxyT works under the hood

> 💡 **Browsing on GitHub?** The documentation source files are in the [`docs/`](./docs) directory

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

See [LICENSE](LICENSE) for details.
