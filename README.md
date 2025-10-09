# ProxyT

A lightweight, preconfigured proxy for the Tailscale control plane that enables Tailscale access in the event the Tailscale control plane is being blocked.


[![Deploy on Railway](https://railway.com/button.svg)](https://railway.app/template/proxyt?referralCode=ftkvtR)

## Overview

Tailscale connections between peers are incredible resiliant. If you are authenticated to Tailscale, it will endeavour to use all mechanisms at its disposal to forge connections it needs between clients.

However, some networks block the Tailscale _control plane_ (ie, the tailscale.com domain) either via DNS blackholing or SNI interception.

Proxyt allows you to host a proxy to the Tailscale control plane which can be used by clients. You can host Proxyt anywhere, register your own domain or even expose it via [Funnel](https://tailscale.com/kb/1223/funnel) giving you a reliable way of accessing the Tailscale control plane to authenticate clients.

## 📖 Documentation

Docs are available in the [docs](./docs) directory or at https://www.proxyt.io

## Installation

See [Installation](installation.md)

## Configuring Proxyt

See [Configuration](configuration.md)

## Hosting

For some examples of different ways to host Proxyt, see [Hosting](hosting.md)

## Clients

For information about how to configure clients, see [Clients](clients.md)

## Troubleshooting

See [Troubleshooting](troubleshooting.md)

## Security

See [Security](security.md)

## Architecture

See [Architecture](architecture.md)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

See [LICENSE](LICENSE) for details.
