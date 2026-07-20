## Why

ProxyT advertises `--config` but never reads a file, forcing deployments to duplicate settings as flags or environment variables. File-backed YAML configuration is needed for repeatable local and orchestrated deployments.

## What Changes

- Load YAML configuration from `--config` or, when omitted, the optional `$HOME/.proxyt.yaml` default.
- Apply deterministic precedence: explicit flags override `PROXYT_*` environment variables, which override YAML values, which override built-in defaults.
- Reject explicitly requested missing, unreadable, or invalid YAML configuration before starting the proxy.
- Validate the resolved serving configuration using the existing domain, certificate-directory, and Let's Encrypt email requirements.
- Document YAML configuration and add deterministic unit coverage for loading, precedence, and failure cases.
- Configuration is read once at startup; ProxyT does not reload files or retry failed configuration reads while serving.

## Capabilities

### New Capabilities
- `configuration-file`: YAML file loading, source precedence, and startup validation for ProxyT configuration.

### Modified Capabilities
- None.

## Impact

- Affects Cobra startup handling in `cmd/root.go`, Viper configuration consumption in `cmd/serve.go`, tests, and `docs/configuration.md`.
- Uses the existing Viper dependency; no new runtime dependency is required.
