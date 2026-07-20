## ADDED Requirements

### Requirement: YAML configuration file is loaded at startup

ProxyT MUST load YAML settings from the exact path passed with `--config`. When `--config` is omitted, ProxyT MUST load `$HOME/.proxyt.yaml` if it exists and MUST continue with built-in defaults when that default file is absent.

#### Scenario: Explicit configuration is loaded
- **WHEN** `proxyt serve --config /path/proxyt.yaml` starts with a readable YAML file
- **THEN** values in that file MUST be available to the serve command

#### Scenario: Default configuration is absent
- **WHEN** `--config` is omitted and `$HOME/.proxyt.yaml` does not exist
- **THEN** ProxyT MUST continue startup without a configuration-file error

### Requirement: Configuration source precedence is deterministic

ProxyT MUST resolve settings with changed command flags taking precedence over `PROXYT_*` environment variables, environment variables taking precedence over YAML values, and YAML values taking precedence over built-in flag defaults.

#### Scenario: Higher-priority values override YAML
- **WHEN** a setting is defined in YAML and also supplied by an environment variable or changed flag
- **THEN** ProxyT MUST use the environment value unless a changed flag supplies that setting

### Requirement: Configuration failures and resolved settings are validated

ProxyT MUST fail before serving when an explicitly requested configuration file is missing, unreadable, or invalid YAML. It MUST validate the resolved domain, certificate-directory, and Let's Encrypt email requirements after applying precedence.

#### Scenario: Explicit file cannot be read
- **WHEN** `--config` points to a missing or unreadable file
- **THEN** ProxyT MUST return a startup error and MUST NOT start listeners

#### Scenario: Resolved configuration is invalid
- **WHEN** configuration sources resolve to a missing domain, a missing certificate directory outside HTTP-only mode, or a missing email with certificate issuance enabled
- **THEN** ProxyT MUST fail before serving traffic
