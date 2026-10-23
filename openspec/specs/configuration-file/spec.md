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
- **WHEN** configuration sources resolve to a missing domain or email while automatic certificate issuance is enabled, or a missing certificate directory while serving HTTPS
- **THEN** ProxyT MUST fail before serving traffic

### Requirement: HA duration settings use existing configuration precedence

ProxyT MUST expose `shutdown-delay`, `shutdown-timeout`, `upstream-connect-timeout`, and `cert-reload-interval` through serve flags, corresponding `PROXYT_*` environment variables, and YAML keys. Values MUST use Go duration syntax with changed flags overriding environment variables, environment variables overriding YAML, and YAML overriding defaults. Defaults MUST be `5s`, `25s`, `10s`, and `30s` respectively. CLI help MUST describe the full upstream establishment scope and the separate shutdown delay and drain budget.

#### Scenario: No HA settings are provided
- **WHEN** ProxyT starts without explicit HA settings
- **THEN** it MUST use a 5-second propagation delay, a 25-second shared drain timeout, a 10-second upstream establishment timeout, and a 30-second external-certificate poll interval

#### Scenario: Duration is overridden across configuration sources
- **WHEN** an HA duration is provided in YAML, environment, and a changed flag
- **THEN** the changed flag MUST win
- **AND** without that flag the environment value MUST win over YAML

### Requirement: HA durations are validated before serving

ProxyT MUST reject malformed or overflowing duration values before opening listeners. `shutdown-delay` MUST be nonnegative; the other HA durations MUST be strictly positive. The sum of shutdown delay and timeout MUST NOT overflow. These validations MUST apply in every serving mode, including when certificate polling is inactive.

#### Scenario: Invalid duration is configured
- **WHEN** any source resolves to malformed syntax, an overflowing value, a negative shutdown delay, or a nonpositive timeout or interval
- **THEN** startup MUST fail with an error naming the setting rather than silently coercing it to zero

#### Scenario: Shutdown duration sum overflows
- **WHEN** individually valid shutdown durations overflow when combined
- **THEN** startup MUST fail before listening

#### Scenario: Immediate propagation is configured
- **WHEN** `shutdown-delay` is `0s` and all other settings are valid
- **THEN** ProxyT MUST accept the configuration and begin listener shutdown immediately upon drain entry
