## MODIFIED Requirements

### Requirement: Shared Runtime Logger

Proxyt MUST initialize and use `github.com/jaxxstorm/log` for command and runtime logging instead of creating or calling `go.uber.org/zap` directly in application code.

#### Scenario: Default runtime logging

- **WHEN** `proxyt serve` starts without `--debug`
- **THEN** it MUST initialize the shared logger at info level
- **AND** startup and runtime log entries MUST be emitted through the shared logger

#### Scenario: Debug runtime logging

- **WHEN** `proxyt serve` starts with `--debug`
- **THEN** it MUST initialize the shared logger at debug level
- **AND** detailed request, response, and routing diagnostics MUST remain available only in debug mode

### Requirement: Structured Operational Fields Remain Available

The logging migration MUST preserve the structured fields used for proxyt operational events.

#### Scenario: Request routing logs keep context

- **WHEN** proxyt logs request routing, response rewriting, protocol upgrades, health checks, or shutdown events
- **THEN** the resulting log entries MUST continue to include the relevant context fields such as remote address, path, target, domain, or byte count
- **AND** application code MUST use field helpers from `github.com/jaxxstorm/log` rather than raw zap field constructors

### Requirement: Fatal Failures Use The Shared Logger

Proxyt MUST use the shared logger's fatal behavior for unrecoverable runtime failures after logger initialization, while still surfacing logger-construction failures before serving traffic.

#### Scenario: Logger initialization fails

- **WHEN** shared logger creation fails because its configuration is invalid or its output cannot be opened
- **THEN** proxyt MUST surface a clear startup error
- **AND** the process MUST exit with a non-zero status before serving traffic

#### Scenario: Listener fails after startup

- **WHEN** an HTTP or HTTPS listener returns an unexpected error after startup
- **THEN** proxyt MUST log the failure through the shared logger's fatal path
- **AND** the process MUST terminate with a non-zero result
