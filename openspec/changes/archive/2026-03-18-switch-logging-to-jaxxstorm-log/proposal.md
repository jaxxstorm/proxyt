## Why

Proxyt currently builds and uses `go.uber.org/zap` directly in [`cmd/serve.go`](/home/lbriggs/src/github/jaxxstorm/proxyt/cmd/serve.go), even though the project standard in [`openspec/config.yaml`](/home/lbriggs/src/github/jaxxstorm/proxyt/openspec/config.yaml) calls for `github.com/jaxxstorm/log`. Migrating to the shared wrapper will make logging behavior consistent with the rest of the project direction, reduce direct zap coupling in application code, and give the CLI the wrapper's default pretty-on-TTY and JSON-off-TTY behavior.

## What Changes

- Replace direct `zap` logger construction and field helpers in runtime code with `github.com/jaxxstorm/log`.
- Introduce a proxyt-owned logger initialization path that maps the existing `--debug` flag to the shared logger's level configuration.
- Preserve current fatal logging and exit behavior by using the shared logger's fatal support where proxyt already treats failures as unrecoverable.
- Preserve the current operational log points for startup, request routing, response rewriting, protocol upgrades, and shutdown.

## Capabilities

### Modified Capabilities

- `logging`: Proxyt runtime logging uses the shared logging wrapper while preserving current debug gating and structured operational fields.

## Behavior

- The `serve` command MUST initialize `github.com/jaxxstorm/log` before emitting runtime logs.
- The `--debug` flag MUST continue to enable debug-level logging, and the default runtime level MUST remain info.
- Proxyt runtime code MUST stop constructing or emitting logs with direct `go.uber.org/zap` APIs.
- Structured fields for existing operational events MUST be preserved during the migration.

## Idempotency And Retry Semantics

- Re-running proxyt with the same flags and environment MUST result in the same logger backend, level selection, and output format behavior.
- Logger initialization is process-local and does not introduce new persisted state.
- Proxyt MUST NOT automatically retry invalid logger configuration; it should fail fast so the operator can correct the configuration and retry explicitly.

## Failure Modes And Recovery

- If shared logger initialization fails, proxyt MUST report the failure clearly and exit non-zero before opening listeners.
- If a listener fails after startup, proxyt MUST log the failure through the shared logger's fatal path and terminate the process instead of silently continuing.
- If logger shutdown or sync returns an ignorable terminal-output sync error, proxyt MAY suppress it; non-ignorable close failures SHOULD still be surfaced for troubleshooting.

## Observability And Audit

- Existing startup, routing, rewrite, protocol-upgrade, health, and shutdown events MUST remain observable with structured fields.
- Debug-only request and header logging MUST remain opt-in because the current documentation already notes that debug mode can expose sensitive headers.
- The migration SHOULD preserve enough contextual fields to compare pre- and post-migration logs during rollout.

## Test Plan Summary

- Prioritize unit tests around logger initialization, debug-level mapping, and fatal-path behavior.
- Add targeted tests for any helper introduced to build shared loggers and for the wrapper-backed fatal behavior proxyt relies on.
- Run the Go test suite after the migration and add focused coverage for any newly refactored control-flow paths.

## Impact

- `go.mod`: add the shared logging dependency and prune direct zap usage from application code where possible.
- `cmd/serve.go`: replace direct logger construction, field helpers, and fatal-style exits with `github.com/jaxxstorm/log`.
- `docs/security.md`: verify the debug logging warning still matches runtime behavior.
- `docs/troubleshooting.md`: verify debug-mode guidance still describes the available logging output.
