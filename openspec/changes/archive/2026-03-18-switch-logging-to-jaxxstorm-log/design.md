## Context

Proxyt currently performs all application logging directly in [`cmd/serve.go`](/home/lbriggs/src/github/jaxxstorm/proxyt/cmd/serve.go) using `go.uber.org/zap` and `zapcore`. That code initializes separate development and production configs based on `--debug`, stores a package-level `*zap.Logger`, and uses `logger.Fatal(...)` for several startup and listener failures. The repository-level OpenSpec context already says the project should use `github.com/jaxxstorm/log`, and the local checkout of that library now exposes `log.New`, `log.Config`, `log.Logger`, field helpers such as `log.String`, `log.Int`, `log.Bool`, and `log.Error`, plus fatal support that preserves the existing process-exit model.

## Goals / Non-Goals

**Goals:**

- Standardize proxyt runtime logging on `github.com/jaxxstorm/log`.
- Preserve the current operational log coverage and structured fields.
- Preserve `--debug` as the switch for debug-level diagnostics.
- Preserve current fatal logging and exit semantics while removing direct zap usage from application code.

**Non-Goals:**

- Redesign proxy routing, handler structure, or TLS behavior.
- Change which events are logged except where required by the wrapper migration.
- Introduce a broader logging configuration surface beyond what is needed for the current migration.

## Decisions

### Decision 1: Add a small proxyt logger factory

Introduce a proxyt-owned helper, likely in a new file such as `cmd/logging.go`, that builds the shared logger with `log.New(log.Config{...})`. The helper will translate the existing `--debug` flag into `log.DebugLevel` or `log.InfoLevel` and rely on the wrapper's `AutoFormat` behavior so interactive use gets pretty logs while non-interactive execution gets JSON logs.

This keeps logger creation in one place and avoids sprinkling wrapper configuration details throughout `runProxy`.

### Decision 2: Replace direct zap field construction with wrapper fields

All current `zap.String`, `zap.Bool`, `zap.Int`, and `zap.Error` calls in application code will be replaced with their `github.com/jaxxstorm/log` equivalents. If an existing field does not have a direct helper, the migration can use `log.Any`.

This preserves structured logging while removing direct zap dependencies from runtime code.

### Decision 3: Keep fatal paths simple by using the wrapper's fatal support

Now that `github.com/jaxxstorm/log` exposes `Fatal`, proxyt can keep its current fatal-style control flow for unrecoverable runtime conditions after logger initialization. Existing `logger.Fatal(...)` call sites in `cmd/serve.go` can be migrated directly to the wrapper without introducing a broader Cobra command refactor.

Logger-construction failures still occur before a usable logger exists, so proxyt should surface those errors explicitly and exit before serving traffic. Everything after successful logger initialization can continue to rely on fatal logging for unrecoverable startup validation and listener failures.

### Decision 4: Preserve current observability and sensitive-debug behavior

The migration should keep the existing log points around startup, request handling, routing decisions, response rewriting, tunneling, and shutdown. Debug-only request and header dumps must remain gated behind `--debug`, matching the current behavior documented in [`docs/security.md`](/home/lbriggs/src/github/jaxxstorm/proxyt/docs/security.md) and [`docs/troubleshooting.md`](/home/lbriggs/src/github/jaxxstorm/proxyt/docs/troubleshooting.md).

## Affected Components

- `go.mod`
- `cmd/serve.go`
- A new helper such as `cmd/logging.go`
- Tests covering logger setup and fatal-path behavior
- Documentation only if behavior or examples need wording updates

## Migration Concerns

- The wrapper adds caller information and chooses pretty vs JSON automatically, so output format may differ slightly from today's development/production zap presets while still remaining structured.
- Logger shutdown should use `logger.Close()` or `logger.Sync()` consistently so buffered output is flushed without failing on ignorable terminal sync errors.
- The migration should avoid leaving mixed logging styles behind; proxyt runtime code should finish the change in one pass so future work does not have to support both zap fields and wrapper fields.
- Fatal tests may need a stubbed exit function or process-level test strategy because the wrapper now owns process termination.

## Verification Plan

- Unit test the proxyt logger factory for level selection and invalid configuration handling.
- Verify fatal call sites still exit non-zero on configuration failures and unexpected listener failures.
- Run `go test ./...` after the implementation and add focused tests for any newly introduced helper or control-flow path.
