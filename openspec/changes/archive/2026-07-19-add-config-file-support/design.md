## Context

The root command exposes `--config` with a default-path description, while `serve` binds flags and environment variables directly to Viper's package-global instance. No code selects or reads a configuration file, so YAML values cannot affect runtime settings.

## Goals / Non-Goals

**Goals:**
- Load one YAML file before `serve` resolves its settings.
- Preserve the existing flags and `PROXYT_*` environment interface.
- Make configuration precedence explicit and unit-testable.
- Fail early for explicit file and resolved configuration errors.

**Non-Goals:**
- Reload configuration while running.
- Support multiple files, includes, remote stores, or arbitrary configuration formats.
- Change TLS, listener, or proxy routing behavior beyond sourcing their values from YAML.

## Decisions

### Use a dedicated Viper instance with injectable setup

The command package will own one Viper instance, configured with its environment prefix, key replacer, and bound `serve` flags. File-loading helpers will accept a Viper instance and home-directory lookup so tests can use isolated state rather than package-global Viper configuration.

Alternative considered: keep the global Viper singleton and reset it in tests. That risks losing flag bindings and makes precedence tests order-dependent.

### Select one explicit YAML path

When `--config` is supplied, ProxyT will read that exact file and return any access or parse error. When omitted, it will attempt `$HOME/.proxyt.yaml`; a missing default file is accepted, while an existing unreadable or malformed file is an error.

Alternative considered: search Viper's default paths and extensions. That makes the advertised default ambiguous and can select an unintended file.

### Resolve configuration before validation

Viper's existing precedence will be used: a changed command flag wins over a matching environment variable, which wins over YAML, then flag defaults. Once resolved, the existing required domain, certificate directory, and Let's Encrypt email conditions will be checked before listeners start.

Alternative considered: validate YAML before environment and flags are applied. This would reject valid deployment overrides and violate source precedence.

## Risks / Trade-offs

- [A missing optional default could hide a filename typo] -> Treat only the default path as optional; explicit files always fail when unavailable.
- [YAML keys differ from flag names] -> Document the exact hyphenated option keys used by flags and environment binding.
- [Validation errors occur before structured logging] -> Return concise Cobra startup errors for file-loading failures and retain structured fatal logging for resolved serving validation.

## Migration Plan

Existing flags and environment deployments continue unchanged. Operators may add a YAML file, then progressively move values from flags or environment knowing those higher-priority sources still override it. Rollback consists of removing `--config` or `$HOME/.proxyt.yaml` usage.

## Open Questions

None.
