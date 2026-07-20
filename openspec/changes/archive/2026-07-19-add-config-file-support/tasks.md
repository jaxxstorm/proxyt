## 1. Configuration Loading

- [x] 1.1 Replace package-global Viper use with an isolated command configuration instance and bind existing serve flags and `PROXYT_*` environment variables.
- [x] 1.2 Load an explicit `--config` YAML file or optional `$HOME/.proxyt.yaml` before `serve` runs, returning explicit-file and YAML parse errors.
- [x] 1.3 Validate resolved serving settings before listeners start.

## 2. Coverage And Documentation

- [x] 2.1 Add unit tests for explicit and default file loading, source precedence, missing and invalid YAML, and resolved validation rules.
- [x] 2.2 Document YAML format, path selection, precedence, and startup failure behavior.

## 3. Verification

- [x] 3.1 Run `gofmt -w cmd/root.go cmd/serve.go cmd/config_test.go`, `go test ./...`, and `go build ./...`.
