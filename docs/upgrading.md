# Upgrading and Compatibility

## Preparing for 0.1.0

0.1.0 is the next planned release, not a 1.0 stability declaration. These notes
describe changes from 0.0.7; no data migration is required.

- **Manual certificates:** With `--issue=false`, startup now rejects expired,
  not-yet-valid, wrong-host, malformed, or mismatched certificate/key pairs.
  Set `--domain` to the certificate hostname and provide `<domain>.crt` and
  `<domain>.key` in `--cert-dir`. This checks the leaf's hostname and dates,
  not public trust of the full chain. Valid replacements are polled every 30s;
  invalid replacements retain the last good pair. Readiness fails if it expires.
- **Shutdown:** SIGTERM/SIGINT immediately makes the instance unready. Defaults
  allow 5s for routing propagation and then 25s for draining. Give the process
  manager at least 45s before forced termination. Tunnels reconnect rather than
  migrate to another instance.
- **Upstream setup:** `/ts2021` establishment now has a 10s total timeout;
  established tunnels have no timeout imposed by this setting.
- **Containers:** Tagged images use GoReleaser/ko. Pass `serve` explicitly and
  prepare writable certificate volumes for UID/GID 65532 as described in
  [configuration](configuration.md#docker). Do not rely on a shell, dumb-init,
  or an automatically writable `/certs` directory in release images.
- **Go security:** Source builds now require Go 1.27.3 or newer, including the
  eMudhra certificate-verification mitigation. Rebuild existing binaries and
  images; see [security](security.md#go-certificate-verification).
- **HA:** Use multiple instances behind a compatible frontend with externally
  managed certificates. See [High Availability](high-availability.md).

Pin a published version or digest when deploying. The experimental `:ha` image
is not the 0.1.0 release. Once 0.1.0 is published, use `:v0.1.0` for that release.

## Compatibility policy

During **0.x**, patch releases preserve documented configuration and metrics
except where security or correctness requires a change. Minor releases may
introduce breaking changes, documented here. There is no 1.x guarantee yet.

The intended **1.x stable surface**, to be finalized at 1.0, is:

- The `serve` command and `--config` file selector.
- The following flags, matching YAML keys, and `PROXYT_*` environment variables:
  `domain`, `email`, `cert-dir`, `issue`, `port`, `https-port`, `debug`,
  `http-only`, `bind`, `shutdown-delay`, `shutdown-timeout`,
  `upstream-connect-timeout`, and `cert-reload-interval`.
- Configuration precedence: explicit flags, environment, YAML, then defaults.
- `/health`, `/ready`, and `/metrics` endpoints and documented status semantics.
- These metric names, types, units, and label keys:

| Metric | Type | Labels |
| --- | --- | --- |
| `proxyt_http_requests_total` | Counter | `method`, `route`, `status` |
| `proxyt_http_request_duration_seconds` | Histogram | `method`, `route`, `status` |
| `proxyt_upstream_errors_total` | Counter | `target` |
| `proxyt_certificate_expiry_timestamp_seconds` | Gauge (Unix seconds) | None |
| `proxyt_ts2021_active_tunnels` | Gauge | None |
| `proxyt_draining` | Gauge (0 or 1) | None |
| `proxyt_shutdown_forced_tunnels_total` | Counter | None |
| `proxyt_certificate_reload_total` | Counter | `result` (`success`, `error`) |

For the planned 1.x contract, incompatible removals, renames, type changes, or
changes to existing option semantics require a major release. New optional
settings, metrics, and route/target label values may be added. Log text, internal
Go packages, histogram bucket boundaries, and experimental image tags are not
stable interfaces. Security fixes may tighten validation, with upgrade notes.
