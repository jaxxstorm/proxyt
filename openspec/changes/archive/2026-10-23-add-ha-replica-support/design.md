## Context

`cmd/serve.go` currently constructs HTTP servers, loads certificates, handles signals, and implements `/ts2021` tunneling. `http.Server.Shutdown` does not own hijacked sockets. The custom upgrade path uses an unbounded TLS dial and upstream response read, and the externally supplied certificate getter captures a startup snapshot. Readiness checks dependencies but not process lifecycle.

The proxy forwards the Noise stream to Tailscale; it cannot inspect encrypted requests, route control shards, inject protocol heartbeats, or migrate a stream. Independent replicas already share no application session state. The product must preserve those properties and work behind a protocol-compatible frontend without provider-specific code.

## Goals / Non-Goals

**Goals:**
- Predictable, bounded termination in containers with explicit ownership of pending upgrades and established tunnels.
- Immediate readiness withdrawal and configurable routing-propagation time before listener shutdown.
- External certificate rotation without interrupting existing connections.
- Deterministic duration settings, bounded observability, and hermetic concurrency/failure tests.

**Non-Goals:**
- Cloud manifests, Helm packaging, DOKS certification, or deployment documentation in this change.
- Distributed coordination, sticky sessions, shared session storage, Noise termination, or live connection migration.
- Compatibility workarounds for HTTP frontends that reject POST upgrades, new UDP services, or PROXY-protocol support.
- Reimplementing or copying private Tailscale code. Runtime code will use public Go APIs and existing dependencies.

## Decisions

### 1. Instance-owned runtime and explicit lifecycle

Introduce focused helpers under `cmd/` for runtime lifecycle, connection ownership, and external certificates rather than adding more global mutable state to `serve.go`. Inject configuration, dial behavior, and clocks/tickers where useful for hermetic tests. Existing CLI wiring remains Cobra/Viper.

The lifecycle is monotonic:

```text
serving ── SIGTERM/SIGINT ──> draining ── cleanup ──> stopped
                               │
                               ├─ immediately fail readiness
                               ├─ reject new proxy requests with 503
                               ├─ keep listeners for propagation delay
                               ├─ stop listeners; drain admitted work
                               └─ deadline: cancel/close remaining work
```

The first drain invocation fixes the schedule; subsequent invocations do not reset it. Health and metrics remain available while listeners are open. Already-admitted ordinary requests and tunnels continue during the propagation interval and bounded drain interval. New requests on existing HTTP keep-alive connections are also rejected.

Choose explicit process shutdown over a public drain endpoint: SIGTERM/SIGINT already work in containers and avoid introducing an administrative API. Kubernetes endpoint removal and frontend propagation still need deployment-specific verification later.

### 2. One shutdown budget across all listeners and connection owners

After the propagation delay, shut down HTTP servers concurrently with one shared drain deadline. Do not give each listener a fresh timeout. Wait for both normal HTTP work and tracked upgrade work; exit early after propagation if all work is complete. At expiry, cancel runtime work, close HTTP servers, and force-close tracked client and upstream sockets. Stop certificate polling and join owned workers during cleanup.

Track upgrade work before upstream establishment begins. Registration, promotion into a tunnel, and entry into drain must be synchronized so no upgrade can escape ownership in the gap around `Hijack`. Release registrations exactly once. Socket closure must unblock both copying directions and establish a joinable completion path.

Include any upgrades handled by the generic reverse proxy in connection ownership, not only `/ts2021`. A common tracking wrapper at the HTTP hijack boundary can cover generic upgraded client sockets; custom `/ts2021` tracking additionally owns upstream establishment and both stream endpoints. Normal HTTP traffic remains managed by `http.Server` plus the runtime cancellation context.

Alternative: relying on `RegisterOnShutdown` alone is insufficient because callbacks are not awaited and hijacked sockets remain outside normal server shutdown.

### 3. A setup deadline, not a tunnel lifetime deadline

Use a context-aware dial/TLS handshake with one establishment deadline covering dial, request write, and upstream response headers. Apply I/O deadlines for operations not governed by a context. Cancellation of the request or forced runtime shutdown must interrupt setup. Preserve the existing one-upstream-attempt rule and error statuses where a response is still possible.

After a successful switch, clear setup deadlines before copying opaque bytes. Established tunnels must not inherit request-context cancellation caused merely by upgrade-handler completion. Preserve client and upstream buffered bytes and track the tunnel until both directions have stopped. No application-level retries or injected keepalives are introduced.

Alternative: a global short HTTP read/write timeout would also terminate healthy long-lived tunnels; it is not a substitute for a setup-specific deadline.

### 4. Poll and atomically publish externally managed certificates

For `--issue=false` outside HTTP-only mode, retain the existing `<domain>.crt` and `<domain>.key` paths. Validate a complete matching pair, leaf validity interval, and configured hostname before first listener startup. Publish an immutable certificate snapshot through a concurrency-safe getter used by TLS, readiness, and expiry metrics.

Poll paths afresh rather than retaining open descriptors or watching only file inodes. This supports atomic directory/symlink replacement used by mounted Kubernetes Secrets and ordinary container bind mounts. Read and validate both files before swapping the snapshot. A mismatched or invalid intermediate pair is rejected; the old snapshot remains active. Byte-identical valid content is a no-op. Future polls retry failed replacements; successful replacement resets failure reporting. Do not log PEM content or keys.

Polling uses standard-library facilities and needs no new dependency. A last-known-good snapshot is still checked for current validity by readiness; a failed refresh must not conceal its eventual expiry. Automatic ACME mode keeps its existing manager, and HTTP-only mode starts no certificate polling worker.

Alternative: loading on every TLS handshake couples filesystem availability and I/O to connection establishment. Restarting for every renewal unnecessarily interrupts tunnels. Polling provides a bounded renewal delay and preserves existing connections.

### 5. Concrete configuration contract

All duration values use Go duration syntax through flags, `PROXYT_*` environment variables, and YAML, with existing precedence. Parse resolved values with errors rather than silently coercing malformed input to zero.

| Setting | Default | Validation | Meaning |
|---|---|---|---|
| `shutdown-delay` | `5s` | >= 0 | Time from drain entry to listener shutdown |
| `shutdown-timeout` | `25s` | > 0 | Shared drain budget after the delay |
| `upstream-connect-timeout` | `10s` | > 0 | Entire `/ts2021` upstream establishment, not just TCP dial |
| `cert-reload-interval` | `30s` | > 0 | External certificate poll interval |

Validate duration syntax and bounds in every mode, including unused reload settings, so configuration errors are deterministic. Validate the sum of shutdown durations against overflow. The normal default shutdown schedule is at most 30 seconds before forced cleanup; container termination grace must leave additional cleanup margin. CLI help must accurately describe each setting. Startup configuration is immutable; this change reloads certificates, not YAML.

### 6. Observability reflects active runtime state

Keep existing request, upstream error, active-tunnel, and certificate-expiry metrics. Add:
- `proxyt_draining`: gauge, 0 while serving and 1 after drain begins.
- `proxyt_shutdown_forced_tunnels_total`: counter of established tunnels actually forced closed by the shutdown deadline, once per tunnel.
- `proxyt_certificate_reload_total{result="success|error"}`: successful changed-certificate publications and failed reload attempts; unchanged polls are not successes.

Use bounded labels only. Log lifecycle transitions, effective shutdown deadlines, summary counts, and reload success/failure/recovery with the existing logger. Repeated identical reload failures should be rate-limited or logged on transition to prevent poll-driven noise; the error counter still records failed attempts. These structured events provide operational auditability without durable audit infrastructure.

Readiness checks lifecycle before dependency I/O and again before returning success, so a check racing with drain cannot publish a successful result after observing drain. Certificate expiry metrics read the active snapshot, including an expired snapshot, rather than leaving a stale value when refresh fails.

## Risks / Trade-offs

- [Existing tunnels cannot survive process or node loss] → Preserve them during bounded drain and rely on client reconnection; never promise socket migration.
- [Long-lived tunnels may never finish naturally] → A fixed deadline forces cleanup; deployments pace replica replacement to control reconnect load.
- [A frontend may still send traffic during endpoint withdrawal] → Keep the listener available during propagation and return 503 for newly admitted work; measure the required delay in follow-up platform testing.
- [Certificate projection updates can race reads] → Validate the complete pair before atomic publication and retry without dropping the active pair.
- [Certificate validation tightens manual-certificate startup behavior] → Fail clearly before listening for expired, not-yet-valid, wrong-host, or malformed certificates; keep existing filenames and configuration modes.
- [Shutdown/hijack races are easy to miss] → Gate-controlled tests exercise all transition boundaries under `go test -race ./...`.
- [LB idle policies vary] → Declare stream-preserving frontend requirements and validate actual idle/reconnect behavior in provider-specific follow-up work.

## Migration Plan

No persistent state migration or new service dependency is needed. Existing invocations inherit bounded lifecycle defaults. Operators using external certificates gain polling automatically; ACME and HTTP-only modes retain their certificate ownership model. Later deployment documentation will specify mount layout, compatible LB modes, probe setup, and termination grace budgeting.

Rollback consists of deploying the previous binary and omitting newly introduced flags if used. Certificate files are read-only and remain compatible with the previous filename layout. Rollback restores startup-only certificate loading and the former shutdown behavior.

## Open Questions

No artifact-blocking questions remain. Exact provider idle limits, endpoint-removal propagation time, and reconnection latency are deliberately left to the separate DOKS validation change; the runtime settings allow those measurements to inform deployment configuration.
