## 1. Runtime configuration

- [x] 1.1 Add validated runtime settings for `shutdown-delay`, `shutdown-timeout`, `upstream-connect-timeout`, and `cert-reload-interval`, with defaults and CLI help from the design.
- [x] 1.2 Bind the settings through existing Cobra/Viper flag, environment, and YAML precedence; reject malformed, out-of-range, and overflowing durations before listeners start.
- [x] 1.3 Extend configuration tests for defaults, precedence, zero delay, invalid values in every serving mode, and shutdown-duration sum overflow.

## 2. Lifecycle and connection ownership

- [x] 2.1 Introduce an instance-owned monotonic lifecycle and synchronized admission/registration API for requests, pending upgrades, and established connections, with idempotent drain and cleanup.
- [x] 2.2 Add admission gating that returns 503 for new proxy work during drain, including keep-alive requests, while health, readiness, and metrics remain accessible on open listeners.
- [x] 2.3 Track `/ts2021` work before dial through hijack and relay completion; also cover generic reverse-proxy upgrades and ensure exactly-once deregistration.
- [x] 2.4 Replace signal shutdown with propagation delay followed by concurrent server shutdown under one shared drain deadline, then forced cancellation/closure and worker cleanup.
- [x] 2.5 Add deterministic lifecycle tests for repeated drain, no upstream work after admission closes, natural completion, multiple listeners, forced tunnel closure, and shutdown racing upgrade transitions.

## 3. Bounded upstream establishment

- [x] 3.1 Replace the unbounded control-plane dial with an injectable context-aware establishment path covering TCP dial, TLS handshake, request write, and upstream response headers under one deadline.
- [x] 3.2 Wire request and forced-shutdown cancellation to pending I/O, retain one-attempt error behavior, and clear setup deadlines on successful handoff to tunneling.
- [x] 3.3 Ensure relay cleanup closes both endpoints, unblocks and joins both copying directions, and preserves bytes buffered by response parsing and hijacking.
- [x] 3.4 Add hermetic tests for each stalled setup stage, cancellation, no replay, buffered payloads, and healthy tunnels that outlive the establishment timeout.

## 4. External certificate rotation

- [x] 4.1 Add a concurrency-safe certificate snapshot loader validating key matching, leaf validity, and configured hostname before external-TLS startup.
- [x] 4.2 Add lifecycle-owned polling of existing certificate paths, atomic publication, unchanged-content detection, and last-known-good retention with retry after failures.
- [x] 4.3 Wire the snapshot getter into TLS handshakes, readiness, and expiry reporting; retain automatic-issuance and HTTP-only certificate ownership modes.
- [x] 4.4 Add generated-certificate unit tests for startup rejection, invalid replacements, expiry, unchanged content, and recovery, including atomic symlink-directory replacement.
- [x] 4.5 Add local TLS tests for concurrent handshakes during rotation and verify that an established tunnel survives replacement while new handshakes see the new certificate.

## 5. Lifecycle observability

- [x] 5.1 Make readiness check lifecycle before dependency I/O and before returning success, while retaining upstream-independent liveness and evaluating the active certificate's validity interval.
- [x] 5.2 Add draining, forced-tunnel, and certificate-reload metrics with bounded labels and exactly-once counts; report active certificate expiry even after expiry.
- [x] 5.3 Add structured transition, deadline, cleanup-summary, and reload/recovery logs; bound repeated identical reload errors and omit keys and payloads.
- [x] 5.4 Extend metrics and logging tests for drain/readiness races, no dependency calls while draining, forced-close counts, reload outcomes, and active certificate expiry.

## 6. End-to-end runtime verification

- [x] 6.1 Add a hermetic multi-instance test demonstrating reconnection through a second independent replica after the first drains, without shared state or session affinity.
- [x] 6.2 Exercise actual runtime signal wiring in a local process test, confirming readiness withdrawal, admission rejection, bounded termination, and cancellation of pending establishment without public network access.
- [x] 6.3 Format changed Go files and run `go test ./...`, `go test -race ./...`, and `go vet ./...`; fix failures and verify existing direct, HTTP-only, and automatic-certificate tests remain compatible.
- [x] 6.4 Review implementation against all five capability specs and confirm no provider-specific dependencies, copied private code, deployment manifests, or DOKS validation work entered this change.
