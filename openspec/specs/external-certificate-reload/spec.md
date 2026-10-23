# External certificate reload

## Purpose

Define validation and atomic reload of externally managed TLS certificates without interrupting established connections.

## Requirements

### Requirement: External certificates are validated before serving

In TLS mode with `issue=false`, ProxyT MUST load `<cert-dir>/<domain>.crt` and `<cert-dir>/<domain>.key` before opening listeners. It MUST reject unreadable or malformed files, a mismatched key pair, a leaf outside its validity interval, or a leaf that does not cover the configured domain. Validation MUST NOT require external network access. HTTP-only and automatic-issuance modes MUST NOT start an external-certificate polling worker.

#### Scenario: Initial external certificate is invalid
- **WHEN** initial files are missing, unreadable, malformed, mismatched, expired, not yet valid, or for a different hostname
- **THEN** startup MUST fail before serving and identify the failure without logging private material

#### Scenario: Certificate ownership belongs elsewhere
- **WHEN** ProxyT starts in HTTP-only mode or automatic-issuance mode
- **THEN** it MUST retain that mode's certificate ownership behavior and MUST NOT poll external certificate files

### Requirement: Reload publishes a complete valid pair atomically

ProxyT MUST re-read external certificate paths every `cert-reload-interval` and publish a complete validated pair atomically. Re-reading MUST support atomic file and symlink-target replacement. New TLS handshakes, readiness, and expiry metrics MUST use the active snapshot. Existing connections MUST NOT be interrupted by certificate replacement. Identical valid content MUST be a no-op.

#### Scenario: Mounted Secret rotates
- **WHEN** a mounted directory's symlink target changes to a valid replacement pair and the next poll completes
- **THEN** subsequent full TLS handshakes MUST present the replacement certificate
- **AND** existing tunnels MUST continue exchanging bytes
- **AND** readiness and certificate expiry metrics MUST reflect the active replacement

#### Scenario: Concurrent handshakes during rotation
- **WHEN** TLS handshakes overlap certificate publication
- **THEN** each handshake MUST observe a complete old or new pair, never a partially updated pair

#### Scenario: Content is unchanged
- **WHEN** a poll reads the same valid pair as the active snapshot
- **THEN** it MUST NOT count as a successful replacement or disrupt connections

### Requirement: Failed reload preserves last-known-good state

An invalid or unreadable replacement MUST leave the active snapshot unchanged and MUST be retried on subsequent polls. A failed reload MUST NOT by itself make a replica unready while its active certificate remains valid and other readiness conditions hold. If that active certificate expires, readiness MUST fail. Reload failures and recovery MUST be observable without exposing keys or certificate contents.

#### Scenario: Files are temporarily inconsistent
- **WHEN** a poll reads a mismatched pair during rotation
- **THEN** ProxyT MUST retain the previous certificate and retry at the next interval

#### Scenario: Replacement recovers
- **WHEN** valid replacement files become available after failed polls
- **THEN** ProxyT MUST publish them on a subsequent poll without restarting

#### Scenario: Active certificate expires during reload failures
- **WHEN** replacements remain invalid and the active snapshot expires
- **THEN** readiness MUST return HTTP 503 and expiry metrics MUST continue reporting the active certificate's expiry
