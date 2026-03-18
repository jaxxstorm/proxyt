## Why

Proxyt now has meaningful unit and integration coverage, but there is no pull request workflow that runs those checks before changes are merged. That leaves the project vulnerable to regressions slipping through unless contributors remember to run the full test suite locally, and it means pull requests do not provide a consistent signal about whether the proxy contract still passes under CI.

## What Changes

- Add a GitHub Actions workflow that runs on pull requests.
- Ensure the workflow installs the project’s Go toolchain and executes the repository’s unit and integration test coverage.
- Keep the workflow aligned with the repo’s existing Actions style so it is easy to maintain alongside the release workflow.
- Make pull request test failures visible as a standard CI signal for contributors and reviewers.

## Capabilities

### New Capabilities

- `ci-testing`: Proxyt validates pull requests by running its automated Go test coverage in GitHub Actions before merge.

## Behavior

- Proxyt MUST have a pull request workflow that runs automatically for pull request events.
- The workflow MUST execute the repository’s automated unit and integration tests in CI.
- The workflow MUST fail the pull request check when the test suite fails.
- The workflow SHOULD use the project’s configured Go version and standard GitHub-hosted runners unless a stronger requirement emerges during implementation.

## Idempotency And Retry Semantics

- Re-running the workflow for the same commit and repository state MUST run the same test commands and produce equivalent pass/fail behavior, aside from normal CI nondeterminism outside the repository’s control.
- The workflow MAY be re-run manually through GitHub Actions without requiring changes to the pull request contents.
- The workflow MUST NOT depend on mutable external infrastructure beyond normal GitHub Actions runner setup and Go module resolution.

## Failure Modes And Recovery

- If unit or integration tests fail in CI, the workflow MUST exit non-zero so the pull request check is marked failed.
- If the repository’s current test suite is too coarse to distinguish fast unit-only coverage from slower integration coverage, the workflow MAY initially run the combined `go test ./...` command while follow-up work splits targets more explicitly.
- If CI configuration changes reveal missing setup steps, the workflow SHOULD be updated in-repo rather than relying on undocumented manual reruns or contributor-specific local workarounds.

## Observability And Audit

- Pull requests SHOULD show a named workflow or job that makes it clear test validation ran.
- The workflow logs SHOULD make the executed Go setup and test command easy to inspect when failures occur.
- The workflow SHOULD provide a stable CI signal reviewers can use to confirm the automated proxy tests passed.

## Test Plan Summary

- Verify the new workflow YAML is syntactically valid and consistent with the project’s existing GitHub Actions style.
- Confirm the workflow runs `go test ./...` or the equivalent combination of unit and integration test commands.
- Validate the workflow by running the repository test suite locally after adding the CI configuration.

## Impact

- `.github/workflows/`: add a pull request workflow for automated tests.
- Contributor workflow: pull requests gain a standard automated validation check.
- Future CI evolution: creates a place to split unit and integration jobs later if the test suite grows.
