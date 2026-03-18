## ADDED Requirements

### Requirement: Pull Requests Run Automated Test Validation

Proxyt MUST run its automated Go test validation for pull requests in GitHub Actions.

#### Scenario: Pull request triggers CI

- **WHEN** a pull request is opened, synchronized, or reopened against the repository
- **THEN** GitHub Actions MUST start the pull request test workflow
- **AND** the workflow MUST run on a GitHub-hosted runner with the repository checked out

#### Scenario: Test suite is executed

- **WHEN** the pull request workflow runs
- **THEN** it MUST install the project’s Go toolchain
- **AND** it MUST execute the repository’s unit and integration test coverage using the standard Go test command or an explicitly equivalent sequence

#### Scenario: Failures block the check

- **WHEN** any unit or integration test fails in the pull request workflow
- **THEN** the workflow MUST exit with a failed status
- **AND** the pull request check result MUST reflect that failure to reviewers

### Requirement: Workflow Aligns With Current Repository CI Patterns

The pull request test workflow SHOULD follow the repository’s existing GitHub Actions conventions closely enough to remain maintainable beside the release workflow.

#### Scenario: Workflow uses repository-compatible setup

- **WHEN** the workflow is defined
- **THEN** it SHOULD use standard GitHub Actions steps such as checkout and Go setup that are already compatible with the repository
- **AND** it SHOULD avoid introducing unnecessary CI services or dependencies when `go test ./...` is sufficient
