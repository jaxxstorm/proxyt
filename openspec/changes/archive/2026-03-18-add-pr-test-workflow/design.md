## Context

The repository currently has a release workflow at [release.yml](/home/lbriggs/src/github/jaxxstorm/proxyt/.github/workflows/release.yml) but no pull request workflow. Proxyt’s current automated test coverage lives in the normal Go test suite, including helper-level unit tests and `httptest`-based integration tests under [cmd/serve_test.go](/home/lbriggs/src/github/jaxxstorm/proxyt/cmd/serve_test.go). That means CI does not need special external infrastructure today to validate the new proxy test surface; it mainly needs a reliable pull request workflow that runs the suite consistently.

## Goals / Non-Goals

**Goals:**

- Add a maintainable GitHub Actions workflow for pull request validation.
- Run the existing automated unit and integration test coverage in CI.
- Keep the workflow simple and aligned with the repo’s release workflow conventions.
- Make CI failure states obvious to contributors and reviewers.

**Non-Goals:**

- Redesign the release workflow.
- Introduce complex matrices, caching strategies, or deployment checks in this change.
- Split the current Go test suite into separate binaries unless implementation shows that is necessary.

## Decisions

### Decision 1: Add a dedicated pull request workflow

Create a new workflow under `.github/workflows/` that triggers on pull request activity. This keeps test validation separate from release concerns and gives reviewers a clearly named CI check for pre-merge validation.

### Decision 2: Use the existing Go test command as the initial validation target

Because the project’s integration coverage is currently implemented as `httptest`-based tests inside the normal Go test suite, the workflow can start by running `go test ./...`. That satisfies the requirement to run both unit and integration coverage without adding extra command plumbing that the repository does not currently need.

If the project later introduces separate long-running integration targets, the workflow can evolve into multiple jobs or commands without invalidating this initial design.

### Decision 3: Match the release workflow’s core setup pattern

Reuse the same general GitHub Actions setup style already present in `release.yml`:

- `actions/checkout`
- `actions/setup-go`
- GitHub-hosted Ubuntu runner

This reduces maintenance overhead and avoids mixing conflicting CI idioms in a small repository.

## Affected Components

- `.github/workflows/` for the new pull request test workflow
- Potentially documentation or contributing guidance if CI behavior needs to be explained

## Migration Concerns

- The workflow should use the project’s Go version expectations so CI matches local development as closely as possible.
- If `go test ./...` begins to include slower or more environment-sensitive tests later, the workflow may need to split jobs or tags, but that is not required for the current test suite.
- The workflow file should stay minimal enough that failures are easy to diagnose from standard Actions logs.

## Verification Plan

- Add the workflow YAML.
- Run `go test ./...` locally to confirm the command used by CI passes in the repository state being proposed.
- Optionally inspect the workflow file structure against the existing release workflow for consistency before implementation is complete.
