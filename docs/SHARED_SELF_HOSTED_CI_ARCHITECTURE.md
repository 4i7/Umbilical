# Shared Self-Hosted CI Execution Architecture

## Status

Shared cross-repository architecture direction for:

- `4i7/WorkGraph`
- `4i7/SolRelay`
- `4i7/KernelFleet`
- `4i7/Umbilical`

Repository-specific workflows may temporarily differ while migrating, but new CI work should preserve the boundaries in this document unless an explicit architecture decision replaces them.

## Problem statement

The required CI path must not depend on GitHub-hosted runner capacity, billing, or hosted-runner quota before work can reach an available self-hosted runner.

A second failure mode must also be avoided: CI repair must not require the previous revision of CI to already be green. A failed `main` validation result is evidence about that revision; it must not become a circular prerequisite that prevents a repair candidate from being tested.

The architecture therefore separates GitHub's scheduling/control plane from the execution plane and keeps recovery simpler than the normal authority machinery.

## Core execution model

GitHub Actions remains the scheduler and event source. Required repository validation executes on repository-scoped self-hosted Windows runners.

```text
pull request / push main
        |
        v
GitHub Actions scheduler
        |
        v
trusted repository-specific self-hosted Windows runner
        |
        +-- bind exact candidate SHA
        +-- checkout exact candidate
        +-- prove exact HEAD
        +-- environment preflight
        +-- validate / build / test
        +-- publish optional result evidence
```

No required job in this path should need a GitHub-hosted runner merely to decide whether the self-hosted job may start.

## Normal CI rules

1. Use `pull_request` and `push` for ordinary validation unless base-context authority is genuinely required.
2. Execute required jobs directly on the repository's self-hosted runner labels.
3. Bind validation to the exact candidate commit SHA and verify the checked-out HEAD before running repository code.
4. Treat validation statuses, attestations, artifacts, and governance records as outputs/evidence. Do not require a previous revision's success status merely to start validation of a repair candidate.
5. Keep workflow permissions at the minimum needed for validation. Candidate validation should normally be read-only with respect to repository contents.
6. Do not execute untrusted fork code on a persistent self-hosted runner. Repositories that accept external PRs must either restrict persistent-runner CI to trusted same-repository/same-owner candidates or use a separately isolated execution surface.
7. Workflow/control-plane changes may receive stronger review than ordinary source changes, but that review must not recreate a hosted-runner bootstrap dependency.

## Break-glass recovery lane

Each repository may keep a small recovery workflow sourced from trusted `main` and invoked explicitly with an exact target ref/SHA.

```text
workflow_dispatch from trusted main
        |
        v
self-hosted Windows runner
        |
        +-- verify current trusted workflow identity
        +-- verify exact remote target ref + SHA
        +-- detached exact checkout
        +-- validate / build / test
        +-- rebind identities before accepting the result
```

This lane exists for a broken normal workflow or other control-plane bootstrap failure. It must remain smaller and easier to reason about than the normal CI system.

The recovery lane must not require Umbilical, another repository, a prior green status, or a GitHub-hosted runner in order to validate a repair candidate.

## `pull_request_target` policy

`pull_request_target` is not the default normal-CI mechanism.

Use it only when a concrete operation truly requires trusted base-repository context. If used, it must not become a general pre-validation authority layer that duplicates GitHub identity checks, repository state, workflow provenance, and validation state before a self-hosted job can run.

Persistent self-hosted runners must never execute untrusted candidate code merely because a `pull_request_target` workflow admitted the event.

## Windows runner contract

These repositories currently target Windows execution. CI should make that operational contract explicit instead of relying on environment accidents.

Preferred repository-scoped runner labels are conceptually:

```text
WorkGraph:   [self-hosted, Windows, X64, workgraph-ci]
SolRelay:    [self-hosted, Windows, X64, solrelay-ci]
KernelFleet: [self-hosted, Windows, X64, kernelfleet]
Umbilical:   [self-hosted, Windows, X64, umbilical-ci]  # when normal CI uses a persistent runner
```

PowerShell steps should use the shell actually guaranteed by the Windows runner contract. `powershell` is the baseline when Windows PowerShell is the installed guaranteed shell. `pwsh` may be used only when PowerShell 7 is explicitly part of the runner contract. `bash` should be requested only for steps that deliberately depend on a guaranteed Bash installation.

Runner prerequisites should be validated early and fail with a direct environment error rather than surfacing later as unrelated test failures.

## Separate failure domains

The following are different systems and must not be collapsed into one success/failure bit:

```text
CI execution     = can the exact source build and pass its tests?
Governance       = may the development process advance under repository policy?
Publication      = can durable evidence/status/artifacts be published?
Release          = can a distributable artifact be produced and released?
Coordination     = what work/role/decision should happen next?
```

A publication failure does not mean CI was unable to execute. A governance failure does not imply the runner is unavailable. A release failure does not invalidate a successful source test unless the release artifact itself is the tested subject.

Keeping these states distinct prevents a secondary subsystem from blocking unrelated development and makes recovery local to the actual failed boundary.

## Repository responsibility boundaries

### WorkGraph

WorkGraph owns AI work coordination, durable Task/Result/Decision state, routing contracts, and coordination evidence. It should not need to become a general-purpose machine scheduler or an external CI authority merely to run repository tests.

Its normal repository CI should converge toward the same simple self-hosted exact-head validation model used by the other repositories. Complex authority checks are justified only where they protect a real WorkGraph coordination invariant, not as prerequisites for ordinary source validation.

### SolRelay

SolRelay owns relay/transport behavior between ChatGPT-facing workflows and external coordination/runtime surfaces. It is not the CI authority for the other repositories.

Its existing direct self-hosted Windows CI model is the reference shape: event -> dedicated runner -> checkout -> build/typecheck/lint/test.

### KernelFleet

KernelFleet owns product code and KernelFleet-specific development governance. Its product CI, governance validation, evidence publication, and release workflows should remain separate failure domains.

KernelFleet development should not be blocked merely because an unrelated publication or coordination subsystem failed after source validation succeeded.

### Umbilical

Umbilical remains an external/local execution-authority substrate and optional break-glass/fallback research path. It is not a required dependency of normal WorkGraph, SolRelay, or KernelFleet CI.

Umbilical may retain its completed execution-authority work without being placed on the critical path for ordinary pull-request validation.

Because Umbilical is public, persistent self-hosted execution must not admit arbitrary external fork code without an isolation policy specifically designed for that trust boundary.

## Migration policy

Migration is functionality-first and deliberately incremental:

1. Restore currently required self-hosted CI paths without adding new architecture dependencies.
2. Do not interrupt an in-flight repair merely to perform a conceptual cleanup.
3. Once stable, simplify WorkGraph normal PR CI toward direct self-hosted exact-head validation.
4. Retain a small exact-ref/SHA self-hosted `workflow_dispatch` recovery path.
5. Remove any rule that makes prior `main` validation success a circular prerequisite for testing the repair of a red `main`.
6. Keep Umbilical parked outside the ordinary CI dependency graph unless a future requirement specifically needs its execution-authority properties.
7. Consider reusable workflows only after the individual repository paths are stable; sharing implementation must not merge repository authority boundaries.

## Cross-repository invariant

The common target state is:

> Each repository can validate a trusted pull-request candidate on its own self-hosted Windows execution surface, using the exact candidate identity, without requiring GitHub-hosted runner capacity, another repository, or the previous revision's successful CI status.

A repository whose normal workflow is broken must still have a bounded trusted-main exact-ref/SHA recovery path that uses the same self-hosted execution surface.

## Non-goals

This shared direction does not require:

- replacing GitHub Actions as the event scheduler;
- moving normal CI authority into Umbilical;
- cross-repository CI admission dependencies;
- Linux or macOS parity;
- ephemeral runner infrastructure for the current trusted private-repository development path;
- one giant shared workflow for all repositories;
- treating every governance/publication failure as a CI failure.

Those may be separate future decisions if concrete requirements justify them.
