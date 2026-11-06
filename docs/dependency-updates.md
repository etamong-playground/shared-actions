# Dependency update PRs

The opt-in `dependency-updates` action proposes npm/pnpm and Go updates using a pinned Renovate worker.
It creates draft PRs and refreshes eligible existing PRs; it never merges them or deploys their changes.

## Prerequisites

Use a trusted Linux or macOS runner with Node.js 24.11 or later in the 24.x line, npm, Python 3, make, a C++ compiler and Git 2.33 or later.
Install the caller's declared package-manager and Go versions before invoking the action.
Each npm/pnpm project needs an exact `packageManager` pin, inherited from a workspace parent when appropriate; a run accepts one installed version per package manager.
The action rejects mismatched versions and unexcluded Yarn/Bun projects instead of letting the engine silently ignore global-tool constraints.
The worker uses installed binaries and keeps Go/toolchain directive updates disabled.

The caller checks out its default branch with `persist-credentials: false`, serializes updater jobs, and obtains a short-lived GitHub App installation token limited to that repository.
Keep issuance and post-job revocation in the caller's existing credential integration; the shared action accepts the token, not an App signing key.
Never supply a personal operator token as a substitute for a missing installation grant.

| Run | Installation token permissions |
| --- | --- |
| Dry-run | Contents, Pull requests, Commit statuses and Issues read |
| Draft PR writes | Contents, Pull requests and Commit statuses write; Issues read |

The engine reads Issues while checking dashboard state and uses Commit statuses for `renovate/artifacts` failures.
The action verifies the installation token's one-repository scope and authenticated bot identity before inspecting update work.
It cannot grant or establish the token's complete permission set; the caller must request and verify permission downscoping at issuance.
Private npm and Git sources require separate read-only credentials and explicit registry/scope or repository selectors.
The reader token must differ from the caller token, and a source-reader list cannot include the caller repository.
No credential is needed for ordinary public npm/Go dependencies beyond the caller's scoped token.

## Start with a manual dry-run

1. Add a restricted `.github/dependency-updates.json`, using the [policy example](../examples/dependency-updates/policy.json).
2. Adapt the [caller example](../examples/dependency-updates/caller.yml) to existing credentials and installed tool versions, replacing `REVIEWED_SHARED_ACTION_SHA` with a reviewed immutable shared-actions commit.
   The example assumes an already authorized caller-owned App credential configuration; retain an established broker instead of distributing new keys merely to copy it.
3. Dispatch on the default branch with `write=false`.
   Feature branches, pull-request events and mismatched caller identities are rejected.
4. After approving the caller and its credentials, dispatch with `write=true` and inspect the resulting draft PR, regenerated artifacts and required consumer CI.
   Prove artifact-error status publication on that exact update head with a controlled failure before relying on the integration.
5. Add a schedule only after its cadence, runner cost and failure-notification route have been separately approved.
   Keep the same default-branch guard, per-repository concurrency and explicit write opt-in.

The component itself installs no caller workflow and enables no recurring execution.
The source-reader and npm-registry inputs remain unset in the public-dependency example.
For private sources, `source-repositories` is a JSON array such as `["example-org/private-library"]`, with the corresponding scoped read token in `source-token`.
For a private npm registry, provide all of `package-token`, `package-scope` (for example `@example-org`) and `registry-url` (for example `https://packages.example/team/`).
Use HTTPS without embedded credentials, query or fragment, and include the trailing slash.

## Restricted policy and preservation

Policy accepts only `commitMessagePrefix`, `commitMessageAction`, `prBodyTemplate`, `ignoreDeps` and `ignorePaths`.
Repository Renovate configuration is ignored; a policy cannot enable commands, install hooks, plugins, automerge, auto-approval or additional managers.
Secrets remain runtime values and are excluded from generated policy files, captured worker output and retained caches.
Engine dependencies are locked to Renovate 44.221.1; setup installs with hooks disabled and compiles the locked RE2 source directly.
This trusted engine build does not enable dependency lifecycle scripts.

Minor/patch updates are grouped separately for npm and Go; majors remain separate.
Explicit private package/source selectors stay outside unrelated groups.
The caller's manifest and matching lockfile/checksums belong in the same update PR.
Package-manager and runtime declarations are excluded from selection and checked again against full base/head manifests; update those tools separately.
Go import-path migrations and toolchain upgrades remain manual work.

`max-open-prs` defaults to three and accepts 1 through 10.
At capacity, maintenance mode refreshes eligible existing PRs while blocking new branches and PRs from orphan branches.
Every open worker PR consumes a slot, including paused ecosystems.
Incomplete API history, the 250-commit inspection ceiling, the PR-file API ceiling or a recently autoclosed updater PR stops the run instead of guessing whether creation is safe.
The seven-day autoclosed-PR hold prevents native reuse from bypassing creation counters.
The worker does not delete that PR or its branch; retain it for explicit disposition or wait until the hold expires.
Concurrency serializes this caller workflow only; another writer can change PR state after inspection.

An open foreign manifest/lockfile PR pauses its entire ecosystem, including renamed paths.
A human author or committer on an updater branch also pauses its ecosystem before execution; native Git author checks add another preservation check.
If all supported ecosystems are paused, the action fails explicitly.
Manual rebase titles, the native rebase checkbox and rebase labels stop the worker for explicit branch disposition rather than overriding human changes.
Git author metadata is not an authorization boundary, and concurrent edits remain subject to native Git push protection.
Closed update PRs and stale branches are retained.
Native security-alert PR creation is disabled because it has a separate quota path; ordinary updates can still include security-fix releases.
This is not an advisory detector or a replacement for existing vulnerability reporting.

## Failure and recovery

The action forces positive artifact-status publication and requires the latest `renovate/artifacts` status to be successful and authored by the configured bot on each eligible update head.
Missing, foreign or failed publication stops the job, as do worker errors and incomplete GitHub inspection.
Heads deliberately paused before execution are excluded only while their exact SHA remains unchanged; no new artifact success is claimed for those heads.
It also rejects changes outside the dependency-file contract and compares complete Go manifests at the base/head SHAs to reject implicit compiler-directive changes.
It inspects statuses again after writing, and removes its transient work, home, config and cache state on completion, failure or catchable cancellation.
Subprocesses run in a separate group and are terminated on cancellation or timeout.
A runner crash or uncatchable kill still requires the runner's normal ephemeral-workspace disposal.

Even a successful job and a positive artifact status do not prove a working application; an absent required status fails the job.
Consumer CI must validate the resulting PR; a pilot must prove actual registry release selection, private access when used, status publication and repeated live PR behavior.
Worker stdout/stderr is discarded because upstream diagnostics may contain credentials; the job exposes bounded phase/exit diagnostics and update-head status failures instead.
Do not enable raw logs in a credentialed job as a debugging shortcut.

To stop future execution, disable the caller workflow or unset its write opt-in.
For an already running job, use the caller's cancellation and token-revocation controls.
Existing branches and PRs remain for human disposition.
Revert an accepted manifest update with its lock/checksum changes and any required migration under the consumer's delivery rules.
A source revert does not establish a runtime or database rollback.

## Local validation

From the repository root, prepare the engine and run:

```sh
mkdir -p .tmp
RUNNER_TEMP="$PWD/.tmp" node .github/actions/dependency-updates/prepare.mjs
node --test tests/dependency-*.test.mjs
python3 -m unittest discover -s tests -v
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
```

The fixtures exercise the real engine's configuration validator, local Git maintenance and author detection, npm/pnpm tarball integrity, Go checksums through a file-only proxy, and Git/HTTP credential selection with synthetic values.
They do not create live update PRs, prove private installation permissions or validate a running application.
The fixture-only pnpm version in the runtime development dependencies does not select the consumer's package-manager version.
