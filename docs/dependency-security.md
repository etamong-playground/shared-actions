# Dependency security evidence

The collector checks open Dependabot alerts against an immutable source commit without executing that repository's code.
It reads pnpm v6/v9 lockfiles and Go module requirements, including indirect dependencies.
It does not create update PRs or replace an updater.

## Prerequisites

The caller needs a supported runner with Node.js 22 or later, Python 3 for the reusable workflow bootstrap, and Corepack with pnpm 10.28.0.
Supply an explicit read-only GitHub credential authorized for the caller's contents and Dependabot alerts.
A repository's ordinary Actions token does not establish Dependabot-alert access.
Use an isolated runner; the collector's immutable dependencies are installed with lifecycle scripts disabled before the read credential is exposed to its inspection step.
No application or publishing credentials belong in this job.

## Read-only caller

Replace `<immutable-helper-sha>` with a reviewed 40-character commit from this repository.
Keep this job isolated from application tests; the collector does not need a caller checkout.
Fork PRs normally cannot receive this read credential, so qualify that access policy rather than treating a failed inspection as clean.

```yaml
name: Dependency evidence
on: [pull_request, push]
permissions:
  contents: read
jobs:
  inspect:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: corepack enable
      - uses: etamong-playground/shared-actions/.github/actions/dependency-security@<immutable-helper-sha>
        with:
          alerts-read-token: ${{ secrets.DEPENDABOT_READ_TOKEN }}
```

This direct helper example does not enable receiver delivery.
Authenticated history additionally requires an immutable reusable-workflow publisher and explicit receiver policy.

## Outcomes and limits

The job summary and JSON artifact distinguish:

| Result | Meaning | Exit |
| --- | --- | --- |
| `clean` | Complete inspection found no affected resolved version among the inspected open alerts | 0 |
| `findings` | Affected versions remain; a missing upstream patch is recorded explicitly | 1 |
| Error or incomplete coverage | Inspection could not establish its declared scope, even if some known findings were collected | 2 |

An empty alert list is clean only within the open-alert scope.
It is not a complete dependency inventory, OSV comparison, call-graph reachability analysis or deployed-image scan.
Failed access, changing pagination, unsupported ecosystems or formats, missing expected packages and Go replacements remain incomplete evidence.
The Go minimum-version directive is never treated as the compiled standard-library version.
Removing an alert or publishing a fix does not by itself prove runtime remediation.

The collector reads at most ten pages of 100 alerts, 64 source files, 1 MiB per file and 8 MiB of source content.
It rejects truncated repository trees, limits its report to 1 MiB and has bounded HTTP timeouts.
Exceeding a limit fails coverage; it never silently truncates a clean result.
PR inspection uses the event's source head and checks it again before completion.
The report retains the execution SHA separately from that source head.

## Receiver contract

Default-branch delivery is optional and is restricted to `push`, `schedule` and `workflow_dispatch`.
PR results stay in their CI job and artifact.
A compatible receiver accepts `POST` with the exact JSON bytes and a Bearer GitHub OIDC token.
The token audience is the exact configured HTTPS endpoint plus `#sha256=` and the lowercase SHA-256 of those bytes.
The sender follows no redirects and never prints or stores the token.

The receiver must verify GitHub's signature, issuer, validity and body-bound audience, then match an explicit publisher policy to signed repository/owner IDs, repository name, default ref, caller workflow and immutable reusable-workflow ref/SHA.
The report's repository, source, execution run/attempt/SHA and collector revision must match those trusted claims and the allowed helper revision.
Reject missing claims, PR events, mismatched metadata and unregistered publishers; do not substitute an internal shared secret or caller-provided counts.
Actual claim presence for each allowed event needs a controlled live qualification.

The reusable workflow pins this helper literally.
Direct invocation of a composite action does not establish the required reusable-workflow identity.
Do not add caller inputs that choose the collector revision, source repository or report body.

Store metadata only, keyed by repository ID, execution run ID and attempt.
An identical replay returns `200 {"status":"already_stored"}`; a new report returns `201 {"status":"stored"}`.
Reject a different body for an existing identity and retain new attempts as separate history.
Do not reconcile a partial or failed report as a full inventory snapshot.
Keep error and incomplete results visible, and gate report reads by the receiver's explicit access policy.

## Local qualification

```sh
corepack pnpm --dir .github/actions/dependency-security install --frozen-lockfile --ignore-scripts
corepack pnpm --dir .github/actions/dependency-security test
```

Tests use controlled GitHub responses and synthetic identities.
They verify residual vulnerable versions, patched and no-fix cases, stale heads, incomplete evidence, parser behavior and exact-body delivery.
They do not establish a caller's grants, actual OIDC claims, receiver availability or live delivery.
Approve and qualify those prerequisites before enabling a caller or recurring schedule.
