# Dependency security evidence

The collector checks open Dependabot alerts against an immutable source commit without executing that repository's code.
It verifies registry-integrity pnpm v6/v9 lockfile entries with importers, including transitive dependencies.
Unsupported resolutions and layouts remain incomplete; this is not a substitute for the package manager validating its entire lockfile.
Go requirements are declaration evidence only; Go alerts remain incomplete because a requirement does not establish the selected graph or workspace replacements.
It does not create update PRs or replace an updater.

## Prerequisites

Use an isolated Linux runner with Bash and Corepack; the reusable workflow supplies Node.js 22.
Direct helper callers supply Node.js 22 or later themselves.
The immutable helper selects pnpm 10.28.0 from its own package metadata.
Supply an explicit read-only GitHub credential authorized for the caller's contents and Dependabot alerts.
A repository's ordinary Actions token does not establish Dependabot-alert access.
Use an isolated runner; the collector's immutable dependencies are installed with lifecycle scripts disabled before the read credential is exposed to its inspection step.
No application or publishing credentials belong in this job.

## Read-only caller

Use the [reusable workflow](../.github/workflows/dependency-security.yml) for an isolated read-only job and the [complete caller example](../examples/dependency-security/caller.yml) to opt in.
Pin the workflow to a reviewed 40-character commit containing that file.
The example's default branch is `main`; change its push filter when the caller uses another default branch.
The `runner` input accepts the caller's approved isolated runner label and defaults to `ubuntu-latest`.
Review hosted-runner usage before adopting that default in a private repository.
The workflow grants only `contents: read`, does not check out caller code and exposes no receiver or OIDC option.
Findings and incomplete evidence fail the job; an artifact is retained when the helper has produced a report, including after its outcome enforcement fails.
Failure before report creation remains a failed job without an artifact.

For an existing custom job, invoke the composite helper directly:

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
      - id: evidence
        uses: etamong-playground/shared-actions/.github/actions/dependency-security@<immutable-helper-sha>
        with:
          alerts-read-token: ${{ secrets.DEPENDABOT_READ_TOKEN }}
      - uses: actions/upload-artifact@v4
        if: ${{ always() && steps.evidence.outputs.report-path != '' }}
        with:
          name: dependency-security
          path: ${{ steps.evidence.outputs.report-path }}
          if-no-files-found: error
          retention-days: 14
```

This direct helper example does not enable receiver delivery.
Authenticated history additionally requires an immutable reusable-workflow publisher and explicit receiver policy.

## Outcomes and limits

The job summary and JSON artifact distinguish:

| Result | Meaning | Exit |
| --- | --- | --- |
| `clean` | Complete inspection found no affected resolved version among the inspected open alerts | 0 |
| `findings` | Complete inspection found affected versions; a missing upstream patch is recorded explicitly | 1 |
| Error or incomplete coverage | Inspection could not establish its declared scope, even if some known findings were collected | 2 |

Incomplete coverage takes precedence as `error`, while confirmed checks and `finding_count` remain visible.
An empty alert list is clean only within the open-alert scope.
It is not a complete dependency inventory, OSV comparison, call-graph reachability analysis or deployed-image scan.
Failed access, observed pagination changes, unsupported ecosystems or formats, missing expected packages and Go replacements remain incomplete evidence.
The Go minimum-version directive is never treated as the compiled standard-library version.
Removing an alert or publishing a fix does not by itself prove runtime remediation.

The collector compares two consecutive traversals of at most ten pages of 100 alerts each.
A mismatch fails coverage; the API has no atomic snapshot, so changes invisible to both observations remain possible.
It reads at most 64 source files, 1 MiB per file and 8 MiB of source content.
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
cd .github/actions/dependency-security
corepack pnpm install --frozen-lockfile --ignore-scripts
corepack pnpm test
```

Tests use controlled GitHub responses and synthetic identities.
They verify residual vulnerable versions, patched and no-fix cases, stale heads, incomplete evidence, parser behavior and exact-body delivery.
They do not establish a caller's grants, actual OIDC claims, receiver availability or live delivery.
Approve and qualify those prerequisites before enabling a caller or recurring schedule.
