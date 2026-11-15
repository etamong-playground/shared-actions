# Source secret checks

The `gitleaks-secret-check` and `trufflehog-secret-check` composite actions provide independent source checks without application or publishing credentials.
Gitleaks 8.30.1 scans all reachable history; TruffleHog 3.99.7 adds provider-specific detection without verifying candidates against provider APIs.
A finding is a candidate, not proof that a credential works or has been revoked.
Neither action scans a built deployment artifact.

## Caller prerequisites

Use a Unix runner with Bash, Git and Python 3, and a full checkout with persisted Git credentials disabled.
Archive installation supports Linux and macOS on amd64 and arm64; unsupported platforms fail rather than skip.
The installer verifies the exact official archive SHA-256 digest before extracting the single regular executable.
The runner needs access to GitHub's release assets for installation; scan invocation disables update and provider-verification requests.
Do not pass application, dependency-registry, publishing or production secrets into either job.
Runner isolation and repository protection remain the caller's responsibility.

Replace `REVIEWED_COMMIT_SHA` below with the reviewed immutable commit containing both actions.
Do not substitute a moving branch or tag.

```yaml
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  secret-check-gitleaks:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: etamong-playground/shared-actions/.github/actions/gitleaks-secret-check@REVIEWED_COMMIT_SHA
  secret-check-trufflehog:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: etamong-playground/shared-actions/.github/actions/trufflehog-secret-check@REVIEWED_COMMIT_SHA
```

Require both observed check names with their GitHub Actions producer identity in repository controls.
Protect the scanner actions, their tests, consumer workflows and release workflows with independent review.
Do not use path filters, optional failures, `pull_request_target` or a same-name green replacement for these checks.
A credentialed build job depends on both checks; credential-free tests can run in parallel.

## Event scope and releases

Gitleaks always checks full reachable Git history, including custom refs copied into a disposable mirror.
TruffleHog uses the observed PR base's merge base through `HEAD` on `pull_request`, and the event's `before` through matching `HEAD` on `push`.
An unresolved base, shallow clone or mismatched push head fails as incomplete; it never falls back to a narrower clean result.
`workflow_dispatch` runs full-history TruffleHog, supporting a CI-cut release workflow.
Unsupported events fail, including privileged `pull_request_target`.

Run both actions inside the release workflow before publishing, with the same canonical job names.
Every tag or artifact publication job declares `needs: [secret-check-gitleaks, secret-check-trufflehog]` and receives release credentials only in that dependent job.
Qualify this ordering with a synthetic candidate that prevents tag and artifact creation; a separate PR's green check does not establish the release gate.
The shared scanner qualification workflow tests binaries and fixtures; it does not configure a consumer's merge or publication rules.

## Sanitization and limits

Scanner stdout and stderr stay in bounded memory and are discarded after schema validation.
The wrappers emit only `Source scan clean.`, a candidate count, or `Source scan incomplete.`.
They do not emit detector names, locations, raw candidates, fingerprints, diagnostics, annotations or uploadable reports.
Unexpected diagnostics, unknown metadata, version mismatch, malformed JSON, duplicate keys, timeouts and limit exhaustion fail as incomplete.
Exit 0 means complete and clean, exit 1 means candidates, and exit 2 means incomplete coverage.

The wrapper builds a local mirror, replaces its configuration, disables hooks and network Git protocols, and strips inherited Git overrides, scanner options and credentials from subprocess environments.
It forces fsmonitor off and compares the source and mirror ref inventories before scanning; hidden or concurrently changed refs fail as incomplete.
TruffleHog's local-config flag applies only to that wrapper-owned sanitized mirror, preserving all refs without trusting the input checkout's configuration.
Gitleaks receives temporary default-rules configuration and an empty ignore file; repository suppression and inline allow comments cannot weaken the gate.
TruffleHog ignores inline ignore tags, disables verification and updates, limits detector concurrency to one, and disables binary and archive expansion.

| Boundary | Limit |
| --- | --- |
| Downloaded archive / extracted executable | 128 MiB / 384 MiB |
| Archive entries / total declared contents | 100 / 512 MiB |
| Scan scope setup and execution | 240 seconds total; scanner process at most 180 seconds |
| Combined process stdout and stderr | 2 MiB; Git setup 1 MiB; version output 4 KiB |
| TruffleHog JSON line / candidate count | 256 KiB / 1,000 |
| TruffleHog detector timeout / decode depth | 2 seconds / one pass |
| Optional staged snapshot | 2,000 regular files, 1 MiB per blob, 16 MiB total |

These limits fail closed; they are not a qualification of every repository size or runner class.
Choose an appropriate runner job timeout and resource isolation, and measure the adopting repository before broader rollout.
The process wrapper terminates its process group on output exhaustion, deadline or catchable interruption.
Disposable mirrors, configuration and staged snapshots are removed on completion or catchable interruption; no raw scanner report is written to disk.

## Optional local staged review

No hook is installed.
Use a staged review when credential handling, injection, authentication, CI, deployment or release code changes, and before publishing source when CI evidence is unavailable.
The snapshot contains index blobs only, excludes unrelated untracked and working-tree changes, rejects links, submodules and unmerged index entries, and does not expand archives or scan binary blobs containing NUL bytes.
Passing this supplement does not establish that Git history is clean.

```sh
mkdir -p .tmp/scanner-tools
python3 .github/actions/source-secret-scan/install.py gitleaks .tmp/scanner-tools
python3 .github/actions/source-secret-scan/install.py trufflehog .tmp/scanner-tools
python3 .github/actions/source-secret-scan/scan.py gitleaks --binary .tmp/scanner-tools/gitleaks --staged
python3 .github/actions/source-secret-scan/scan.py trufflehog --binary .tmp/scanner-tools/trufflehog --staged
SCANNER_TEST_BIN_DIR="$PWD/.tmp/scanner-tools" python3 -m unittest discover -s tests -p 'test_scanner*.py'
```

Run outside GitHub Actions for the optional staged mode; CI rejects that narrower mode.
The explicit binary directory makes missing qualification binaries fail instead of silently passing the real-engine suite.
Without that environment variable, normal unit discovery reports real-engine cases as skipped; `Scanner qualification` supplies both binaries and exercises those cases.
Never copy raw findings into issues or logs for triage, and never send a candidate to a provider just to decide whether it is safe to commit.
The initial baseline has no exceptions; remediation and any later exact fixture-exception policy belong to the consumer's independently reviewed process.

## Upstream contracts

- [Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/tree/v8.30.1) defines default rules, redaction and JSON reporting.
- [TruffleHog v3.99.7](https://github.com/trufflesecurity/trufflehog/tree/v3.99.7) defines offline detection, Git scopes and the qualified JSON schema.
