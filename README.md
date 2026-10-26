# shared-actions

> **About** — Reusable GitHub Actions building blocks for shipping small services:
> build an image and push it to an OCI registry, install pnpm deps against a private
> scoped registry, and ping a version-audit hub. **Bring-your-own-infra** — the
> registry, runner, npm registry, and ingest URL are all `inputs`, so nothing is
> hardcoded to one environment. Authored and maintained with
> [Claude Code](https://www.anthropic.com/claude-code) (Anthropic's agentic CLI),
> not hand-written.
>
> **This is a public repository** — keep secrets out of code, comments, and commit messages.

Reusable building blocks, called via `uses:` from your own workflows.

## `kaniko-build` — build & push an image (docker buildx)

```yaml
jobs:
  build:
    uses: etamong-playground/shared-actions/.github/workflows/kaniko-build.yml@main
    with:
      registry: registry.example.com
      image-name: myapp
      runner: ubuntu-latest        # or a self-hosted label
    secrets:
      REGISTRY_USER: ${{ secrets.REGISTRY_USER }}
      REGISTRY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}
      # NPM_TOKEN: ${{ secrets.NPM_TOKEN }}   # optional, forwarded as a build-arg
```

Pushes `:<sha>` and `:latest`. Emits OCI mediatypes (`provenance: false`) so it works
with OCI-strict registries (e.g. Zot) that reject Docker v2 schema over existing OCI tags.

## `pnpm-install` — install with a private scoped registry (composite action)

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: etamong-playground/shared-actions/.github/actions/pnpm-install@main
    with:
      registry-url: https://npm.example.com/api/packages/myorg/npm/
      scope: "@myorg"
      npm-token: ${{ secrets.NPM_TOKEN }}
      working-directory: .
```

Runs `corepack enable`, writes auth to `~/.npmrc` (corepack-pinned pnpm ignores
`pnpm config`), then `pnpm install --frozen-lockfile --ignore-scripts`.

## `fleet-audit-register` — POST a version snapshot to a status/version-audit hub

```yaml
jobs:
  register:
    uses: etamong-playground/shared-actions/.github/workflows/fleet-audit-register.yml@main
    with:
      ingest-url: https://status.example.com/cluster   # POSTs to <ingest-url>/<app-name>/ingest
      app-name: myapp
    secrets:
      INGEST_TOKEN: ${{ secrets.INGEST_TOKEN }}
```

## `private-source-token` — read one private GitHub source repository

Prerequisites: a trusted Kubernetes runner with a projected service-account JWT, an existing Vault Kubernetes role authorized to read an App credential, and a GitHub App installed on the source repository.
The runner receives the App private key while composing the token; the read-only output does not reduce the privileges of that underlying key or its Vault role.
Use this action only in workflows already trusted with those credentials.
It does not create a Vault policy, enroll a runner, or authorize untrusted fork code to read private source.

The App secret contains `app_id` and `private_key` fields at the supplied KV API path.
The action requires one explicit repository name, fixes token permissions to `contents: read`, and retains the token action's post-job revocation.
All infrastructure is provided by the calling workflow.
Third-party credential actions are pinned to immutable commits.

```yaml
jobs:
  test:
    runs-on: your-kubernetes-runner
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: etamong-playground/shared-actions/.github/actions/private-source-token@main
        id: source
        with:
          vault-url: https://vault.example.com
          vault-role: existing-source-reader
          kubernetes-token-path: /projected/runner/token
          app-secret-path: secret/data/ci/source-app
          owner: example-org
          repository: private-library
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Test with authenticated dependencies
        env:
          GOPRIVATE: github.com/example-org/private-library
          PRIVATE_SOURCE_TOKEN: ${{ steps.source.outputs.token }}
          GIT_CONFIG_COUNT: "2"
          GIT_CONFIG_KEY_0: credential.helper
          GIT_CONFIG_VALUE_0: ""
          GIT_CONFIG_KEY_1: credential.https://github.com.helper
          GIT_CONFIG_VALUE_1: '!f(){ echo username=x-access-token; echo password=$PRIVATE_SOURCE_TOKEN; };f'
        run: go test ./...
```

`vault-auth-path` defaults to `kubernetes`; `kubernetes-token-path` defaults to the standard Kubernetes service-account token path.
The Vault URL must be an HTTPS host origin, optionally with a port.
Owner, repository and Vault selectors reject empty or ambiguous values before credential retrieval.
The token is available only as the `token` output and is not exported into the job environment automatically.

For image builds, pass the token through a BuildKit secret rather than a build argument or authenticated URL.
Create the temporary netrc file with owner-only permissions and remove it when the build step finishes:

```yaml
- name: Build with private source
  env:
    PRIVATE_SOURCE_TOKEN: ${{ steps.source.outputs.token }}
  run: |
    set -euo pipefail
    umask 077
    auth_dir=$(mktemp -d "$RUNNER_TEMP/private-source.XXXXXX")
    trap 'rm -rf "$auth_dir"' EXIT
    printf 'machine github.com login x-access-token password %s\n' "$PRIVATE_SOURCE_TOKEN" > "$auth_dir/netrc"
    docker buildx build --secret "id=github,src=$auth_dir/netrc" .
```

The Dockerfile consumes it only while fetching dependencies:

```dockerfile
RUN --mount=type=secret,id=github,target=/root/.netrc,required=true go mod download
```

The [Vault action](https://github.com/hashicorp/vault-action) owns Kubernetes authentication and secret masking.
The [GitHub token action](https://github.com/actions/create-github-app-token) owns installation-token creation and revocation.

## Notes

- **Self-hosted runner**: set the `runner` input when your registry / secret manager /
  ingest endpoint is only reachable from inside your network.
- **npm token**: fetch it from your secret manager in the calling workflow and pass it
  in — never hardcode it.

## License

MIT — see [LICENSE](LICENSE).
