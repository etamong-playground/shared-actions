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

Three building blocks, called via `uses:` from your own workflows.

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

## Notes

- **Self-hosted runner**: set the `runner` input when your registry / secret manager /
  ingest endpoint is only reachable from inside your network.
- **npm token**: fetch it from your secret manager in the calling workflow and pass it
  in — never hardcode it.

## License

MIT — see [LICENSE](LICENSE).
