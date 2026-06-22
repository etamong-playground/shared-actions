# shared-actions

> **About** — Reusable GitHub Actions workflows for a personal homelab "fleet" of small apps (image build → in-cluster registry, pnpm install with a private registry, fleet version audit). Published to show the **CI / platform design** behind a self-hosted fleet — authored and maintained with [Claude Code](https://www.anthropic.com/claude-code) (Anthropic's agentic CLI), not hand-written. These workflows are **cluster-specific** (they target this fleet's ARC runners / registry / Vault), so they're a reference, not a drop-in for other setups.
>
> **This is a public repository** — keep internal infrastructure details (secret paths, private credentials) out of code, comments, and commit messages.

Reusable GitHub Actions workflows and composite actions for the etamong-playground fleet. Ported from GitLab `etamong-lab/shared/ci` (v0.2.0).

**Status:** No consumers yet — apps adopt these as they migrate to GitHub Actions (Wave 3, [planning#8](https://github.com/etamong-playground/planning/issues/8)). Apps that remain on Forgejo use Forgejo Actions; a separate Forgejo-compatible equivalent may be added there in a later wave.

---

## Workflows

### `kaniko-build.yml` — Image build → push to in-cluster Zot

Builds a Docker image using `docker buildx` and pushes to `registry.m.etamong.com`.

**Caveats:**
- **ARC runner required.** `ubuntu-latest` cannot reach `registry.m.etamong.com` (ETIMEDOUT). Must use `arc-etamong-playground`.
- **OCI mediatypes.** Zot stores images as OCI artifacts. Once a tag is pushed as OCI, pushing Docker v2 schema returns HTTP 400. `outputs: type=registry,oci-mediatypes=true` + `provenance: false` is mandatory on every push.
- **Forgejo npm token.** If your Dockerfile installs `@etamong-playground/*` packages, pass `FORGEJO_NPM_TOKEN` and add `ARG FORGEJO_NPM_TOKEN` + the `.npmrc` write to your Dockerfile (rename any existing `GITLAB_NPM_TOKEN` arg).

**Usage:**

```yaml
jobs:
  build:
    uses: etamong-playground/shared-actions/.github/workflows/kaniko-build.yml@main
    with:
      image-name: my-app          # → registry.m.etamong.com/my-app
      context: .
      dockerfile: Dockerfile
      cache: true
      # build-extra-args: |       # optional extra build-args (newline-separated key=value)
      #   SOME_ARG=value
    secrets:
      REGISTRY_USER: ${{ secrets.REGISTRY_USER }}
      REGISTRY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}
      FORGEJO_NPM_TOKEN: ${{ secrets.FORGEJO_NPM_TOKEN }}   # optional
```

---

### `fleet-audit-register.yml` — Register deployed version with fleet status hub

POSTs a version snapshot to `status.m.etamong.com` after a successful build/deploy, so the fleet version view stays current.

**Caveats:**
- `FLEET_TOKEN` should be stored as a GHA Actions secret at repo/org level. If fetching from internal Vault at runtime, the fetch step must run on `arc-etamong-playground` (Vault unreachable from `ubuntu-latest`).
- If `FLEET_TOKEN` is not set, the step exits 0 (graceful skip) so pipelines succeed before the token is provisioned.

**Usage:**

```yaml
jobs:
  register:
    needs: build
    uses: etamong-playground/shared-actions/.github/workflows/fleet-audit-register.yml@main
    with:
      app-name: my-app
      # app-version defaults to github.sha
    secrets:
      FLEET_TOKEN: ${{ secrets.FLEET_TOKEN }}
```

---

## Composite Actions

### `pnpm-install` — pnpm install with Forgejo private-registry auth

Enables corepack, writes `~/.npmrc` with Forgejo npm token auth for `@etamong-playground/*` scoped packages, then runs `pnpm install --frozen-lockfile`.

**Caveats:**
- **ARC runner required** for the Vault fetch step (caller's responsibility). The action itself can run anywhere once the token is in hand.
- Auth is written to `~/.npmrc`, not via `pnpm config` — corepack-managed pnpm ignores the latter for auth tokens.
- Fetch the token with `hashicorp/vault-action` (kubernetes auth, role `arc-runner-workflows`, secret `homelab/data/apps/forgejo/npm-publish`), then pass it in.

**Usage:**

```yaml
jobs:
  build:
    runs-on: arc-etamong-playground
    steps:
      - uses: actions/checkout@v4

      - name: Fetch Forgejo npm token from Vault
        id: vault
        uses: hashicorp/vault-action@v3
        with:
          url: https://vault.m.etamong.com
          method: kubernetes
          role: arc-runner-workflows
          secrets: |
            homelab/data/apps/forgejo/npm-publish token | FORGEJO_NPM_TOKEN

      - name: Install dependencies
        uses: etamong-playground/shared-actions/.github/actions/pnpm-install@main
        with:
          working-directory: .
          forgejo-npm-token: ${{ steps.vault.outputs.FORGEJO_NPM_TOKEN }}
```
