#!/usr/bin/env bash
set -euo pipefail

registry=$(node <<'JS'
const raw = process.env.REGISTRY_URL ?? "";
const scope = process.env.SCOPE ?? "";
const token = process.env.NPM_TOKEN ?? "";
try {
  const url = new URL(raw);
  if (!/^https?:$/.test(url.protocol) || !url.hostname || url.username || url.password || raw !== raw.trim() || /[\r\n?#]/.test(raw) || !/^@[a-z0-9][a-z0-9._-]*$/.test(scope) || !token || /[\r\n]/.test(token)) {
    throw new Error();
  }
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  process.stdout.write(url.href);
} catch {
  process.stderr.write("Invalid pnpm install configuration.\n");
  process.exit(2);
}
JS
)

umask 077
install_config=$(mktemp "${RUNNER_TEMP:?}/pnpm-install.XXXXXX")
install_pid=""
cleanup() { rm -f -- "$install_config"; }
interrupt_install() {
  local status=$1
  trap - INT TERM
  if [[ -n "$install_pid" ]]; then
    kill -TERM "$install_pid" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'interrupt_install 130' INT
trap 'interrupt_install 143' TERM

source_config=${NPM_CONFIG_USERCONFIG:-${npm_config_userconfig:-${HOME:?}/.npmrc}}
if [[ -e "$source_config" ]]; then
  cat -- "$source_config" > "$install_config"
fi
printf '\n%s:registry=%s\n%s:_authToken=%s\n' "$SCOPE" "$registry" "${registry#*:}" "$NPM_TOKEN" >> "$install_config"

NPM_CONFIG_USERCONFIG="$install_config" npm_config_userconfig="$install_config" \
  pnpm install --frozen-lockfile --ignore-scripts &
install_pid=$!
wait "$install_pid"
