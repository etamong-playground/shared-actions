#!/usr/bin/env bash
set -euo pipefail
invalid() { echo "Invalid private source token configuration: $1" >&2; exit 1; }
[[ ${SOURCE_OWNER:-} =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]] || invalid owner
[[ ${SOURCE_REPOSITORY:-} =~ ^[A-Za-z0-9_.-]+$ ]] || invalid repository
[[ $SOURCE_REPOSITORY != . && $SOURCE_REPOSITORY != .. ]] || invalid repository
[[ ${SOURCE_VAULT_URL:-} =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]] || invalid vault-url
[[ ${SOURCE_VAULT_ROLE:-} =~ ^[A-Za-z0-9_.-]+$ ]] || invalid vault-role
for variable in SOURCE_VAULT_AUTH_PATH SOURCE_APP_SECRET_PATH; do
  value=${!variable:-}
  [[ $value =~ ^[A-Za-z0-9_-]+(/[A-Za-z0-9_.-]+)*$ && $value != */../* && $value != */.. && $value != */./* && $value != */. ]] || invalid "$variable"
done
[[ ${SOURCE_TOKEN_PATH:-} == /* && $SOURCE_TOKEN_PATH != *[[:space:]]* ]] || invalid kubernetes-token-path
