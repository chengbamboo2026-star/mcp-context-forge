#!/usr/bin/env bash
set -euo pipefail

read_secret() {
  local variable_name="$1"
  local secret_path="$2"

  if [[ ! -r "${secret_path}" ]]; then
    echo "Required secret is not readable: ${secret_path}" >&2
    exit 1
  fi

  printf -v "${variable_name}" '%s' "$(<"${secret_path}")"
  export "${variable_name}"
}

read_secret KC_DB_PASSWORD /run/secrets/keycloak_db_password
read_secret KC_BOOTSTRAP_ADMIN_PASSWORD /run/secrets/keycloak_admin_password

exec /opt/keycloak/bin/kc.sh "$@"
