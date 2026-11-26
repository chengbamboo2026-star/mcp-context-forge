#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi

secrets_dir="${POWER_WIKI_AUTH_SECRETS_DIR:-./runtime/auth-secrets}"
contextforge_gid="${CONTEXTFORGE_RUNTIME_GID:-10001}"
keycloak_gid="${KEYCLOAK_RUNTIME_GID:-0}"
postgres_gid="${POSTGRES_RUNTIME_GID:-999}"

umask 077
mkdir -p "${secrets_dir}"

generate_password() {
  local destination="$1"
  local group_id="$2"

  if [[ ! -e "${destination}" ]]; then
    openssl rand -base64 36 | tr -d '\n' >"${destination}"
    printf '\n' >>"${destination}"
  fi
  chown root:"${group_id}" "${destination}"
  chmod 0440 "${destination}"
}

generate_root_password() {
  local destination="$1"

  if [[ ! -e "${destination}" ]]; then
    openssl rand -base64 36 | tr -d '\n' >"${destination}"
    printf '\n' >>"${destination}"
  fi
  chown root:root "${destination}"
  chmod 0400 "${destination}"
}

db_postgres="${secrets_dir}/keycloak-db-password-postgres"
db_keycloak="${secrets_dir}/keycloak-db-password-keycloak"

if [[ ! -e "${db_postgres}" && ! -e "${db_keycloak}" ]]; then
  database_password="$(openssl rand -base64 36 | tr -d '\n')"
  printf '%s\n' "${database_password}" >"${db_postgres}"
  printf '%s\n' "${database_password}" >"${db_keycloak}"
  unset database_password
elif [[ ! -e "${db_postgres}" || ! -e "${db_keycloak}" ]]; then
  echo "Both Keycloak database secret copies must exist or both must be absent." >&2
  exit 1
fi

if [[ "$(sha256sum "${db_postgres}" | cut -d' ' -f1)" != "$(sha256sum "${db_keycloak}" | cut -d' ' -f1)" ]]; then
  echo "Keycloak database secret copies do not match." >&2
  exit 1
fi

chown root:"${postgres_gid}" "${db_postgres}"
chmod 0440 "${db_postgres}"
chown root:"${keycloak_gid}" "${db_keycloak}"
chmod 0440 "${db_keycloak}"

generate_password "${secrets_dir}/keycloak-admin-password" "${keycloak_gid}"
generate_password "${secrets_dir}/contextforge-client-secret" "${contextforge_gid}"
generate_root_password "${secrets_dir}/operator-initial-password"
generate_root_password "${secrets_dir}/verifier-client-secret"
generate_root_password "${secrets_dir}/verifier-user-password"

echo "Prepared Power Wiki authentication secrets in ${secrets_dir}."
