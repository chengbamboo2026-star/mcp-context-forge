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

read_secret JWT_SECRET_KEY /run/secrets/contextforge_jwt_secret
read_secret AUTH_ENCRYPTION_SECRET /run/secrets/contextforge_auth_encryption_secret
read_secret PLATFORM_ADMIN_PASSWORD /run/secrets/contextforge_platform_admin_password
read_secret DEFAULT_USER_PASSWORD /run/secrets/contextforge_default_user_password
read_secret IDENTITY_CLAIMS_SECRET /run/secrets/power_wiki_identity_secret

if [[ -r /run/secrets/power_wiki_service_token ]]; then
  read_secret POWER_WIKI_SERVICE_TOKEN /run/secrets/power_wiki_service_token
fi

if [[ -r /run/secrets/contextforge_oidc_client_secret ]]; then
  read_secret POWER_WIKI_OIDC_CLIENT_SECRET /run/secrets/contextforge_oidc_client_secret
fi

if [[ "${CONTEXTFORGE_SET_DATABASE_URL:-false}" == "true" ]]; then
  read_secret POSTGRES_PASSWORD /run/secrets/postgres_password
  export DATABASE_URL="postgresql+psycopg://contextforge:${POSTGRES_PASSWORD}@postgres:5432/contextforge"
fi

exec "$@"
