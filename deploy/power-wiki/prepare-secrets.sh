#!/usr/bin/env bash
set -euo pipefail

secrets_dir="${CONTEXTFORGE_SECRETS_DIR:-./runtime/secrets}"
runtime_gid="${CONTEXTFORGE_RUNTIME_GID:-10001}"
umask 077
mkdir -p "${secrets_dir}"

generate_hex_secret() {
  local destination="$1"
  local byte_count="$2"

  if [[ -e "${destination}" ]]; then
    echo "Keeping existing secret: ${destination}"
    return
  fi

  openssl rand -hex "${byte_count}" >"${destination}"
  chmod 600 "${destination}"
  echo "Created secret: ${destination}"
}

generate_password() {
  local destination="$1"

  if [[ -e "${destination}" ]]; then
    echo "Keeping existing secret: ${destination}"
    return
  fi

  openssl rand -base64 36 | tr -d '\n' >"${destination}"
  printf '\n' >>"${destination}"
  chmod 600 "${destination}"
  echo "Created secret: ${destination}"
}

generate_hex_secret "${secrets_dir}/postgres-password" 32
generate_hex_secret "${secrets_dir}/jwt-secret" 64
generate_hex_secret "${secrets_dir}/auth-encryption-secret" 32
generate_password "${secrets_dir}/platform-admin-password"
generate_password "${secrets_dir}/default-user-password"

# Docker Compose file-backed secrets retain host ownership and mode. The
# ContextForge image runs as 10001:10001, so grant only that runtime group
# read access instead of making the files world-readable.
chgrp "${runtime_gid}" "${secrets_dir}"/*
chmod 0440 "${secrets_dir}"/*
