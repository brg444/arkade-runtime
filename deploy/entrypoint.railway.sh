#!/bin/sh
set -eu

# Railway volume is root-owned on first attach. Drop to the vault user after.
if [ "$(id -u)" = "0" ]; then
  mkdir -p /app/data
  chown -R 10001:10001 /app/data
  chmod 0700 /app/data
fi

mkdir -p /tmp/vault-secrets
umask 077
if [ -n "${VAULT_COSIGNER_KEY_HEX:-}" ]; then
  printf '%s\n' "$VAULT_COSIGNER_KEY_HEX" > /tmp/vault-secrets/vault-cosigner.key
  export VAULT_VAULT_COSIGNER_KEY_FILE=/tmp/vault-secrets/vault-cosigner.key
fi
if [ -n "${VAULT_ENROLLMENT_TOKEN:-}" ]; then
  printf '%s\n' "$VAULT_ENROLLMENT_TOKEN" > /tmp/vault-secrets/enrollment.token
  export VAULT_ENROLLMENT_TOKEN_FILE=/tmp/vault-secrets/enrollment.token
fi
chmod 0700 /tmp/vault-secrets
chmod 0400 /tmp/vault-secrets/* 2>/dev/null || true
PORT="${PORT:-8080}"
export VAULT_AUTHORIZER_ADDR="0.0.0.0:${PORT}"

if [ "$(id -u)" = "0" ]; then
  chown -R 10001:10001 /tmp/vault-secrets
  exec su-exec 10001:10001 vault-authorizer "$@"
fi
exec vault-authorizer "$@"
