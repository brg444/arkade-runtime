#!/bin/sh
# Manual unlock for Vaulted Guardian. Decrypts operator-held age blobs into
# tmpfs and starts the authorizer. Does not store the passphrase.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "unlock must run as root via Tailscale or an equivalent private admin path" >&2
  exit 1
fi

ENCRYPTED_KEY="${VAULTED_GUARDIAN_KEY_AGE:-/var/lib/vaulted-guardian/vault-cosigner.key.age}"
ENCRYPTED_TOKEN="${VAULTED_GUARDIAN_TOKEN_AGE:-/var/lib/vaulted-guardian/enrollment.token.age}"
ENCRYPTED_GATEWAY="${VAULTED_GUARDIAN_GATEWAY_AGE:-/var/lib/vaulted-guardian/gateway.env.age}"
RUNTIME_DIR=/run/vaulted-guardian
PLAINTEXT_KEY="${RUNTIME_DIR}/vault-cosigner.key"
PLAINTEXT_TOKEN="${RUNTIME_DIR}/enrollment.token"
PLAINTEXT_GATEWAY="${RUNTIME_DIR}/gateway.env"

if [ ! -f "$ENCRYPTED_KEY" ]; then
  echo "encrypted VaultCosigner blob is missing" >&2
  exit 1
fi
if [ ! -f "$ENCRYPTED_TOKEN" ]; then
  echo "encrypted enrollment token blob is missing" >&2
  exit 1
fi
if ! command -v age >/dev/null 2>&1; then
  echo "age is required to decrypt the off-host operator secret" >&2
  exit 1
fi

install -d -o vaulted-guardian -g vaulted-guardian -m 0700 "$RUNTIME_DIR"
umask 077

# Prompt on the real terminal so the passphrase never enters argv, env, or logs.
age -d -o "$PLAINTEXT_KEY" "$ENCRYPTED_KEY" < /dev/tty
age -d -o "$PLAINTEXT_TOKEN" "$ENCRYPTED_TOKEN" < /dev/tty
if [ -f "$ENCRYPTED_GATEWAY" ]; then
  age -d -o "$PLAINTEXT_GATEWAY" "$ENCRYPTED_GATEWAY" < /dev/tty
  chown vaulted-guardian:vaulted-guardian "$PLAINTEXT_GATEWAY"
  chmod 0400 "$PLAINTEXT_GATEWAY"
fi

chown vaulted-guardian:vaulted-guardian "$PLAINTEXT_KEY" "$PLAINTEXT_TOKEN"
chmod 0400 "$PLAINTEXT_KEY" "$PLAINTEXT_TOKEN"

systemctl start vaulted-guardian.service
# The authorizer unlinks the plaintext VaultCosigner key after it is loaded.
# The enrollment token remains in tmpfs for this boot only.

if ! systemctl is-active --quiet vaulted-guardian.service; then
  echo "vaulted-guardian failed to start; plaintext files will be removed" >&2
  rm -f "$PLAINTEXT_KEY" "$PLAINTEXT_TOKEN" "$PLAINTEXT_GATEWAY"
  exit 1
fi
