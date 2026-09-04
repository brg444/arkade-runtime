#!/bin/sh
# Mint Vaulted Guardian operator secrets on an offline/admin laptop.
# Writes files only. Never prints key material.
# Run this in a local terminal, not in a chat agent.
set -eu

if [ -t 1 ] && [ "${VAULTED_MINT_CONFIRM:-}" != "i-understand-this-creates-production-keys" ]; then
  echo "This creates production VaultCosigner material on disk." >&2
  echo "Re-run with VAULTED_MINT_CONFIRM=i-understand-this-creates-production-keys" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi
if ! command -v age >/dev/null 2>&1; then
  echo "age is required (brew install age)" >&2
  exit 1
fi
if [ ! -t 0 ]; then
  echo "mint must run on a real terminal so the age passphrase is not logged" >&2
  exit 1
fi

OUT="${VAULTED_OPERATOR_OUT:-$HOME/VaultedOperatorSecrets}"
umask 077
mkdir -p "$OUT"
chmod 0700 "$OUT"

python3 - "$OUT" <<'PY'
import os, pathlib, secrets, sys, base64

out = pathlib.Path(sys.argv[1])
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

while True:
    raw = secrets.token_bytes(32)
    if 1 <= int.from_bytes(raw, "big") < n:
        key_path = out / "vault-cosigner.key"
        key_path.write_bytes(raw.hex().encode("ascii") + b"\n")
        key_path.chmod(0o600)
        break

token = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
if len(token) != 43:
    raise SystemExit("enrollment token encoding is not 43 characters")
token_path = out / "enrollment.token"
token_path.write_text(token + "\n")
token_path.chmod(0o600)

gateway = out / "gateway.env"
gateway.write_text("VAULT_GATEWAY_SECRET=" + secrets.token_hex(32) + "\n")
gateway.chmod(0o600)
PY

echo "Encrypting with age passphrases. Use a distinct passphrase per blob if you want."
age -p -o "$OUT/vault-cosigner.key.age" "$OUT/vault-cosigner.key" < /dev/tty
age -p -o "$OUT/enrollment.token.age" "$OUT/enrollment.token" < /dev/tty
age -p -o "$OUT/gateway.env.age" "$OUT/gateway.env" < /dev/tty
chmod 0600 "$OUT"/*.age

python3 - "$OUT" <<'PY'
import os, pathlib, sys
out = pathlib.Path(sys.argv[1])
for name in ("vault-cosigner.key", "enrollment.token", "gateway.env"):
    path = out / name
    try:
        length = path.stat().st_size
        path.write_bytes(b"\0" * length)
        path.unlink()
    except FileNotFoundError:
        pass
print("plaintext removed; age blobs remain in", out)
PY
