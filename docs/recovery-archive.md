# Encrypted recovery archives

Standard and Advanced Savings wallets can persist encrypted recovery data at
`/v1/recovery-archive/{challenge,open,read,write}`. Both the existing Savings
script and `phone-connector-recovery-savings-v1` are supported. The existing
`/v1/light/backup/*` routes remain restricted to Light enrollment.

The archive transport grants no signing, payment or recovery authority. Clients
must encrypt and verify their recovery data; the runtime cannot establish that
ciphertext is decryptable or that an exit graph is complete. A public Recovery
Kit or map remains separate from the encrypted archive.

## Authentication and session scope

A POST of `{}` to `challenge` issues a discoverable, single-use WebAuthn challenge
without enumerating credentials. POST `open` accepts the existing backup request
fields: `vaultId`, `challengeId`, `credentialId`, `clientDataJSON`,
`authenticatorData`, `signature`, and `directProof`. User presence and verification
are required. The direct proof uses the existing passkey proof encoding with
purpose `recovery-archive-open`, distinct from Light and payment purposes.

The response contains `token`, `vaultId`, `expiresAt`, `backup`, and `binding`.
The binding contains these enrolled public facts:

- `vaultId`, `network`, `templateVersion`, and `protectionTier`;
- `policyVersion` and `spendingPolicyDigest`;
- `descriptorHash`: the Savings and boarding composite hash for existing
  Savings, or `connectorEnrollment.descriptorHash` for the connector template.

The server derives these values from authenticated enrollment records. Every
read and write rebuilds the binding and compares it with the session. The client
must independently compare it with the verified wallet descriptor before use.
Tokens expire after eight hours and disappear on process restart. Light and
Savings share a bounded session map, but tokens cannot cross route families.
There are at most 256 active sessions in total and 256 pending challenges per
family. Either family can exhaust the shared session pool; opening another
session then requires an existing session to expire.

## Archive and write contract

POST `read` accepts `{token}` and returns `null` or `{revision,payload}`. POST
`write` accepts `{token,revision,payload}`, where revision is the expected current
revision, starting at zero. A successful write returns the new revision and
payload. An exact retry of the same ciphertext at its original expected revision
returns the prior result. A conflicting writer must reopen and reconcile; it
cannot overwrite an unseen revision.

The payload is a JSON envelope named `vaulted-recovery-backup`, version `1`, with
`header`, a twelve-byte hex `nonce`, and base64 `ciphertext`. The entire envelope
is limited to 3,000,000 bytes, and the header to 96 KiB. Ciphertext must contain
more than an authentication tag. The server does not decrypt or decompress it.
The header must contain the exact enrolled `binding` returned at open.

The client authenticates the exact serialized header as encryption AAD. That
header remains byte-identical for the enrollment: timestamps belong in the
encrypted data, and each encryption nonce belongs in the outer envelope. Opening
an existing archive pins its header hash; the first successful write pins a new
archive. Another session opened before that first write must honor the stored
header as well. A fresh passkey ceremony does not permit silently replacing it.
Phone-envelope rotation requires a separately designed protocol.

## Persistence and release

Light and Savings share one opaque `recovery_backup` table and one CAS store,
keyed by vault ID. Rows authenticate the vault ID, revision and payload with a
separate MAC domain. Reads verify the MAC before returning data, and writes
verify the prior row before testing its revision. Archive updates neither debit
allowances nor advance the economic policy sequence.

This is an explicit behavior change to the undeployed schema-4 integration.
Schemas 1, 2 and 3 remain frozen and migrate through their verified structural
baselines to the shared schema 4. The earlier scratch schema 4 with only the
`light_backup` table is refused. Startup does not infer lineage from table
presence or recover a missing economic sequence from database rows.

Transport qualification covers both networks, templates and protection tiers,
passkey and route isolation, descriptor and header substitution, concurrent CAS,
exact retries, restart and expiry, malformed envelopes and HTTP body bounds.
Client encryption, complete exit-graph restoration and recovery execution remain
separate release qualifications.
