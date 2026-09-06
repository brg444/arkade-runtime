# Deploy the Savings connector to mainnet RC

Deploy the runtime and wallet revisions recorded in the release manifest as a
pair. The offline recovery companion commit is pinned by the wallet submodule.
This release keeps the current external Emulator stack; it does not depend on
PR 102 or migrate existing Savings funds.

## Before the maintenance window

Check that all three pull requests have passed their applicable checks and
that the artifact hashes match the manifest. Confirm the host architecture is
Linux amd64 before staging the binary. Retain the current binary separately;
copying a replacement into a staging path does not require stopping Guardian.

The deployed Guardian uses `VAULT_COSIGNER_KEY_UNLINK=after-load`. Its running
key cannot be recovered from the deleted plaintext file. The operator must be
present with the three age passphrases and a real terminal before stopping the
service. Enter passphrases exclusively at the terminal prompts.

Record the current mainnet readiness, wallet release identity, service unit,
and non-secret network/origin pins. Preserve the existing `VAULT_CLIENT_ORIGIN`,
RP ID, Emulator configuration, database path, and independent sequence path.
Changing a domain or RP ID can break existing passkeys. A mainnet build must
use `build:mainnet`; the RC hostname alone does not select the network.

Take a consistent SQLite backup using SQLite's backup facility and verify it.
Keep it under the database backup authority. Preserve the independently
administered policy sequence in place; copying an older sequence alongside a
database rollback is forbidden. Follow [state operations](../deploy/ops.md).

## Activate Guardian, then the wallet

1. Confirm the operator can run the existing interactive unlock procedure.
   Stop `vaulted-guardian.service`, install the verified staged binary at
   `/usr/local/bin/vault-authorizer`, and retain executable permissions.
2. Run `/usr/local/sbin/vaulted-guardian-unlock` from a real SSH terminal. It
   decrypts the existing secrets into tmpfs and starts the service; an
   unattended restart cannot load the already removed key.
3. Require `/ready` to report `ok: true`, `network: mainnet`, and schema `5`.
   `/v1/status` must advertise `savings-connector-v1` in `connectorCapability`.
   Keep the original enrollment-template field unchanged for legacy clients.
4. Deploy the paired wallet build to the existing RC deployment with its
   established origin, passkey, and gateway settings. Verify the compiled
   mainnet policy and release manifest, then check an existing vault can unlock.
5. Enroll a separate disposable connector vault. Compare its reserve address
   with Sparrow or Electrum before sending exactly 1,000 sats there. Deposit
   Savings separately and wait for Bitcoin confirmation.
6. Exercise one withdrawal, reload during signer handoff, verify the complete
   recipient address in the signer, and return its signed transaction. Confirm
   the real broadcast endpoint accepts the program packet. After confirmation,
   verify one history entry, correct Savings change, and the 1,000-sat reserve
   successor; spend that successor in a second withdrawal.

The last two steps are funded deployment qualification. Local Core, Emulator,
and software-signer tests leave the live broadcast endpoint's relay policy
unverified. Keep new enrollment restricted until these checks succeed.

Keep `VAULT_LIGHT_DELEGATION_ENABLED=false` until the funded renewal, cleanup,
restart, and independent recovery gates in
[native Light delegated renewal](light-delegated-renewal.md) pass. The schema-5
migration runs even when this flag is disabled; connector deployment alone
does not qualify unattended renewal.

## Recovery and rollback

Startup migrates valid prior databases through schema 2 (Light renewal),
schema 3 (Savings connector), schema 4 (shared encrypted recovery backup), and
schema 5 (native Light delegated renewal). Migration tests preserve
original Savings, credential, recovery-session, and Light MACs and the economic
sequence. Legacy descriptors and version-4 passkey bindings retain their bytes;
new connector vaults use the distinct template and version-5 binding.
Schema 5 preserves every connector origin, candidate, signing stage, and
resolution record, together with the shared backup state. Backup writes leave
the economic sequence unchanged; delegated renewal mutations advance it.
The isolated Light backup drill used a different schema-3 layout; this release
refuses that layout and requires an explicitly reviewed recovery path for it.

The migration rejects the earlier, undeployed Light-only schema-4
layout. No production database uses that scratch layout, and table presence
does not select a migration lineage.

Schema-4 and earlier binaries cannot operate a schema-5 database. After migration, repair or
roll forward with a compatible binary while retaining all authorization rows
and the current sequence. Reverting the wallet UI can leave connector vaults
unsupported, so restrict enrollment or serve a maintenance page while the
compatible release is restored. Preserve every connector row and pending
payment and delegated renewal operation, together with the current state
required by the compatible binary. Disabling delegated renewal does not remove
its authorization history or release unresolved input holds.

A schema-2 backup is not a routine rollback once signing may have occurred.
Any exceptional recovery must reconcile issued signatures, chain outcomes,
current sequence authority, and every intervening operation before restarting.
Existing funds remain in their enrolled contracts; migration is a separate
owner-authorized operation.
