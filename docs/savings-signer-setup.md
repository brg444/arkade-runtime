# Funding the Savings signer from Spending

The wallet can create the enrolled signer's approval outputs through a named
Spending batch. Savings deposits remain ordinary Bitcoin receives; the signer
setup is separate and may be funded before the first Savings withdrawal.

## Authorized transaction

One live, committed `vault-policy-v1` input funds one or two exact 500-sat
outputs for a v2 connector, or one exact 1,000-sat output for an existing v1
connector. The input must also cover the live Operator fee and at least
330 sats of change to the original enrolled Spending script. Several small
Spending inputs cannot be combined by this endpoint.

The Guardian rebuilds both enrolled contracts from authenticated records.
The signed plan binds the vault, Spending context, connector enrollment,
input, reserve script, output count, amounts, fee policy and expiry. Principal
and fee share the existing Spending allowance and concurrent-operation fence.

The stock SDK constructs the intent and participates in the batch. The named
Guardian capability verifies the owner proof and exact outputs before adding
its registration signature. Before final signing, it verifies the fully signed
replacement VTXO tree, the forfeit connector and the distinct approval outputs
in the same commitment transaction. The protected change remains recoverable
under the enrolled Spending contract.

## API and failure handling

All mutations use the existing same-origin gateway and mutation protections.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/vtxo/savings-setup/info` | Report availability and the enrolled Spending context |
| POST | `/v1/vtxo/savings-setup/prepare` | Reserve the exact input, principal and fee |
| POST | `/v1/vtxo/savings-setup/register` | Authorize and submit the SDK intent |
| POST | `/v1/vtxo/savings-setup/final` | Verify recovery paths and submit the scoped forfeit |
| POST | `/v1/vtxo/savings-setup/status` | Reconcile the retained operation |
| POST | `/v1/vtxo/savings-setup/release` | Release only before final dispatch |

The wallet saves the owner-signed prepare request before dispatch. Its expiry
is enforced under the ledger lock; an absent operation can be discarded only
after that request expires and the server confirms absence. An existing
reservation is released through its recorded lifecycle.

Registration and final dispatch are durable before contacting the Operator.
Registration and finalization retries never submit a second request after an ambiguous dispatch. Before registration, the wallet also saves an owner-signed cancellation for
that exact input. Registration expiry does not remove an intent from the
Operator's queue. After expiry, the Guardian verifies and cosigns the retained
cancellation, confirms deletion with the Operator, then checks that the input
remains live before releasing the reservation. A lost deletion response or
no-match response remains unresolved; neither permits a new setup. Cancellation
cannot race a final dispatch. A lost final response stays unresolved until the
exact commitment and replacement output can be verified. Elapsed time does
not release its allowance.

The wallet shows pending setup on its home screen and reserves the input in
its available-balance calculation. Once submitted, protected change replaces
the input in that calculation without counting both. The setup journal remains
until confirmation and a complete local recovery archive covers the exact
replacement Spending output.

## Upgrade and qualification

Schema 6 introduces a reader-version fence for the setup principal stored in
the existing authenticated batch journal. The physical tables and all legacy
MAC preimages are preserved. The upgraded database rejects schema-5 binaries at startup; rollback requires a compatible binary that preserves the new journal
fields and allowance semantics. Never restore an older database and policy
sequence to bypass this fence.

Local checks cover exact outputs, destination substitution, merged reserves,
missing tree signatures, owner authorization, allowance accounting, lost
responses, cancellation and SDK intent signing. The funded qualification below
covers batch execution, restart reconciliation, recovery capture and offline
exit preparation. Mainnet deployment still requires passing CI and the Guardian
unlock procedure because its loaded key is removed from disk.

`internal/application/testdata/savings-setup-sdk.json` contains a real intent
produced by the pinned wallet SDK, together with its public test enrollment and
signed plan. `TestSavingsSetupActualSDKIntent` independently rebuilds the Go
contracts and verifies the prepare signature, plan digest, complete intent and owner-signed cancellation.
Regenerate a candidate from the wallet checkout with
`VAULT_SETUP_SDK_VECTOR=/tmp/savings-setup-sdk.json pnpm exec vitest run src/lib/vault/savingsSetupStore.test.ts`,
then inspect and copy the public fixture into the runtime testdata directory.
This fixture verifies protocol compatibility without moving Bitcoin.

## Funded qualification — 2026-09-08

A disposable Standard vault on Mutinynet funded two 500-sat signer outputs
from a 10,000-sat Spending input. The Operator charged zero fees and returned
9,000 sats to the enrolled Spending script. The Bitcoin commitment
`c15220d7cce21068a43182088e11e7bf288c06c92f06506e04512ec4b6188a46`
confirmed at height 3,409,096. Its two 500-sat outputs have the same enrolled
signer script and separate output indexes.

The browser drill resumed an interrupted registration, deleted the exact
queued intent with an owner proof, and completed a new batch. A later reload
reconciled the confirmed operation. The complete local recovery file contains
replacement output
`0dd902be452bc498e3a29c3c67f67fd2b175c03815e11e0ffce5f90819d727a7:0`
with its 9,000-sat value and exit ancestors. The setup journal cleared only
after that file was saved; another reload displayed the completed signer setup.

Using that file and the disposable test keys, a separate test prepared and
validated a fully signed unilateral Spending exit while Guardian and Operator
network calls were disabled. Bitcoin commitment bytes came from a local copy.
The exit was not broadcast, so this does not qualify timelock maturity, fee
funding or execution of the final Bitcoin recovery transaction.

The wallet repository contains the opt-in funded browser test and
`savingsSetupRecovery.live.test.ts`. Test keys, virtual passkey state, recovery
files and signed exits stay in a private local directory outside both repositories.
