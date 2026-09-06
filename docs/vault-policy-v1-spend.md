# `vault-policy-v1` Spending

An ordinary Spending payment reserves between one and 50 spendable
`vault-policy-v1` VTXOs. Selection is deterministic by effective value, then
the reserved set is persisted and returned in canonical outpoint order. A
single operation can therefore spend fragmented balances without making caller
order part of the signed contract.

The destination must be a `tark` address for the same release-pinned Operator.
Bitcoin destinations and VTXO offboarding remain separate programs. Spending
never falls back to an onchain transaction.

Each reserved input has one version-3 checkpoint with `[checkpoint output,
P2A]`. The Arkade transaction spends those checkpoints in the same canonical
order and contains `[destination, change, P2A]` when change is at least dust,
or `[destination, P2A]` when the input total exactly covers the destination and
Operator fee. Every collaborative input uses the three-key leaf `[user, VTXO
VaultCosigner, Arkade Operator]` with `SIGHASH_DEFAULT`.

The server independently verifies every reserved outpoint, checkpoint,
tapleaf, control block, user signature, version, locktime, sequence, output,
and conservation equation. The operation binds the destination, ordered input
set, exact fee, fee-policy digest, optional change amount and output index, and
reservation time.

Each vault carries one immutable `vault-spending-policy-v1` instance selected
during enrollment. The user selects the recipient cap and rolling 24-hour
allowance. The current release fixes the absolute fee cap at 5,000 sats and the
feerate cap at 10 sat/vB. The policy digest is bound to the pending enrollment,
authenticated vault record, Savings descriptor, Recovery Kit, and wallet pin.
Authorization always loads the tenant record; a different vault on the same
service may use different exposure limits without changing the compiled
`vault-policy-v1` program.

The rolling allowance remains charged while an operation is signed or
submitted, regardless of its age. Once the Guardian verifies finalization,
the completed payment counts for another 24 hours from that observation.
For example, a payment held for two days still consumes allowance for 24 hours
after its finalization is observed. This conservative rule prevents delayed
execution from immediately restoring the full allowance.

A conflicting spend enters `unresolved`. Its debit ages out after 24 hours,
but the vault continues to refuse new cooperative payments. Time alone does
not release that fence. Recovery requires checking the committed transaction
paths and the current chain state; the appropriate unilateral recovery path
depends on which outputs remain controlled by the wallet.

The persisted `CreatedAt` field is the original reservation time during
signing and becomes the accounting timestamp on terminal reconciliation.
Terminal retries preserve that timestamp. The stored bundle digest remains
the original signed reservation commitment; reconstructing it from terminal
accounting fields is unsupported.

The fee is evaluated from the Operator's four `fees.intentFee` CEL programs.
It includes every selected offchain input, the destination, and the change
output when present. P2A is not an intent recipient. The exact program strings
are hashed into the reservation; any fee-policy change before either signing
stage stops the operation. The enrolled vault's recipient, allowance,
absolute-fee, and feerate caps still apply. Its two fee ceilings are also
embedded in the fixed Savings transition template, so changing the policy
values changes the descriptor that both sides must reconstruct before
enrollment can finish.

The live sequence is:

1. The wallet persists a random operation ID, phone-signs the operation ID,
   vault, purpose, destination script, and amount, then calls `reserve`. An
   exact retry returns the same inputs, fee, and change facts.
2. The wallet builds a canonical pending-transaction proof for the exact
   reserved inputs. `authorize` validates the phone-signed proof, user-signed
   Arkade PSBT, and unsigned checkpoints, then adds the VaultCosigner signature
   to the proof and Arkade PSBT. Both are persisted before the response.
3. The wallet submits to the Operator once. If the response is ambiguous, it
   uses the dual-signed proof with the deployed pending-transaction interface
   and accepts only the exact Arkade transaction and checkpoints committed by
   the reservation.
4. The wallet signs those checkpoints, and `checkpoints/authorize` verifies
   their identity and canonical alignment before adding the VaultCosigner.
5. After Operator finalization, `finalize` verifies that every reserved input
   was spent by the authorized Arkade transaction. A change VTXO is required
   only when the reservation committed one.

State changes use compare-and-swap updates. `GET /v1/vtxo/operation` exposes
the persisted fee, change facts, signed transaction stages, and authorized
pending proof so an ambiguous Vault-service response can resume the same
operation. An empty or mismatched Operator lookup remains locked and never
triggers a second submission.

Mutinynet qualification must cover fragmented inputs, exact no-change spends,
nonzero and amount-dependent fees, reloads, dropped Vault-service responses,
ambiguous Operator submissions, empty and mismatched pending lookups,
checkpoint reordering, and concurrent exact retries before this path is
considered for mainnet.
