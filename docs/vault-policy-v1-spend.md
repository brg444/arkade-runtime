# `vault-policy-v1` Spending

An ordinary Spending payment reserves between one and 50 spendable
`vault-policy-v1` VTXOs. Selection is deterministic by effective value, then
the reserved set is persisted and returned in canonical outpoint order. A
single operation can therefore spend fragmented balances without making caller
order part of the signed contract.

The destination must be a `tark` address for the same release-pinned Operator.
Bitcoin destinations and VTXO offboarding remain separate programs. The
retired onchain Spending pipeline is not a fallback.

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

The fee is evaluated from the Operator's four `fees.intentFee` CEL programs.
It includes every selected offchain input, the destination, and the change
output when present. P2A is not an intent recipient. The exact program strings
are hashed into the reservation; any fee-policy change before either signing
stage stops the operation. The vault's recipient, allowance, and absolute fee
caps still apply.

The live sequence is:

1. The wallet persists a random operation ID, phone-signs the operation ID,
   vault, purpose, destination script, and amount, then calls `reserve`. An
   exact retry returns the same inputs, fee, and change facts.
2. `authorize` validates the user-signed Arkade PSBT and unsigned checkpoints,
   then adds the VaultCosigner signature to the Arkade PSBT.
3. The Operator signs one checkpoint per reserved input.
4. The wallet signs those checkpoints, and `checkpoints/authorize` verifies
   their identity and canonical alignment before adding the VaultCosigner.
5. After Operator finalization, `finalize` verifies that every reserved input
   was spent by the authorized Arkade transaction. A change VTXO is required
   only when the reservation committed one.

State changes use compare-and-swap updates. `GET /v1/vtxo/operation` exposes
the persisted fee and change facts with the signed transaction stages so an
ambiguous response can resume the same operation.

Mutinynet qualification must cover fragmented inputs, exact no-change spends,
nonzero and amount-dependent fees, reloads, dropped responses, checkpoint
reordering, and concurrent exact retries before this path is considered for
mainnet.
