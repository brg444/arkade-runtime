# vault-policy-v1 one-input spend

Collaborative spend is a one-VTXO MVP. Reserve rejects any bundle that is
not exactly one spendable policy VTXO covering `amount + dust`. The wallet
builds only from the single outpoint returned by the reservation and exposes
this limitation directly.

The destination must be a `tark` address for the same pinned Operator. Bitcoin
destinations and VTXO offboarding are outside this slice. The retired onchain
Spending pipeline is not a fallback.

Arkade addresses serialize the Operator key in BIP340 x-only form. Decoding can
therefore normalize an odd-Y compressed key to its even-Y representative. Code
that validates the address must compare the 32-byte x-only keys, not full
compressed-point equality.

The SDK builds a version-3 checkpoint with `[checkpoint output, P2A]` and
a version-3 Arkade transaction with `[destination, vault-policy-v1 change,
P2A]`. Both transactions spend the three-key collaborative leaf
`[user, VTXO VaultCosigner, Arkade Operator]` with `SIGHASH_DEFAULT`.
There is no Emulator Packet and the emulator is not a VTXO tree signer.

The server independently enforces the reserved outpoint, exact tapleaf and
control block, user signature, version, locktime, sequence, output order,
P2A, destination, mandatory change, and input/output conservation. The live
sequence follows the SDK and Operator protocol exactly:

1. The wallet persists a random operation ID, signs the canonical operation
   ID, vault, purpose, destination script, and amount with the phone key, then
   calls `reserve`. The server authenticates the proof before it fixes the one
   input, amount, and change program. An exact retry returns the same
   reservation; a mutated retry is rejected.
2. `authorize` validates the unsigned checkpoints and user-signed Ark PSBT,
   then adds the VaultCosigner signature to the Ark PSBT.
3. The wallet submits that Ark PSBT and the unsigned checkpoints to the
   Operator. The Operator rebuilds and signs the checkpoints.
4. The wallet adds the user signature to those returned checkpoints and
   `checkpoints/authorize` validates the exact stored transaction shape plus
   the user and Operator signatures before adding the VaultCosigner signature.
5. The wallet finalizes with the Operator, then `finalize` verifies that the
   reserved VTXO was spent by the authorized Ark transaction.

The indexer uses two identifiers for that final check. `spentBy` is the
checkpoint transaction ID; `arkTxid` is the Arkade transaction ID that created
the spend. The vault service must compare the authorized Arkade transaction ID
to `arkTxid`, not to `spentBy`.

Signing checkpoints before Operator submission is invalid because the
Operator intentionally rebuilds that stage. State changes use compare-and-swap
updates so concurrent requests cannot overwrite a completed stage.

This slice permits zero virtual fee only. It also requires one input and a
dust-valued change output. Fragmented balances, exact-value sends, and nonzero
Operator fees are mainnet release gates, not wallet errors to disguise.

Deploy this regular VTXO spend path and validate it on Mutinynet before
enabling delegation or beginning Lightning integration.
