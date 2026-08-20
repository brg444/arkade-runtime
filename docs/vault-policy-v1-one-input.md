# vault-policy-v1 one-input spend

Collaborative spend is a one-VTXO MVP. Reserve rejects any bundle that is
not exactly one spendable policy VTXO covering `amount + dust`. The wallet
must coin-select a single VTXO; it must not imply general multi-input
spending.

The SDK builds a version-3 checkpoint with `[checkpoint output, P2A]` and
a version-3 Arkade transaction with `[destination, vault-policy-v1 change,
P2A]`. Both transactions spend the three-key collaborative leaf
`[user, VTXO VaultCosigner, Arkade Operator]` with `SIGHASH_DEFAULT`.
There is no Emulator Packet and the emulator is not a VTXO tree signer.

The server independently enforces the reserved outpoint, exact tapleaf and
control block, user signature, version, locktime, sequence, output order,
P2A, destination, mandatory change, and input/output conservation. This
slice permits zero virtual fee only.

Deploy this regular VTXO spend path and validate it on Mutinynet before
enabling delegation or beginning Lightning integration.
