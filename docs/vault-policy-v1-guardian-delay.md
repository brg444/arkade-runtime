# vault-policy-v1 guardian delay

Product pin: **4608 seconds**. Unit: BIP68 seconds. Encoded as sequence
value `9` (`4608 / 512`) with the seconds type flag.

This is not arkd's advertised hatch. Live Mutinynet `GetInfo.unilateralExitDelay`
is **2048 seconds**. `TapscriptsVtxoScript.Validate` requires the smallest
CSV on the tree to be greater than or equal to that minimum, and BIP68
seconds values must be a multiple of 512. 2048 meets the arkd minimum and
the 512-mod constraint, but it is below the 144-block floor at Mutinynet
(~30s/block → 4320s). Do not freeze 2048.

| Constraint | Value | 4608s |
| --- | --- | --- |
| arkd `unilateralExitDelay` | 2048s | >= |
| BIP68 seconds modulus | 512 | 9 × 512 |
| 144-block floor at ~30s | 4320s | >= |

The tree has exactly three leaves, in this order:

1. collaborative spend/intent Multisig `[user, VTXO VaultCosigner, Arkade Operator]`
2. exactly one guardian CSV exit at this delay
3. delegate-forfeit Multisig `[user, VTXO VaultCosigner, pinned public delegate, Arkade Operator]`

The emulator is not a tree signer. The required VaultCosigner
independently enforces the Vault Program.

Two-key mapping is device+hardware; three-key mapping (when recovery is
present) is hardware+recovery. Those are alternate encodings of the same
exit leaf, not two exits.

Do not read live arkd at runtime to rewrite boarded leaves.
