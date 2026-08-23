# `vault-policy-v1` guardian delay

The current tree pins a 4,608-second BIP68 delay for Mutinynet. The value is
encoded as sequence value `9` because BIP68 seconds use 512-second units.

| Mutinynet constraint | Value | Result |
| --- | --- | --- |
| Operator minimum unilateral exit delay | 2,048 seconds | 4,608 is above the minimum. |
| BIP68 encoding unit | 512 seconds | 4,608 is exactly 9 units. |
| Existing 144-block test posture at roughly 30 seconds per block | 4,320 seconds | 4,608 preserves at least that test interval. |

This is a Mutinynet compatibility pin. It does not establish a mainnet safety
posture. With ten-minute Bitcoin blocks, 4,608 seconds is roughly 1.28 hours,
far shorter than a 144-block observation window.

Mainnet activation therefore requires a separately reviewed delay, including
the threat model, human response time, Operator minimum, BIP68 rounding, and
recovery usability. Freezing that value changes the Taproot tree and requires
new server and wallet contract packs plus regenerated cross-implementation
vectors. Runtime `GetInfo` data may confirm a release pin, but it cannot choose
or rewrite the delay.

The Mutinynet tree contains three leaves in a fixed order:

1. Collaborative spend with the user, VTXO VaultCosigner, and Arkade Operator.
2. One guardian exit at the pinned delay.
3. Delegate-forfeit with the user, VTXO VaultCosigner, pinned public delegate,
   and Arkade Operator.

The two-guardian exit uses the device and hardware keys. When a recovery key
is enrolled, the exit uses hardware and recovery. Both forms encode one exit
leaf; the tree never includes two alternative guardian delays.
