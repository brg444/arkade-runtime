# Simple Savings: direct approval and delayed phone-loss recovery

Proposed 2026-09-06. Keep everyday payments in the existing Spending wallet.
Hold Savings onchain with two user-controlled signing identities and one delayed
fallback. This replaces the connector/native-Savings direction as the next
proposal to qualify; existing funded contracts remain unchanged.

## One spending policy

P is the phone signer. H is the independent signer, with its seed backup kept
outside the phone and Vault services. H can be a software wallet for testing;
physical hardware support requires its own qualification.

| Path | Required approval | When available |
| --- | --- | --- |
| Normal payment | P and H | Immediately |
| Phone-loss recovery | H alone | After the output's 12,960-block relative lock matures, approximately 90 days |

The proposed delay is 12,960 blocks, subject to qualification before release.
Use a native SegWit P2WSH Miniscript descriptor. There is one primary path and
one recovery path, with no online-service key in either. Generate the exact
script with a supported compiler and verify that these are its only spending
authorities. H may derive separate normal/recovery child keys under one seed;
the descriptor records their complete origins.

Bitcoin must reject every spend made with only P and all server keys. H remains
necessary through both paths. After the delay, H can spend without P; that is
an explicit reduction from two approvals to one. Loss of the physical H device
is recoverable from its seed. Loss of H and every backup is unrecoverable under
this policy. A third recovery signer and inheritance paths are outside this
first design.

## What the owner does

Vaulted constructs the payment, obtains the phone signature, and exports a PSBT.
The independent wallet imports the complete Savings descriptor, reviews the
actual recipient, amount, fee, and change, then signs its own Savings input.
Vaulted verifies SIGHASH_ALL and the unchanged transaction before broadcast.
The independent key signs the payment directly; the transaction needs no
connector deposit or separate authorization message.

A transfer into Spending pays the existing boarding address and uses its current
confirmation/boarding flow. Other Bitcoin recipients remain allowed. Savings
has Bitcoin fees and dust constraints, without Spending payment/rolling limits.

If the phone or Vaulted disappears, the owner imports the descriptor and H into
the qualified independent wallet and spends eligible outputs through recovery,
using Bitcoin access. Backup needs the descriptor and H seed; there is no
presigned transaction graph to refresh after every payment. Normal public
transaction history still has to be discovered and verified.

## The delay means coin age

[BIP 68](https://bips.dev/68/) measures relative age from the spent output's
confirmation. The delay does not start when someone presses Recover. Old outputs
may already be recoverable immediately; each new deposit or change output has
its own clock. There is no cancellation window or clawback after a valid spend.

Savings does not expire and needs no periodic transaction to preserve funds.
The two-approval requirement does relax as coins age. Restoring that requirement
for an aged output requires an authorized transaction creating a fresh output.
Automatic refresh and recovery-cancellation services are outside this design.

## One signer qualification

Target [Liana v15.0](https://github.com/wizardsardine/liana/tree/4684d5cb0c75471ae40f43dffc78333ac74afb38)
first. Its [policy implementation](https://github.com/wizardsardine/liana/blob/4684d5cb0c75471ae40f43dffc78333ac74afb38/liana/src/descriptors/analysis.rs)
supports primary multisig and delayed recovery under P2WSH, including separate
child-key paths for the same signer. This is source support; the exact Vaulted
PSBT and user flow have not been tested. Sparrow's ordinary multisig support and
the earlier connector tests are insufficient evidence for this timed policy.

Before enrollment work, prove one fixture: import the descriptor in Liana, sign
a real payment with P and H, reject recipient mutation, and confirm recovery
with H alone only at the correct block boundary. Include multiple deposits,
change, descriptor/seed restoration, and fee replacement; every replacement
needs signatures valid for its own transaction. Run Bitcoin validation with all
Vault services unavailable and test P-only attacks before and after maturity.

## What leaves the design

Savings needs no connector reserve, Guardian authorization, external emulator,
Operator signing, checkpoint archive, expiry renewal, pending recovery tree, or
quarantine transaction. Spending retains its existing services and recovery.
The native contingency and connector experiments remain reference material.
A qualified new descriptor requires new enrollment and an authorized migration;
existing Savings funds keep their original scripts and recovery tooling.
