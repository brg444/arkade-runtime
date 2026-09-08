# Allowance construction qualification

8 September 2026. The fixed-budget contract now has native transaction
construction tests covering controller bootstrap, checkpoints, signed intent
proofs, and a payment after construction of a replacement batch leaf. These
tests exercise protocol libraries locally; live admission and settlement
remain release gates.

## Reviewed source

| Component | Revision and consequence |
| --- | --- |
| Runtime main | `bddc84284dba42b3521fd1a0dd6b441a377a8d0e`; schema 5 and finite native renewal for all Spending programs are merged. |
| Wallet main | `d4f7458c0238246c319c77367cb7b4e51e9154d3`; native renewal, recovery ancestry, and portable Spending recovery are present. |
| Emulator master | `4feb9eaa81b49f8d321407e92dba107ec9ba5158`; the draft engine pin remains current. |
| Operator master | `f863e484719344edbe4a8d10cf5fe994b123f2c0`; current master has migrated to btcd v0.26 and version-2 submodules. |
| Operator v0.9.16 | `e2d9ed443df7a0dfb3aa1e5c824de9541ff71047`; this tag identifies the installed local Operator image, whose container was stopped. |
| Construction library | `f444de6c336c`; the draft retains its own pinned protocol library and dependency graph. |

The current [native renewal implementation](https://github.com/brg444/arkade-runtime/blob/bddc84284dba42b3521fd1a0dd6b441a377a8d0e/docs/spending-delegated-renewal.md)
uses finite owner-authorized plans for the existing enrolled contracts. It
preserves the original recovery leaves and requires verified replacement
graphs before final forfeit signing. The emulator draft's recursive renewal
leaf is a different authorization model and needs its own enrollment and
recovery qualification.

The current [allowance rules](https://github.com/brg444/arkade-runtime/blob/bddc84284dba42b3521fd1a0dd6b441a377a8d0e/docs/vault-policy-v1-spend.md)
retain signed/submitted debits indefinitely, then charge completed payments
for 24 hours after Guardian observes finalization. That terminal timestamp
reset already existed in the September 5 inspected source; the original
research's reservation-time description omitted it. Current allowance also
includes claimed renewal fees, retaining confirmed fees for 24 hours after
confirmation observation. Armed renewal plans consume no allowance.

## Bootstrap verification

`ValidateBootstrap` takes independently reconstructed enrollment expectations
and verifies a genesis plus a native checkpoint transfer. Genesis must issue
exactly one controller unit at output 0, with no reissuance authority or
metadata. The controller holds 330 sats under the expected issuer script.
Its issuance transaction hash and group index must match the expected ID.

The transfer has one checkpoint input and exactly three outputs: the expected
controller destination, the standard zero-value P2A, and the extension. It
preserves the unit and 330 sats, and initializes remaining allowance to the
expected budget with sequence zero. The native link check reconstructs the
checkpoint tree from the pinned Operator exit and selected source leaf,
verifies both taproot commitments, and reconciles values and previous
transaction attachments.

The tests construct genesis and transfer using `offchain.BuildTxs`, derive
controller identity from the actual genesis hash, and verify signatures on the
bootstrap transfer and its checkpoint. Adversarial cases cover altered
identity, issuer, destination, budget, supply, reissuance authority, previous
outputs, checkpoint links, selected leaves, and missing data.

This verifier establishes construction and hash linkage. The initial funding
output remains a fixture, while authoritative issuance admission, unspent
status, and authenticated enrollment are external prerequisites. Calling this
function alone must never activate an enrollment. The expected contract script
must be reconstructed independently from the named program and enrolled keys.

## Payment and renewal construction

The payment test builds a separate checkpoint for each selected VTXO. It
executes the unchanged allowance script using direct checkpoint values and
logical previous VTXO scripts and packets. The checkpoint script differs from
the protected Spending script, so returning the direct checkpoint script from
the logical-script resolver would break continuation. Changed or missing
logical previous transactions fail verification.

The native payment and its checkpoints require all four fixture signatures.
The pinned stock builder requires input/output value equality; these tests
use zero fees. Positive native fees, current Operator fee expressions, and the
enrolled feerate cap need a separately qualified transaction builder.

Renewal uses `intent.New`, an explicit empty onchain-output list, finite
message validity, and the actual synthetic message input. The emulator checks
each real input with one shared compute budget. The emulator and Operator
fixture keys sign every proof input, and `intent.Verify` validates the
message commitment and signatures. Changing the message or a receiver after
signing fails verification. Test code supplies expiry and final signatures;
the signing service and indexer have yet to be exercised.

## Replacement leaf and subsequent payment

The construction test reproduces the Operator's current
[intent-to-leaf packet mapping](https://github.com/arkade-os/arkd/blob/f863e484719344edbe4a8d10cf5fe994b123f2c0/internal/core/application/service.go#L2113):
asset inputs become intent references through `LeafTxPacket`, while other
packet bytes are preserved. The stock `BuildVtxoTree` builder constructs a
grouped leaf containing the requested outputs and extension. Its allowance
packet matches the intent byte-for-byte, and the asset packet retains the
intent transaction ID.

A subsequent payment consumes that constructed leaf through new checkpoints
and decreases the allowance again. An attempted refill fails. This proves
composition of the serializers, tree builder, previous-state lookup, and
allowance program under fixture context. It leaves Operator registration,
persisted packet propagation, batch signing, confirmation, and restart
reconciliation untested.

The existing local regtest stack had no running Operator and exposed emulator
v0.0.7, which lacks the required renewal opcodes. Those shared services were
left intact. The next service-level experiment needs a dedicated stack with
pinned compatible versions, admitted genesis, native fee construction, and a
complete recovery tree before funded lifecycle evidence can be recorded.
