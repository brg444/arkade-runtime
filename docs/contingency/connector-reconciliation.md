# Connector work and the Savings contingency

Reconciled 2026-09-06. The contingency branch owns the future Savings contract,
Operator lifecycle, and timelocked recovery. The connector branch supplies
reusable experiments and signer qualification. Its onchain contract is excluded
from the native implementation; no production activation or migration follows
from this reconciliation.

## The requirement that carries forward

The user must approve the actual payment destination and amount in the chosen
signer. The accepted signature must commit every output, and Vaulted must verify
it against the retained transaction. A message signature, intent proof, or a
separate authorization transaction is insufficient unless an executable proof
establishes both its destination binding and honest display to the user.

A connector is one possible way to meet that requirement. Retain it only if the
supported transaction flow and the selected wallet accept it. Direct signing of
the native Savings path is also a candidate; it requires its own demonstrated
wallet support. Sparrow and Electrum are the present software targets, while
physical hardware support remains separately qualified.

The accepted L1 experiment permits a chosen Bitcoin recipient, including the
user's Spending destination, without Spending payment or rolling limits on
Savings. Preserve this product intent in evaluation. Native VTXO recipient
outputs and direct onchain withdrawals have different lifecycles; qualify each
supported destination and show the actual output being authorized. A narrower
recipient policy needs an explicit product decision; a direct Bitcoin withdrawal
needs qualification of its complete native-to-onchain path.

## What survives from the connector branch

| Existing artifact | Reuse in the contingency | Boundary |
| --- | --- | --- |
| Runtime `experiments/connector/connector_test.go` | Program-versus-consensus counterexamples, missing-key cases, fixed-presignature limitation | Add every required online key, including Operator, to the native attacker set. |
| Runtime `internal/vault/connector/handoff.go` and wallet `connectorPayment.ts` | Immutable transaction comparison, independent signature verification, parent validation, strict sighash rejection | Extract only after the new transaction shape is known; current builders assume the L1 contract. |
| Runtime `family_test.go` and wallet `connector-vectors.json` | Cross-language vector methodology and regression reference | Existing script bytes, descriptors, fees, and addresses identify the old candidate. Generate new vectors. |
| Wallet `tools/connector-signers` | Real Electrum/Sparrow import, signing, output display, and return adapters | Existing results cover conventional P2WPKH/BIP86 inputs with finalized foreign Savings. Native signing remains unproved. |
| Fixed reserve and successor tests | Conflict, replay, refill, and value-conservation cases if a reserve is retained | The 1,000-sat reserve, two-input shape, output positions, and L1 anchor are experimental choices. |
| Recovery-family and Core tests | CSV boundary and alternate-leaf regression cases | Recovery from a native enrollment needs the complete ancestry and transition test. |
| Light recovery and lifecycle code on merged main | Signed ancestry capture, reconciliation, archive freshness, and Bitcoin exit patterns | Its owner-only authority does not establish Standard/Advanced protection. |

Source pins: [runtime connector](https://github.com/brg444/arkade-runtime/tree/9630b75dbe52ead1f99a4d634d82118ca8864b6c/experiments/connector)
and [wallet connector](https://github.com/brg444/vaulted-bitcoin-wallet/tree/fbc5b1d3e7a0d9921580130e5e129db39285a2f6/tools/connector-signers).
Keep those experiments reproducible on their branch. Avoid merging the whole
branch or copying a second transaction coordinator into the contingency.

## Three separate design decisions

**Transaction flow.** The implemented connector spends onchain Savings through
`/v1/onchain-tx`, without the Operator key. The intended contingency requires
Operator-compatible cooperative transactions. The inspected native flow requires
checkpoints and backing VTXOs for every input; boarding also validates an
Operator-compatible script. Appending an ordinary Sparrow UTXO fails those input requirements.
A connector represented as a VTXO changes the signer path and needs a new
compatibility test. The [source inventory](context.md) pins this admission
evidence; it does not attest the current operated service version.

**Signing service.** [Emulator PR 102](upstream-signing-library.md) may allow reuse
of an embedded execution/signing engine. Its program-signing key and Operator
public key remain separate inputs. Engine placement does not establish input
admission or merge their authority. Keeping both Guardian and program-signing
keys under one administrator changes the independence assumption. A separately
operated L1 signer is an alternative architecture, outside the selected native
contingency; it cannot authorize outputs committed to a different key.

**Hardware enforcement.** The original strict test gives the attacker the phone
and every online signing key while withholding hardware. The implemented L1
connector fails that test even though its program rejects the same attack.
The later accepted honest-cosigner tradeoff remains an explicit, different
outcome. Native testing must report both results and show whether that accepted
model transfers unchanged. A required Operator key belongs in the compromised
set; service admission never counts as a strict hardware-enforcement pass.
Material changes to authority or independence require a new trust decision.

## One implementation sequence

1. Specify the candidate input types, complete signer matrix, engine/key owners,
   and outputs. With disposable keys, prove an admitted cooperative transaction
   and actual destination review/signing in Sparrow or Electrum. Test signing
   order explicitly: the old handoff finalized Savings before asking for the
   connector signature. Neither a signed checkpoint nor a generic PSBT import
   establishes the required payment approval. If direct signing works, remove
   the connector; if both fail, record the specific missing capability before
   building enrollment or reserve tracking.
2. Run program-policy tests separately from Bitcoin-consensus bypass tests over
   every spendable leaf and key path. Include Operator compromise, alternate
   recovery leaves, substituted connector inputs, changed outputs, and weak
   sighashes. A presigned alternative must prove the complete reusable graph
   and setup/key-removal assumptions, including deposits, fees and replacement.
3. Complete the [timelocked recovery plan](implementation/native-savings.md):
   committed ancestors, confirmed exit output, then the selected delayed user-key
   sweep. Start with outage recovery while phone and hardware remain available,
   then qualify key-loss initiation, pending claim, and cancellation separately.
   Any lone-key fallback requires an explicit authority decision for that route. Repeat after spending and renewal,
   using saved artifacts with online services unavailable. Use the new contract's
   actual clocks, fees, expiry, and archive-freshness requirements.
4. Only after these results identify a supported contract, integrate a new named
   descriptor, enrollment, semantic authorization, SDK coordinator, and recovery
   archive. Preserve unresolved signed operations across reloads and failures.
   Qualify funded Mutinynet lifecycle and generation-specific migration before
   considering mainnet activation.

## Branch and release alignment

At reconciliation, contingency heads were runtime `8d90467` and wallet
`b0b970e`, on `codex/operator-gated-contingency`. Their preparation baselines were
runtime `a70823a` and wallet `53c5973`. Fetched main has since advanced to runtime
`15a83fbe425e3093b0e48839db4422e1b44947f7` and wallet
`7687134f9be2428062a841aad4c71821c0c230ae`, including Light and its wallet updates.
These preparation branches are historical baselines, not replacement RC builds.
Before implementation, incorporate reviewed current main changes and preserve
Light, schema-2 records, existing contracts, and recovery behavior. Before any
release, verify actual deployment manifests again.

Connector branches remain isolated qualification references. The contingency
[implementation plan](implementation/native-savings.md) is the active work order;
this document determines which connector artifacts belong in it. Existing funded
Savings keeps its descriptor and authorized paths. A new contract requires an
intentional transaction into a new enrollment, with old-generation recovery
retained for any remaining funds.
