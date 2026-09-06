# Vaulted allowance script draft

6 September 2026. Local executable research for `vault-allowance-fixed-draft-v0`.

A payment consumes a shared allowance controller, deducts the recipient amount
and transaction fee, and recreates that controller with the remaining budget.
Deposits add principal without replenishing allowance. A separate renewal
script preserves the selected outputs and, whenever the controller participates,
its exact allowance state.

The isolated Go module contains a script compiler, a state codec, and tests
using the upstream emulator engine and Bitcoin script interpreter. Runtime
profiles, HTTP routes, production keys, Contract Packs, wallet code, and
deployments have no dependency on this module. The first policy has a fixed,
non-replenishing budget; Guardian's rolling 24-hour allowance remains the
production authority.

## Source pins and authority

| Component | Draft pin |
| --- | --- |
| Runtime checkout base | `a70823a28b596195e033c4c25e48d8d82e22a72d` |
| Emulator engine | `4feb9eaa81b49f8d321407e92dba107ec9ba5158`, matching `v0.0.8-rc.0` |
| Protocol library | `f444de6c336c`, full module version in `go.mod` |
| Toolchain | Go 1.26.6 |
| Program identifier | `vault-allowance-fixed-draft-v0` |

The checkout base precedes the merged Light program and schema 2. Integration
must reconcile current runtime and wallet main, protection tiers, and recovery
contracts. This module's separate dependency graph allows the modern engine
to be evaluated without changing the runtime dependency pins.

The initial research is in the workspace's
`outputs/vaulted-emulator-allowance-research-2026-09-05/`. Current source
governs the opcode behavior. The delegation workstream reconfirmed on September
6 that native admission, checkpoints, and controller-asset recovery still need
qualification; its Light recovery evidence covers a different contract.

## Controller and state

Each enrolled vault requires one previously issued asset unit with a fixed
issuance ID. The controller VTXO holds that unit and 330 sats. Principal VTXOs
use the same taproot tree, so every ordinary payment requires the controller.
The tests supply an existing asset identity and authenticated input ownership
as fixtures; bootstrap and issuance are unfinished.

The custom type-2 transaction packet has a canonical 20-byte encoding:

| Bytes | Meaning |
| --- | --- |
| 0–3 | ASCII `VA00` program/version magic |
| 4–11 | Remaining allowance, unsigned little-endian integer |
| 12–19 | Sequence, unsigned little-endian integer |

The script checks length, magic, numeric bounds, and the padded numeric
representation, including rejection of negative zero. Remaining allowance is
bounded by the compiled budget, which is at most 1,000,000,000 sats. Sequence
is bounded by 2,147,483,647 and each payment increments it once. Exhausting the
sequence requires a separately authorized migration. Type 2 is a draft-local
assignment that needs collision review before release.

Controller identity relies on stock Operator asset validation authenticating
the transaction's declarations against resolved input assets. Tests explicitly
show that a fabricated ownership declaration can satisfy VM introspection
while failing `ValidateAssetTransaction`. They also show that hiding a
controller's asset packet during renewal fails that external check.

One-time issuance must create exactly one unit with no reissuance authority,
then move it into the enrolled tree with the approved initial state. This
two-stage bootstrap resolves the circular dependency between the issuance
transaction ID and a script containing that ID. Enrollment must authenticate
the issuance, supply, absence of reissuance authority, initial state, and
bootstrap completion before accepting principal deposits.

## Payment contract

The draft accepts version-3 transactions with controller input 0 followed by
one to four principal inputs. All selected inputs must have the same protected
script. The output order is fixed:

```text
controller (330 sats), recipient, optional protected change, zero-value P2A, extension
```

Exactly one asset group transfers the controller's single unit from input 0
to output 0. Both controller value and script remain unchanged. Recipient
and change outputs must be taproot outputs of at least 330 sats, and change
must return to the protected script.

```text
debit         = sum(principal input values) - protected change
fee           = debit - recipient value
new remaining = previous controller remaining - debit
new sequence  = previous controller sequence + 1
```

The script enforces the recipient cap, an absolute nonnegative fee cap, and
the exact successor state. Additional destinations, malformed state, cap
splitting, budget restoration, and escaping change fail. The separate
controller retains its 330 sats when principal is spent exactly or allowance
reaches zero. Refunds and deposits enter as principal; this draft provides no
credit transition.

The fixture's cooperative Bitcoin leaf requires the user, Guardian, tweaked
emulator, and Operator signatures. A Bitcoin interpreter test signs an actual
fixture transaction and rejects each missing signer and a changed recipient
amount. The fixture contains only the payment and renewal leaves. Production
recovery leaves and their commitments remain an integration requirement.

Each payment must consume the current controller, so payments funded by
different principal inputs still conflict on that outpoint. The VM can approve
two conflicting proposals independently. Authoritative single-spend admission,
reservation coordination, and reconciliation of outstanding signatures must
ensure only one transition completes.

## Renewal contract

The renewal script accepts version-2 intent-proof shapes. Input 0 represents
the synthetic message input; each selected VTXO at input `i` maps to output
`i - 1`. The final zero-value extension makes output count equal input count.
Each evaluated input requires:

```text
OP_PUSHEXPIRY <renewal window> OP_SUB OP_CHECKTIMEVERIFY
```

The intent must be `register`, contain no onchain output indexes, and specify
exactly the compiled delegate cosigner. `OP_TUNNEL` uses all three preservation
flags, with no exceptions. Explicit checks also preserve every selected
input's script and value, leaving zero transaction fee in this proof shape.
The renewal fixture leaf requires the tweaked emulator and Operator signatures.
Its absence of an owner signature makes faithful emulator execution and
Operator admission part of the renewal authorization boundary.

Controller renewal places the controller at input 1 and preserves the entire
allowance packet, including sequence. It can include up to four principal
inputs. Principal-only renewal accepts one to four inputs, omits the asset
and allowance packets, and leaves the controller untouched. This allows older
deposits to renew while a recently renewed controller remains outside its own
renewal window. Operator asset validation must reject passing the controller
through the principal-only path.

The engine supplies each input's expiry and execution clock. The test supplies
those expiries as fixtures; the signing service must resolve them from its
configured indexer. `OP_CHECKTIMEVERIFY` establishes that a threshold has been
reached. It supplies neither an authenticated debit creation time nor a
deadline after which an issued signature becomes invalid.

Each renewal input reads four intent fields. A five-input renewal passes with
the stock shared request budget of 64 message inspections and fails with a
shared limit of 19. Batch packet propagation, native BIP322 proof acceptance,
tree signing, and finalization are outside these local tests. In particular,
the fixture's synthetic input represents indexing and value context only.

## Qualification and next implementation

Run the nested module explicitly:

```sh
cd tools/allowance-draft
go mod verify
go vet ./...
go test -race ./...
go test -run '^$' -fuzz FuzzStateEncoding -fuzztime=3s -parallel=2
```

The tests exercise serialized extension packets, previous transaction state,
taproot commitments, emulator-key binding, authoritative asset validation
with fixture ownership, and the actual emulator interpreter. They cover
valid spends, hostile transaction mutations, deposits, a three-payment
successor chain, conflicting proposals, controller renewal, principal renewal,
and Bitcoin payment signatures. Production admission and signing APIs are
absent from the harness.

For the test parameters, payment bytecode is 648 bytes and renewal bytecode
is 773 bytes. The maximum fixture payment is 3,724 unsigned bytes, including
3,356 extension bytes. The maximum fixture renewal is 4,463 unsigned bytes,
including 3,981 extension bytes. The extension repeats the program for each
input. Native admission, fees, witness size, and transport limits still need
measurement on the completed transaction path.

The next implementation should qualify these dependencies in order:

1. **Bootstrap and native admission.** Issue one immutable controller unit,
   establish the enrolled initial state, and exercise native VTXOs and
   checkpoints through the supported emulator and Operator interfaces.
   Qualify resolution of both logical VTXO scripts and previous transaction
   packets. Retain the established fee and feerate policy, canonical input
   ordering, and checkpoint constraints in the new named program.
2. **State across settlement.** Execute payment, controller renewal, independent
   principal renewal, and another payment through actual batches. Capture
   successor ancestry and state artifacts, then repeat after process and
   wallet restarts. Test missing packet data, refunds, Lightning funding,
   conflicting dispatch, and lost responses. A locally accepted proof alone
   cannot establish successful settlement or cancellation.
3. **Recovery and migration.** Define and test Light, Standard, and Advanced
   recovery under their own approved key combinations and delays. Recovery of
   Bitcoin principal can exit the cooperative policy; recovery of controller
   authority is a separate obligation. Decide whether loss requires a new
   vault and explicit migration. Build matching Contract Packs, enrollment
   commitments, boarding destinations, wallet handlers, and recovery archives.
   Existing funded trees retain their original contracts until spent through
   an authorized path.
4. **Rolling allowance.** Bind debit time to authenticated transaction and
   lifecycle evidence, retain outstanding signed obligations, and define
   bounded expiry-state storage. Compare boundary behavior against Guardian's
   rolling ledger. A fixed day reset or continuous refill changes the policy;
   adding either requires an explicit product decision.

Guardian remains necessary for authentication and lifecycle coordination during
qualification. Removing its allowance calculation follows evidence that the
new program covers the same intended rules and can recover after uncertain
dispatch, offline renewal, and loss of local state. The emulator becomes a
required policy-signing trust domain: Bitcoin validates its signature while
the extended program executes in the emulator.
