# Rolling allowance implementation and release gates

8 September 2026. `vault-allowance-rolling-v1` is an implementation candidate
with Go and TypeScript compilers, native and renewal transaction builders, an
authenticated runtime journal and a scoped finalization receipt issuer. It is not activated
in production enrollment or the wallet payment flow, and is not ready for
deployment with funds.

## Allowance rule and trust boundary

Payments deduct their recipient amount and any permitted fee from a unique
controller. Each debit remains charged until the runtime independently observes
finalization, then for at least another 24 hours. Signed or submitted operations
with an unknown outcome never regain allowance merely because time passes.

The controller commits the remaining amount, a monotonically increasing debit
sequence and a sparse history root. A mature credit removes one exact debit
from that history before restoring its amount, so the same receipt cannot
increase allowance twice. Credits retain the monotonically increasing sequence. The service and
wallet reconstruct a deterministic history layout and check its root against
the transaction state.

`OP_CHECKTIMEVERIFY` enforces the emulator's time threshold; it cannot establish
when an earlier payment finalized. A separate BIP340 receipt key signs the
first independently observed finalization time and the exact debit identity.
The domain binds the network, controller issuance, receipt key, policy,
delegate and checkpoint exit. Credit requires integer time strictly greater
than `observedAt + 86400`. The shared Savings and Spending ledger uses the same
boundary, including fractional-second observations.

The Operator authenticates asset issuance, input assets and conflicting spends.
The emulator enforces script execution, while Guardian authenticates the owner,
reserves shared allowance and attests the finalization observation. This design
retains the authenticated ledger and its independent policy sequence; it does
not eliminate those responsibilities.

## Implemented candidate

The controller is one non-reissuable asset unit carried by a 330-sat output.
Its state is 52 bytes: `VR01`, remaining allowance, debit sequence and history
root. A debit is 52 bytes, including its amount and the actual parent outpoint.
Native payments bind the checkpoint parent; renewal binds the original VTXO.
Thirty-one history levels use sorted, tagged SHA256 branches and two witness
chunks that stay within the emulator's element limit.

The current complete tree has five leaves:

| Leaf | Required keys | Permitted use |
| --- | --- | --- |
| Payment | Device, Guardian, emulator, Operator | Debit actual outflow and preserve protected change |
| Credit | Device, Guardian, emulator, Operator | Restore one mature authenticated debit |
| Renewal | Guardian, emulator, Operator | Register preserved outputs to the exact delegate within each source's renewal window |
| Cleanup | Guardian, emulator, Operator | Prove deletion of original inputs using a short-lived intent |
| Recovery | Tier-specific recovery keys | Delayed Bitcoin exit without Guardian or emulator |

Cleanup messages expire within five minutes. The script checks a numeric expiry
and its earliest valid issue time; the stock message validators reject expired
proofs. Cleanup does not require the original source's expiry lookup. The
Guardian signs only after an atomic journal mutation fences the exact renewal
against final signing and retains its immutable deadline. The private cleanup
capability reconstructs the proof from stored sources, while the service
independently verifies the returned signatures before retaining and releasing
the proof. There is no production cleanup route or dispatcher. Already accepted
remote deletions still require a barrier before the original inputs can safely
enter a later registration.

The emulator's finalization API must also be tested with a cleanup proof. Its
source associates prior proof signatures with later forfeits without executing
the script again. Guardian's full transaction signature must never transfer to
a monetary transaction or a weaker sighash. A delete-only script is therefore
not, on its own, a claim about every emulator API.

The runtime journal uses additive schema 6 tables in the existing SQLite
ledger, verifies MACs before filtering, and advances the independent sequence
before committing economic mutations. WebAuthn counter advancement and retained
Guardian signatures commit atomically. Native and renewal registration
authorization reconstruct the saved semantic proposal; their key capability
accepts no caller PSBT, digest or observation timestamp.

The wallet independently builds the scripts, complete tree, native payments,
credits, renewal proofs and authorization digest. The shared fixture covers
transaction bytes, zero-fee and fee-bearing renewal, checkpoint bytes, state,
proofs, receipts and every leaf/control block. Source metadata retains complete
previous transactions, including witnesses. Generic
SDK selection cannot spend this contract. Enrollment, foreground coordination
and Recovery Kit integration remain required before activation.

Renewal also requires a fresh Guardian signature on the final forfeits. Its
registration signature and tree participation cannot satisfy that gate. The
private runtime capability now verifies and atomically retains the complete
signed successor graph, commitment, connectors and ordered forfeit set before
Guardian signing. The final graph must match both retained tree-session
bindings. Every recovery node uses the qualified immediate-spend transaction
header; valid signatures cannot conceal an added absolute or relative delay.
Cleanup and final authority exclude each other at the same persistence
boundary, and final signatures are retained before release.

First registration authority, final authority and final-signature retention
must occur within the registration validity window. The key backend also
checks current time before generating fresh final signatures. A clock crossing
after final authority leaves the fence intact. Already retained final signatures
can be returned after expiry without access to the master signing key. These
private capabilities still need the production delegation session adapter.

## Qualification evidence

The isolated module pins upstream emulator
`4feb9eaa81b49f8d321407e92dba107ec9ba5158`, version `v0.0.8-rc.0`, and stock
Operator `v0.9.16` at `e2d9ed443df7a0dfb3aa1e5c824de9541ff71047`.
The production root module retains the existing Savings emulator dialect; it
executes Savings; the new bytecode requires the separately qualified emulator.

The current five-leaf candidate completed real regtest issuance, native payment,
mature credit, delegated batch renewal and a payment from the successor
controller through the stock Operator and upstream emulator. A further renewal
was registered and deleted using the bounded cleanup proof through the same
public APIs. The credit used a backdated test-only receipt, while separate VM
tests exercise the actual maturity boundary. The batch coordinator remains an
admission fixture without the production persistence and recovery safeguards.
This run does not qualify funded emergency recovery, lost cleanup responses or
replay against a later registration.

`make rolling-check` verifies the isolated module, vets it, runs its race suite
and checks the portable Go fixture. CI now runs this gate separately from the
production module. The tests include receipt replay, malformed state, strict
maturity, native payment and credit, fee-bearing renewal, cleanup proof shape,
and actual Bitcoin script verification of each tier's delayed exit. They do
not replace funded recovery or live cleanup qualification.

The wallet candidate uses its checked-in SDK tarball, whose origin record pins
source `552106239d9ebfadd56e79c1a5286951029e97b1` and SHA256
`baf08f891e4a3e9dbad57d8fa731c47c0b57b69662688bb4a163765810c21b9d`.
The SDK lifecycle remains the reference for transaction coordination and
retained recovery ancestry.

## Required before activation

1. Bind one immutable full profile to the funded controller, Guardian and
   receipt scopes, exact delegate, release emulator, protection tier and policy.
   Independently verify single-unit issuance and bootstrap admission, and retain
   recovery material before publishing a receiving destination. Existing funded
   trees cannot be edited in place; migration requires its own transaction path.
2. Complete the typed HTTP and wallet foreground workflow, including input
   discovery, reserve, device proof, emulator submission, reconciliation and
   history recovery. Native builders currently require zero Operator fee;
   nonzero fee policy must refuse admission until separately qualified.
3. Adapt the existing delegation scheduler and retained nonce/transcript
   machinery to the controller and all principal inputs. Bind actual Operator
   registration and tree-session events to the new journal stages, and apply
   the recovery header and output checks before nonce generation as well as
   final signing. The private final verifier and signature journal are implemented;
   the production session adapter remains absent.
4. Connect the cleanup capability to stale-dispatch protection, a qualified
   clock margin and a barrier for already accepted remote deletions. The basic
   registered-intent deletion passed regtest; qualification still requires lost responses,
   expired proofs, no-match handling and later-generation safety.
5. Close renewal liveness cases: incompatible source windows, fee exhaustion,
   mature credits near expiry and principal-only renewal. Charge each renewal
   fee once in the shared allowance system.
6. Integrate complete controller history and grouped successor imports into the
   encrypted recovery archive. Exercise each offered protection tier with funded
   outputs after payment, credit and renewal, with Guardian, emulator, Operator
   and their indexers unavailable. Bitcoin recovery does not establish continued
   usability of the controller asset after exit.
7. Pin the release endpoint and Contract Pack, pass runtime and wallet release
   checks, build the exact deployment images, then qualify fresh enrollment,
   restart, backup, restore, rollback and outage behavior on the target network.
