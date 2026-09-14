# Spending to Bitcoin

Spending payments to Bitcoin use `/v1/vtxo/bitcoin/{info,prepare,register,final,status,release}`.
The first version supports one live Spending input, one or two ordered Bitcoin
outputs, and at least 330 sats of protected Spending change. Standard P2PKH,
P2SH, P2WPKH, P2WSH, and P2TR destinations are accepted with dust checks. Two
identical outputs remain distinct because their order and values belong to the
owner-authorized plan.
Input aggregation and sending the entire balance without change are not
implemented by this version. The wallet supports this route for its existing
Standard and Advanced Spending flow.

## Authorization

The owner-signed prepare request binds the vault, operation, input outpoint,
ordered `{script, amountSats}` outputs, and expiry. The Guardian reconstructs
the enrolled Spending program, resolves the input, and quotes the pinned
Operator fee policy. The plan commits every output, fee, protected change,
policy identity, and expiry. Registration requires the existing passkey and
direct authorization of that exact plan. The recipient cap applies to the sum
of Bitcoin outputs; the rolling allowance includes that sum and the fee.

The official SDK constructs the intent, participates in the batch, signs the
replacement tree, and constructs the owner forfeit. The Guardian verifies the
exact Bitcoin outputs, signed replacement recovery tree, connector path, and
forfeit before its scoped cosignature and durable dispatch. There is no new
raw signing endpoint or Operator modification.

A Bitcoin payment's change may have the same expiry as its input. Only a
renewal requires an expiry extension. Both paths verify the exact replacement
value, script, and commitment, and payment confirmation additionally verifies
the Bitcoin commitment on the canonical chain.

## Pending operations

The runtime accepts explicit output plans and persists
`spending-bitcoin-v1` operations. Retired signer-setup routes and reserve-only
plans are rejected. The current signed plan retains its established field order,
empty reserve fields and digest domains; changing those bytes would change
current owner authorizations.

The wallet journal binds the output plan to its saved owner-signed prepare
request. Changing displayed destinations and recomputing a plan hash cannot
change that authority. The ledger verifies authenticated operation facts before
using their amounts, phases or timestamps, and economic mutations advance the
independent policy sequence.

A lost final response remains uncertain. Expiry, an ended batch, or an unspent
input alone cannot release a potentially escaped signature. Guardian checks the
exact commitment before signing and again before recording final dispatch. If a
crash or delayed request crosses that boundary after the Operator has already
ended the batch, reconciliation releases the reservation only when the retained
dispatch time is strictly later than the Operator's ended time and the exact
original input remains live. Equal second-resolution timestamps remain
uncertain. A separate conflict recovery path can release the reservation after
Guardian verifies that another Bitcoin transaction has spent an input of the
exact retained commitment, with at least six confirmations. See
[Bitcoin conflict recovery](bitcoin-conflict-recovery.md) for its proof and
chain-authority requirements. Pre-final cancellation still needs
the retained owner deletion proof and the existing release conditions.

After confirmation, the wallet retains the operation until the exact
replacement Spending exit is in its durable recovery file. A stale recovery
snapshot cannot make the new change spendable by discarding its journal.

## Qualification

Tests cover destination and amount substitution, duplicate outputs, protected
change, limits, owner-request replay, lost registration and final responses,
ended-before-dispatch ordering, cancellation proofs and an independently
committed SDK intent checked by the Go verifier. Current lifecycle fixtures
enroll shared Spending with optional Ledger Savings on mainnet and Mutinynet,
including Standard and Advanced protection. The SDK vector preserves its signed Spending context, requests,
plan and transaction bytes.

Retired API rejection, reserve-only plan rejection and ledger admission checks
qualify the removal boundary. Complete candidate qualification also requires
cross-repository builds, wallet browser and recovery checks, and exact release
inputs. Funded lifecycle and recovery drills remain separate release gates.
