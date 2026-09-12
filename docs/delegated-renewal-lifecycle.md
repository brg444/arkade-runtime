# Delegated renewal lifecycle

Guardian executes finite owner-authorized Spending renewals through the stock Operator interfaces. The [Spending API](spending-delegated-renewal.md) defines enrollment binding, passkey authorization, bounded sets and authenticated readback. Each plan covers one original input; a replacement requires fresh owner authorization.

The feature is disabled by default. `VAULT_LIGHT_DELEGATION_ENABLED=true` or `--light-delegation-enabled=true` activates the shared scheduler. Mainnet and Mutinynet retain their deployment pins, contracts, fees and allowance policies. Guardian retains no owner key and exposes semantic signing capabilities.

## Transaction authorization

The registration proof has the owner's SIGHASH_ALL signatures, one real input,
one synthetic BIP322 input, and exactly one receiver using the same enrolled
Spending script. Its `valid_at` is at most 30 days ahead; `expire_at` equals the
outer `expiresAt`, lies within 24 hours of `valid_at`, and precedes the input's
expiry by at least 60 seconds. The partial forfeit commits the pinned Operator
destination, input value plus the 330-sat connector, and the standard anchor
using SIGHASH_ALL|ANYONECANPAY. Guardian verifies the actual paid fee against
the current Operator fee expression before claiming the input.

`deleteIntent` uses the same original input and Spending leaf, an owner-signed
BIP322 delete message with `expire_at:0`, and only the synthetic zero-value
OP_RETURN output. It cannot transfer money. Its unrestricted cleanup lifetime
does not extend the finite registration authorization. Guardian adds its delete
signature only after durable abandonment has excluded final-forfeit signing.

## Ownership, signing and restart

Authenticated operation and event records are verified before their correlation, state or time is trusted. Every economic mutation participates in the independent policy sequence. Current record serialization and MAC domains remain unchanged through the schema 12 retirement.

Armed requests consume no allowance and can coexist with a payment reserved
against another input. A payment atomically invalidates overlapping armed
requests. Claiming a due renewal acquires the existing vault-wide execution
fence and reserves only its fee against the allowance. Confirmed renewal fees
remain charged for the rolling 24-hour period. Principal is not counted as a
payment.

Guardian subscribes to the stock Operator stream before registration, saves
the assigned intent ID, acknowledges its matching batch, and participates in
MuSig tree signing. The existing scoped Spending key is normalized to the even
lift of its x-only contract key. Nonce seeds are encrypted under that scoped
key and bound to one validated tree. The key capability checks the persisted
capsule and complete peer nonce transcript before signing. Changed transcripts
are refused, including after restart. Partial signatures and received tree
events are durable before their respective next external step.

Complete signed replacement and connector graphs are independently verified
before the final forfeit is released. An uncertain final submission retries
only the exact retained signed bytes. Final authority permanently retains the
input fence until the expected indexer settlement and Bitcoin commitment are
verified. Status exposes lowercase SDK-compatible `txid`, `tx`, and `children`
nodes; it never exposes nonce seeds or encrypted nonce capsules. The wallet
imports and verifies this public graph on its next unlock and then updates its
existing encrypted backup. An earlier backup does not contain the replacement
path until that import and upload complete.

## Abandonment and availability limits

After the finite authorization deadline plus a 30-second quarantine, an
unsettled operation without final authority can begin cleanup only after its
original input is verified live. Guardian atomically records `cleanup_pending`,
which excludes every later final authorization. A stored signed deletion is
then retried unchanged. A successful deletion response permits terminal
`expired`; a request never dispatched can expire locally.

The stock Operator stream is live, without guaranteed historical replay.
Guardian reconstructs events it previously saved, but cannot reconstruct an
unreceived random registration ID or a missing upstream event. The deletion
endpoint can also return no-match while an intent is selected into a batch.
No-match and a lost successful deletion response therefore remain
`cleanup_pending`, retaining the current vault-wide fence. They are not proof
that the Operator has released its input lock. An old cleanup dispatcher is
fenced after the operation ends so it cannot delete a later generation's
registration. This uncertainty can delay payments while the signing boundary remains enforced.
