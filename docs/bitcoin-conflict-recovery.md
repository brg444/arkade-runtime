# Bitcoin payment conflict recovery

A Bitcoin payment whose final response was lost can retain a Spending input
and its allowance indefinitely. Status reconciliation now releases that
reservation when the pinned Bitcoin chain service establishes that a different
transaction spent a funding input of the retained commitment, with at least six
confirmations. Both `savings-setup-v1` and `spending-bitcoin-v1` use this path.
Ordinary Spending renewals retain their existing release rules.

The Guardian first verifies the retained owner registration, complete final
transcript, commitment, connector path, and forfeit signatures. The dispatched
request digest must match that transcript. The verifier then checks the raw
conflicting transaction against its reported txid, input index, and an actual
funding outpoint of the retained commitment. Because the signed connector and
forfeit path depends on that exact commitment, the confirmed conflict prevents
that path from settling on the observed chain.

The release requires the original Spending output to remain live under its
original script and value. Missing indexer data, an unconfirmed conflict, a
shallow confirmation, malformed transaction bytes, or changing chain responses
preserve the reservation. Expiry, a failed batch, and an unspent input alone
remain insufficient.

There is one separate proof for a final request delayed past the Operator's
batch deadline. Guardian checks the exact commitment before signing and again
before the durable final-dispatch event. Reconciliation may release a dispatch
with no final result when the release-pinned Operator reports that commitment's
ended time, the authenticated dispatch time is strictly later, and the exact
original input is still live with its original script, value, expiry, and
commitment ancestry. Equal timestamps preserve the reservation because the
Operator endpoint has one-second resolution. This proof establishes that the
first dispatch happened after the exact batch became irreversibly unavailable;
it does not infer failure from elapsed time or a generic batch error.

## Chain authority and finality

The release-pinned HTTPS Esplora service remains the chain authority. The
Guardian verifies its network checkpoint, reads the conflicting transaction's
status and funding outspend twice, and checks both the conflict block and the
observed tip against their canonical heights. Raw transaction verification binds
the reported spender to the commitment input; it does not independently prove
block inclusion or accumulated proof of work.

Six confirmations are the accepted finality assumption for this release. A
reorganization that removes the conflict could make the old commitment viable
again. A compromised chain service could fabricate confirmation information.
This implementation therefore depends on the pinned chain service and the
six-confirmation assumption; it does not provide an absolute impossibility
proof across arbitrary future reorganizations.

## Durable state and compatibility

Recovery appends one authenticated `released` event containing either the
confirmed conflict proof or the exact ended-before-dispatch proof, plus the
original final-request digest.
The original signed evidence remains intact. The existing ledger mutex and
independent sequence serialize release against confirmation and late callbacks;
only one terminal transition can win. Status and final replay return `released`
without another signature, and the released operation no longer reserves its
input or consumes allowance. A new payment requires a new owner authorization.

Schema 8 prevents older readers from opening this changed lifecycle. The
migration changes only the schema version, preserving authenticated rows and
the independent policy sequence. Install the compatible Guardian before the
wallet deployment, preserve a stopped-service backup of both stores, and use
only binaries compatible with the current database schema for subsequent rollback.
Boarding conflict recovery adds schema 9 and its own authenticated conflict history. Never clear the
pending record or rewind the policy sequence manually.

Tests cover canonical and legacy payments, persisted final evidence across a
ledger restart, missing original inputs, ended-batch ordering, equal timestamp
ambiguity, shallow or changing confirmations, raw transaction substitution,
terminal races, replay, allowance release, and preservation of existing
authenticated records.
