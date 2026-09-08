# Rolling allowance using finalization receipts

8 September 2026. This proposed extension has an executable probe for receipt
signatures and maturity, while the deployed policy and fixed-budget draft
remain unchanged.

A possible replacement for Guardian's numerical allowance ledger keeps debit
and credit state in the controller, while Guardian issues a narrowly scoped
receipt after independently observing finalization. The emulator would verify
that receipt and permit its credit only after the rolling window has elapsed.
This retains trusted finalization and time evidence as a separate responsibility.

## Accounting rule

Current Guardian behavior reserves payment amount plus fees, retains signed
and submitted obligations while settlement is uncertain, and keeps completed
debits charged for 24 hours after finalization observation. Renewal fees follow
their own authenticated lifecycle and also consume allowance. A script
replacement must cover those fees and pending obligations along with payments.

`OP_CHECKTIMEVERIFY` can enforce a mature threshold, but an unsigned witness
timestamp can be arbitrarily old. A signed receipt supplies the missing
provenance only if its issuer has verified the claimed finalization. Candidate
receipt fields include a versioned domain, controller issuance identity,
unique debit sequence, actual transaction ID, debit amount, and observation
timestamp. Network and named program must be bound through the signed domain
or explicit fields.

The issuer must obtain finalization evidence from the authorized protocol
path, match the exact admitted transaction and economic outflow, and stamp its
own observation time. An issuance time after verified finalization is
conservative. Earlier signatures, elapsed reservation deadlines, and a
missing transaction lookup cannot establish finalization. The capability
should accept that semantic request and return a fixed receipt format;
arbitrary digest signing remains outside its scope.

## Candidate state transitions

1. **Payment.** The controller deducts actual outflow and commits a unique
   pending debit identity. Unknown settlement leaves that amount unavailable.
2. **Finalization acknowledgement.** A receipt must match the pending debit,
   amount, and accepted transaction ancestry. The controller records its
   authenticated maturity without increasing remaining allowance.
3. **Credit.** Once the maturity threshold passes, the controller removes that
   exact obligation and restores its amount once. Consumption must update
   authenticated controller state and preserve the budget ceiling.
4. **Renewal.** Every renewal preserves all allowance obligations. Any renewal
   fee creates its own debit or uses an explicitly equivalent shared rule.
   Principal-only renewal with a fee needs controller participation or another
   proven method of charging the same budget.

The fixed-budget draft's 20-byte state has no pending-debit or expiry history,
so it cannot implement these transitions unchanged. A bounded queue can refuse
new debits when full; that adds an availability limit requiring explicit
acceptance. A commitment with verified append, removal, and membership proofs
could support a larger history, while making proof availability and recovery
archives part of the contract. Neither representation is implemented.

Receipt identity must be checked against authenticated state and actual
transaction ancestry. Native checkpoint outpoints differ from logical VTXO
outpoints, so that binding must be qualified through both payment and intent
paths. A static expected digest in a primitive test cannot establish the
complete dynamic binding.

## Executed primitive probe

`TestSignedReceiptMaturityProbe` verifies a BIP340 signature over a fixed-format
receipt with `OP_CHECKSIGFROMSTACK`, matches its expected debit context, and
applies `OP_CHECKTIMEVERIFY` to the signed timestamp plus the window. It accepts
a mature authenticated receipt and rejects a recent receipt, a timestamp
altered after signing, a different signed debit, and an untrusted signer.

Guardian stores second-resolution timestamps and releases a completed debit
strictly after `observedAt + 86400`. The probe uses a threshold of
`observedAt + 86401` with the emulator's integer-second clock. Boundary
equivalence across the complete service clocks still needs qualification.

The probe assumes its signer told the truth about finalization. It does not
query settlement, consume a receipt, update allowance, or prevent replay on
its own. Those properties belong to the complete issuer and controller state
machine. Its script is separate from `Compile`, and no signing service or
production route exposes the probe.

## Remaining trust and lifecycle requirements

The emulator's key attests faithful script execution, while the receipt issuer
attests finalization and observation time. The Operator authenticates assets
and admission and enforces conflicting-spend rules. Removing arithmetic from
Guardian would preserve its authentication and lifecycle coordination duties
unless separately replaced by proven mechanisms.

A receipt can be replayed cryptographically, so the controller must make its
credit consumable only once. A delayed receipt can postpone restoration;
holding a mature credit transaction must never create a second credit from
the same controller lineage. Forked proposals, signed but unsubmitted
payments, lost responses, terminal retries, recovery, and offline renewal all
need end-to-end tests before this proposal can replace the current ledger.
