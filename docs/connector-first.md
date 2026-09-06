# Savings connector implementation and Guardian engine replacement

Accepted sequence, 2026-09-06: implement the onchain Savings connector against
the current Guardian stack first. Merge the Guardian's upstream engine
replacement separately after emulator PR 102 is merged and qualified. Fund
migration belongs to a later release step.

## Savings connector

Savings remains onchain. Its normal withdrawal spends one Savings UTXO and one
conventional signer-owned UTXO, returning the connector's full reserve to its
enrolled script. The owner may choose any supported Bitcoin payment address;
the enrolled Spending boarding address is one destination choice. Existing
Spending payment and rolling limits remain specific to Spending operations.
Savings retains its Bitcoin fee, anchor, change, and dust constraints.

The phone and both existing online cosigners sign the Savings input first. The
wallet verifies those signatures and finalizes that input before exporting the
PSBT. The independent signer reviews the actual recipient and signs its own
input with a signature committing to every output and preventing added inputs.
The wallet accepts only that verified signature into its retained transaction.

The current candidate supports P2WPKH and P2TR connectors. Qualification with
Electrum and Sparrow supplies evidence for conventional-input signing; no
physical hardware compatibility claim follows from software tests alone.
The existing packet and PSBT tests remain the implementation starting point.

Normal connector enforcement depends on at least one required online cosigner
remaining honest. Phone plus both online signing keys can deliberately bypass
the program and authorize another transaction. This accepted trust tradeoff
must remain visible in tests and documentation. Original recovery initiation,
pending, cancellation, quarantine, and claim paths remain the selected model.
The direct multisig/90-day proposal and native Savings contingency are inactive.

## Guardian engine replacement

PR 102 provides an engine embedded inside the Guardian, replacing its forked
execution and signing implementation. Guardian authentication, named-program
authorization, scoped key derivation, policy state, and durable transaction
coordination remain Vault responsibilities. The Operator retains its existing
protocol role; this replacement does not relocate Guardian authority to it or
change separately committed cosigner identities.

The engine replacement must preserve the contracts supported at its merge,
including connector withdrawals if they have shipped. The connector's inputs,
program packet, signature ordering, recovery, and adversarial fixtures become
regression requirements for that later refactor. No connector implementation
dependency points to the unmerged library.

## Implementation stages

1. Add scoped support for the exact two-input connector transaction in the
   current signing stack. Validate both parents, the enrolled program, phone
   signature, immutable transaction, and expected cosigner signature delta.
   Keep existing single-input recovery validation intact.
2. Implement wallet persistence for the complete candidate and verified signing
   stages. Restore the same candidate across reload or a lost response. Persist
   before asking any service to sign, and persist the final raw transaction
   before broadcast. A timeout supplies no evidence that a signature was not
   issued or an input was released.
3. Bind the new contract and connector origin through enrollment, descriptor,
   local pin, Recovery Kit, authenticated named authorization, and authoritative
   replay protection. Integrate the payment UI only after those boundaries are
   complete. Existing enrollments retain their original contract interpretation.
4. Qualify full normal and recovery flows, signer handoff, confirmation,
   conflicting reserve spends, replacement, and interrupted operations. Include
   multiple deposits even while each transaction selects one Savings input.
   Keep release activation separate from local implementation tests.

Source branches must include reviewed current main before merge, including
Light and schema-2 compatibility. Explicit fetches in these checkouts can
update FETCH_HEAD without moving origin/main; inspect the actual fetched commit.
The latest inspected heads are runtime 15a83fb and wallet 5c57b14.

## Implemented increment

The scoped Guardian helper reconstructs the connector program and signing
authorities from enrolled values, verifies both parents and the Savings
Taproot commitment, and adds one Guardian signature to the retained candidate.
Existing single-input signing and recovery checks retain their original scope.
The helper has no HTTP, profile, or key-capability caller yet.

The wallet store persists and reconstructs the complete candidate under a
required per-vault Web Lock. Every mutation binds to its transaction identity;
queued arguments are copied before waiting for the lock. Reload verifies the
independent enrollment pin, complete candidate PSBT, saved Savings signatures,
and any final transaction. Cancellation is available only before signatures
may have issued. A signed operation remains reserved until the future
reconciliation layer resolves it.

Enrollment and Recovery Kit versioning, authenticated ledger authorization,
the remote cosigner stage, chain reconciliation, and payment screens remain
unimplemented integration stages. Local persistence provides wallet consistency;
authoritative replay protection belongs to the server ledger.

## Review boundary

Muse Spark leads implementation through OpenCode. Codex owns architecture and
independent patch review. The first increment is reviewable signing and
persistence support, with no automatic enrollment activation, service restart,
fund movement, or migration. Approval of the design does not establish remote
service admission or funded qualification.

Keep exact input ownership after a signing request may have run. A signed
candidate remains pending until independently observed transaction evidence
resolves it; neither a UI cancellation nor expiry of a local timer releases its
inputs. Signed-transaction reconciliation and balance presentation must avoid
double counting or presenting reserved Savings as money already sent.

## Sources

- [Connector transaction and handoff](../internal/vault/connector/handoff.go)
- [Connector family and recovery construction](../internal/vault/connector/family.go)
- [Existing local Guardian signer](../internal/application/signer.go)
- [Existing signature response verification](../internal/application/psbtguard.go)
- [Emulator PR 102](https://github.com/arkade-os/emulator/pull/102)
