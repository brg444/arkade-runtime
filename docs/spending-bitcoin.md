# Spending to Bitcoin

Spending payments to Bitcoin use `/v1/vtxo/bitcoin/{info,prepare,register,final,status,release}`.
Signer setup is a wallet preset: it derives the enrolled signer address and
requests the missing exact-value outputs through the same payment coordinator,
Review screen, policy ledger, pending display, and recovery capture.

The first version supports one live Spending input, one or two ordered Bitcoin
outputs, and at least 330 sats of protected Spending change. Standard P2PKH,
P2SH, P2WPKH, P2WSH, and P2TR destinations are accepted with dust checks. Two
identical outputs remain distinct; combining them would break signer setup.
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

## Pending operations and compatibility

The original `savings-setup-v1` plans, signed requests, digest domains, event
bytes, and MACs remain valid. Legacy phase URLs reach the same lifecycle code;
the legacy prepare decoder retains its enrolled-signer restrictions. The
canonical prepare route accepts explicit output plans under new prepare/plan
digest phases and persists `spending-bitcoin-v1` operations. Old reserve fields
in the shared wire plan must be empty for these new operations.

Schema 8 extends the reader fence while preserving pending rows and the
independent policy sequence. The database rejects binaries that support only schema 7 or earlier at startup.
The browser retains the historical journal key and event name so existing
reservations, cross-tab observers, and recovery capture remain coordinated.
The journal parser binds any new output plan back to its saved owner-signed
prepare request; changing displayed destinations and recomputing a plan hash
cannot change that authority.

A lost final response remains uncertain. Expiry, an ended batch, or an unspent
input alone cannot release a potentially escaped signature. A separate conflict recovery path can release the reservation after the
Guardian verifies that another Bitcoin transaction has spent an input of the
exact retained commitment, with at least six confirmations. See
[Bitcoin conflict recovery](bitcoin-conflict-recovery.md) for its proof and
chain-authority requirements. Pre-final cancellation still needs
the retained owner deletion proof and the existing release conditions.

After confirmation, the wallet retains the operation until the exact
replacement Spending exit is in its durable recovery file. A stale recovery
snapshot cannot make the new change spendable by discarding its journal.

## Qualification and rollout

Tests cover destination and amount substitution, duplicate outputs, protected
change, limits, owner-request replay, lost final responses, legacy record
preservation, and an actual SDK intent checked by the Go verifier. Browser
coverage exercises the shared review and pending presentation without moving
mainnet funds.

On 2026-09-08, a fresh Standard Mutinynet vault used the canonical Bitcoin route
to fund two separate 500-sat signer outputs from one 10,000-sat Spending input.
The shared Review required one confirmation. The zero-fee batch returned 9,000
sats to the enrolled Spending script and confirmed at height 3,409,624:

- Commitment: `220f77d12b42907313da5e58e7a81e20421d5ab6808e0d4258b60bb9fef11862`
- Spending change: `1f5a6fd5b71369e696e9ef5beeb719b0408f71d8925bf0fbec976cea9b5fe99d:0`

The browser verified the exact change in its durable recovery file and retained
completed signer setup after reload and sign-in following a test Guardian
restart. That file then produced a validated,
fully signed unilateral exit with Guardian and Operator network calls disabled.
The exit remained unbroadcast; timelock maturity, fee funding, and the final
Bitcoin recovery spend remain outside this drill. Single-recipient payments,
Advanced policy, and nonzero fees have local verifier and wallet coverage;
the funded drill covers the Standard two-output route.

Fresh funded drills generate a fresh disposable signer identity so approval
outputs left by earlier tests cannot silently skip the payment. Private test
keys and signed recovery artifacts remain outside the repositories.

Deploy the schema-8 Guardian before assigning the matching wallet to RC. A
Guardian restart requires a live operator unlock because its plaintext signing
key is removed after load. Preserve the existing mainnet pending operation
through deployment.
