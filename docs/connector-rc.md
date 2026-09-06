# Savings connector RC qualification

The RC candidate must complete a Savings withdrawal using a conventional
software signer, preserve its outcome across interruption, and retain the
original recovery paths. The separate Guardian engine replacement is outside
this release. Existing funded vaults keep their enrolled contract.

## Contract and persistence

New enrollment commits the connector type, compressed public key, fingerprint,
derivation path, reserve script, complete Savings/recovery family, and selected
Spending policy. The wallet reconstructs those values before accepting the
server descriptor. The Recovery Kit and passkey recovery binding preserve the
same identity on a fresh device. Changing an existing hardware identity
requires a separately authorized fund migration.

Old descriptors, enrollment pins, credential envelopes, and Recovery Kits must
remain valid for their original template. Database migration preserves existing
row MACs and the independent policy sequence. Upgrade testing starts with a
populated schema-2 database containing both original Savings and Light state;
empty-database initialization alone does not qualify the migration.

## Withdrawal and interruption

| Scenario | Required outcome |
| --- | --- |
| Standard or Advanced enrollment, either connector type | Client and Guardian reconstruct the same contract and recovery scripts |
| Unrelated Bitcoin recipient or Spending boarding destination | Exact recipient and amount survive every signing stage |
| Multiple Savings deposits | Select one sufficient confirmed Savings input; show the spendable amount without promising aggregation |
| Missing, unconfirmed, or spent reserve | Explain the funding or confirmation requirement before requesting signatures |
| Partial or complete withdrawal | Return the full reserve and any valid Savings change; account for fee and anchor separately |
| Lost authorization response or Guardian restart | Resume the same durable operation and signing result |
| Wallet reload or another tab opens | Restore the same transaction and retain both reserved inputs |
| Signer declines, disconnects, or returns malformed data | Keep any potentially signed candidate and reject changed inputs, outputs, or weak signatures |
| Lost broadcast response | Reconcile or rebroadcast the same raw transaction |
| Confirmation | Replace pending activity once and discover actual successor outputs |
| Unconfirmed conflicting spend | Retain uncertainty and prevent a fresh competing authorization |
| Confirmed conflicting spend | Verify the conflict onchain before resolving the old reservation |
| Reorganization | Revalidate outcome evidence and outpoints before permitting reuse |

The Guardian authorizes only the named connector operation after verifying the
enrolled program, exact candidate, both parent transactions, and independently
observed chain state. Durable authorization and sequence advancement precede
signature dispatch, with both inputs retained until independently observed
transaction evidence resolves the operation. Spending's per-payment and rolling
allowance remain specific to Spending operations.

## Signer and recovery qualification

Electrum and Sparrow must receive a PSBT with finalized Savings, display the
actual recipient, and return a valid signature for their conventional input.
The imported signature must commit every output and prevent added inputs.
Automated component tests and any desktop interaction are reported separately;
software qualification does not establish hardware compatibility.

Standard and Advanced recovery initiation, pending claims, clawback, and
quarantine reconstruction must work for the connector family. Conventional
connector-input signing does not establish support for directly signing custom
recovery scripts. Recovery instructions must identify the applicable signer
requirements and preserve the existing phone-assisted recovery route.

The phone-plus-both-online-cosigners bypass remains a required counterexample.
Normal connector enforcement assumes at least one honest required online
cosigner, while Bitcoin verifies the completed transaction's signatures.

## Deployment gates

Full runtime tests, race tests, lint, dependency scan, image builds, wallet unit
and browser tests, typecheck, formatting, and both network builds must pass.
The compiled mainnet build must reject Mutinynet policy before requesting a
passkey. Run heavy Bitcoin Core suites serially to avoid mining RPC contention.

Qualification must exercise the current emulator request and response boundary,
onchain acceptance, successive reserve reuse, and the interrupted operations
above with disposable keys. A Core test with a larger data-output setting does
not establish acceptance by the production broadcast path. Record exact source
heads, dependency and Contract Pack identities, schema version, service pins,
and any remaining external qualification before calling the candidate ready.

RC deployment preparation includes verified migration and rollback instructions.
A Guardian restart requires the operator's existing interactive unlock
procedure. Deployment and funded-wallet migration are separate actions from
preparing this candidate.

## Current qualification evidence

On September 6, the connector protocol tests accepted and mined the complete
packet and two successive withdrawals under Bitcoin Core 30.3's default relay
policy, verifying the 1,000-sat reserve successor each time. A separate test
retains an explicit larger data-output setting for older nodes. The 30.3 binary matched the official
[30.3 release checksums](https://bitcoincore.org/bin/bitcoin-core-30.3/SHA256SUMS).
Production broadcast acceptance remains a separate deployment check.

The wallet's [emulator HTTP qualification](https://github.com/brg444/vaulted-bitcoin-wallet/blob/codex/hardware-connector-rc/tools/connector-signers/EMULATOR.md)
passes twelve cases against the upstream v0.0.7 gateway, handler, interpreter,
and signer with disposable keys. This test found the wallet's dropped PSBT
parent fields; the corrected builder preserves those fields through creation
and handoff. Local source qualification supplies no attestation of the live
service's code or deployment configuration.

The wallet store now retains an immutable phone-signed PSBT for authorization retries.
Signing the same transaction again can produce a different valid Schnorr
signature, so reconstructing and signing again does not provide a byte-identical
retry. Restore tests verify the saved signature and complete parent and origin
metadata against the independently rebuilt candidate before reusing it.

The public readiness checks on September 6 reported a healthy mainnet Guardian
using schema 2 and the original Savings template. The RC app's release manifest
also reported mainnet. These read-only checks describe the deployment baseline;
the connector changes have not been deployed.
