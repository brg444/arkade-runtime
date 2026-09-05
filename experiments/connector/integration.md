# Savings connector integration

The accepted candidate makes ordinary Savings transfers depend on an enrolled
hardware input, the phone, and two online cosigners. At least one cosigner must
remain honest for the hardware requirement to hold against a compromised phone.
Compromise of the phone and both cosigner signing authorities permits a bypass.
Ordinary transfers require both services to be available.

The owner accepted this tradeoff on 2026-09-05. That decision supersedes the
strict hardware-enforcement gate in the original staged proposal; the reproduced
bypass remains a required test. Existing recovery-initiation dependence is
documented in [the feasibility report](README.md).

## Implemented transaction boundary

`internal/vault/connector` contains a transaction builder, the named candidate
program, and an immutable PSBT handoff. Production imports are prohibited by
`architecture_test.go`. No profile, enrollment, signing endpoint, Contract Pack,
wallet flow, or funded Savings tree selects this candidate.

The candidate name is `savings-connector-candidate-v0`. It is an experimental
program identity, not a released contract version. Both program-derived
cosigner keys commit the identical program; the normal tapscript requires the
phone and those two keys. The builder checks the exact leaf and its Merkle
proof against the independently pinned Savings script.

| Position | Input or output | Fixture value |
| --- | --- | ---: |
| Input 0 | Savings | 10,000 sats |
| Input 1 | Enrolled BIP86 connector | 1,000 sats |
| Output 0 | Registered Spending boarding script | 8,000 sats |
| Output 1 | Same Savings script | 760 sats |
| Output 2 | Same connector script | 1,000 sats |
| Output 3 | Existing P2A fee anchor | 240 sats |
| Output 4 | Canonical Emulator packet | 0 sats |
| Miner fee | Input total minus output total | 1,000 sats |

Savings pays both the miner fee and the anchor. In this example its debit is
9,240 sats; the hardware reserve stays at 1,000 sats. A future payment review
must include the anchor in the total cost. The program caps the miner fee and
feerate separately, commits the anchor's amount, and uses the exact final
witness size when checking feerate.

The first integration stage has exactly two inputs and five outputs and requires
at least 330 sats of Savings change. Multiple Savings inputs and complete
withdrawals need a separately tested output/count rule before wallet release.
Both input sequences signal replacement, while version 2 and locktime 0 are
fixed. A replacement requires fresh signatures over the complete transaction.

The connector uses one fixed enrolled address. Each transfer consumes a specific
outpoint and returns its full value to the same address. Deriving a new address
for each successor would introduce an additional identity-verification contract;
that is outside this candidate. A refill must use the same enrolled script and
still requires that hardware key to authorize its later consumption.

## Signing order and verification

1. Resolve both parent transactions independently and verify the selected
   amounts and scripts. Confirmations and current unspentness remain the chain
   verifier's responsibility; parent contents establish only the prevout data.
2. Build the entire transaction, including the Emulator packet, and retain an
   immutable snapshot. The PSBT includes full parents, witness UTXOs, the
   Savings leaf/proof, and BIP86 origin metadata for the connector and return.
3. The phone and both cosigners sign the exact Savings input with DEFAULT
   sighash. Each service must validate its pinned program and authenticated
   semantic operation before using a signing key. The tests execute the packet
   through the pinned parser and engine for both cosigner public keys.
4. Verify all three Savings signatures and finalize that input before exporting
   the hardware PSBT. This supplies a verifiable external input to devices that
   require one. It does not establish support on any particular device.
5. The hardware reviews the full transaction and signs its connector input with
   DEFAULT sighash. Its approval must display the registered boarding address
   accurately enough for the user to compare with an independently verified
   address. Amount and total cost review remain device qualification gates.
6. Import only the verified hardware signature into the retained transaction.
   Reject transaction mutations, conflicting prevout claims, non-DEFAULT
   signatures, script-path connector witnesses, and annexes. Retain the locally
   verified Savings witness regardless of returned foreign-input metadata.
7. Persist the exact signed transaction before broadcast, then reconcile its
   confirmation and successor outpoints through the existing wallet lifecycle.

Steps 1's live chain lookup, 3's service authentication and authorization, and 7's
persistence and broadcast are integration work remaining. The module builds and
verifies transactions without obtaining private keys or calling a signing service.
Its `Validate` function checks transaction rules; it is not a complete runtime
authorization operation.

Requiring the hardware signature before either cosigner signs would conflict
with devices that require a finalized external input for review. The chosen
order supplies Savings signatures first. Those signatures already commit the
hardware input, so they cannot be attached to a transaction with an attacker
input substituted afterward. The complete transaction cannot spend until its
hardware input has a valid signature.

## Wallet lifecycle to integrate

| Observed event | Required behavior |
| --- | --- |
| Confirmed unspent reserve discovered | Select it only when no unresolved operation already owns a connector |
| Transfer prepared | Persist exact inputs and candidate; show the amount awaiting approval |
| Any signature released | Retain the candidate and reconcile it across reload, timeout, and device disconnect |
| Hardware declines | Preserve the signed candidate's identity; no new outpoint selection based on a timeout |
| Broadcast response lost | Query and rebroadcast the same transaction; show processing while the outcome is unknown |
| Transfer confirms | Atomically advance Savings activity and the reserve to the actual successor outputs |
| Confirmed connector conflict | Mark the old candidate unusable and rediscover a same-key refill; retain the independently observed Savings balance |
| Hardware absent or lost | Keep normal transfers unavailable; expose only the enrolled recovery paths |
| Chain reorganizes | Reconcile the transaction and both reserve outpoints before showing availability |

Hardware replacement changes the committed Savings policy. The phone cannot
replace that identity in place. Existing vaults retain their current contracts;
migration requires an intentionally authorized spend into a separately enrolled
new contract. The full recovery family must be reconstructed and qualified for
the new Savings output before funding it. The candidate fixture's single normal
leaf is not a complete recoverable vault.

## Qualification and remaining work

The integration suite verifies the complete packet for both program-bound
cosigner roles, exact fee boundaries, pinned parents and leaf proofs, immutable
handoff, both partial and finalized hardware PSBT responses, and signature and
transaction mutations. All signing keys are disposable fixture keys. The origin
metadata uses illustrative derivations; actual hardware derivation and review
remain untested.

Bitcoin Core 28.1 rejects the fixture's 301-byte packet output under its default
83-byte data-output policy. With only `-datacarriersize=100000` changed, the suite
accepts and mines two successive complete connector transfers, verifies the
reserve remains 1,000 sats, and rejects stale transactions. That explicit test
setting matches the larger data-output limit documented in the
[Core 30.0 release notes](https://bitcoincore.org/en/releases/30.0/); it does not
claim qualification on a Core 30 binary or on the public broadcast service.

Reproduce with the pinned Go dependencies and an isolated Core binary:

```sh
CONNECTOR_BITCOIND=/absolute/path/to/bitcoind \
  go test ./experiments/connector -run '^TestConnector' -count=1 -v
```

The remaining release work is:

- qualify one hardware device with the complete packet, foreign Savings input,
  and all outputs, without disabling its safety checks;
- qualify the public Emulator's multi-input request, packet, fee policy, and
  exact signature response using disposable funds;
- define the complete new Savings/recovery family, versioned descriptor,
  matching wallet vectors, Recovery Kit, and explicit enrollment migration;
- implement the named authenticated runtime operation and wallet coordinator,
  including durable reconciliation, multiple deposits, complete withdrawal,
  conflicting reserve spends, and replacement;
- test the public broadcast path and funded lifecycle before enabling the
  candidate in a release.

Passing the local transaction tests closes the packet and PSBT construction
stage. It does not close device review, remote-service availability, recovery,
wallet integration, or deployment qualification.

Validation on 2026-09-05: `make check` passed module verification, build, vet,
and the full repository suite with Core enabled. The complete connector suite
also passed with `-race` and Core enabled. Pinned golangci-lint v2.13.1 reported
zero issues; documentation style and whitespace checks passed.
