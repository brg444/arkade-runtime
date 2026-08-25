# Mainnet POC readiness checklist

This is a preparation checklist only. The audited Runtime at
`36cde909cc2ed745fef3efd4ecafc4371cfd8298` is Mutinynet-only. Completing this
document does not authorize mainnet deployment, choose mainnet policy values,
or claim hardware isolation.

## Release identity

- [ ] A reviewed source revision explicitly supports mainnet; no operator or
      environment flag can select unreviewed policy.
- [ ] The build uses the reviewed Go toolchain, locked modules, reviewed
      Emulator dependency, digest-pinned bases, and a clean source tree.
- [ ] The private Emulator module replacement has been removed after its checks
      land in a reviewed official release.
- [ ] The server repository has an explicit distribution license.
- [ ] CI, vulnerability review, SBOM/provenance, image signing, immutable image
      digest, and deployment readback are recorded for the exact candidate.
- [ ] Server and wallet Contract Packs are regenerated from approved values,
      byte-identical, and digest-pinned.

## Network and external services

- [ ] Mainnet network identity, Operator origin and signing keys, Emulator
      origin and signing key, checkpoint closure, exit delays, fee policy, and
      rotation procedure are reviewed and compiled.
- [ ] The stock public Arkade Operator and official SDK interfaces are sufficient;
      no private Operator API or `arkd` change is assumed.
- [ ] Redirect, timeout, response-bound, identity-drift, resolver-failure, and
      Operator-availability drills pass from the intended deployment regions.
- [ ] VTXO send, ambiguous submission recovery, checkpoint exchange,
      finalization, and SDK-owned state reload pass without Vault-specific SDK
      forks.
- [ ] Boarding cancellation/retry behavior and the phone-plus-Operator trust
      window have an explicit acceptance or redesign decision.
- [ ] Package-native Lightning send remains gated behind ordinary Spending,
      swap, refund, and live qualification; Lightning receive remains separate.

## Keys, passkeys, and edge

- [ ] VaultCosigner generation, custody, recovery, recipient access, and
      destruction procedures are approved for the POC. A file-backed software
      key is not described as hardware-isolated.
- [ ] Gateway secret injection/stripping, TLS, exact Origin, RP ID, WebAuthn
      ceremony behavior, shared rate limits, and supported browser/platform
      boundaries are verified at the real edge.
- [ ] Enrollment invitation creation, expiry, one-time use, rotation, and audit
      procedure pass without exposing tokens.
- [ ] Passkey PRF, phone, hardware-wallet, recovery, and multi-device flows pass
      on every supported platform with the existing KDF and script domains.
- [ ] Logs, traces, crash reports, shell history, and platform support access are
      shown not to contain keys, gateway headers, enrollment tokens, passkey
      material, PSBTs, or Recovery Kit payloads.

## Persistence and recovery

- [ ] SQLite and the policy sequence use approved durable paths, restrictive
      ownership/modes, capacity alerts, and one coherent state-unit procedure.
- [ ] An external recovery evidence system records each accepted manifest
      digest and policy-sequence high-water mark outside the restore unit.
- [ ] Snapshot, offsite copy, retention, restore approval, and deletion
      procedures have named owners and recovery-time/recovery-point objectives.
- [ ] A fresh disposable environment passes matched restore, mismatched
      database, mismatched/missing sequence, modified-row, wrong-key, and exact-
      image rollback drills.
- [ ] A restore never treats a matched rollback of both artifacts as detectable;
      the external high-water record and approval process close that gap.
- [ ] Load tests establish a supported authenticated-history bound and alert
      threshold before the ledger's linear verification cost becomes unsafe.

## Product qualification and authorization

- [ ] Mainnet Vault Program and allowance values have a separate reviewed
      decision. Mutinynet values are not copied by default.
- [ ] Savings, recovery, Spending, VTXO change, boarding, and Recovery Kit
      vectors pass against the exact server and wallet candidates.
- [ ] No existing Mutinynet database, key, invitation, vault identifier,
      allowance, operation, or Contract Pack is migrated into the POC.
- [ ] The POC fund limit, operators, users, incident authority, stop conditions,
      and unilateral recovery exercise are approved before any funding.
- [ ] Arkade Runtime remains under the `brg444` repository boundary.
      `ArkLabsHQ/enclave` is an external future deployment host and no Enclave
      work or attestation claim is implied by this checklist.
- [ ] Vault Board v2 and any second cosigner profile have their own design and
      release decisions; this POC does not infer them from `arkade-vault-v1`.
