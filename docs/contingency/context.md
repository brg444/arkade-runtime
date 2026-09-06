# Contingency evidence inventory

Snapshot: 2026-09-05. This is a source-derived architecture review and implementation plan, not a security scan or a completed recovery qualification.

Runtime main is `a70823a28b596195e033c4c25e48d8d82e22a72d`; wallet main is `53c597393c68374afaec06108a8f803f24d7de6e`. Both preparation worktrees started at those fetched revisions, with upstream source and parallel candidate branches retained as evidence outside this implementation.

## Immutable source evidence

The collection digest is SHA-256 of UTF-8 JSON for `sourceArtifacts` in `hardening.json`, with sorted object keys, separators `,` and `:`, and the listed array order. Each artifact digest covers `git show <revision>:<path>` bytes, excluding the working tree.

Collection SHA-256: `d6580b5df69b98178722fde15fd6c9a6c7f017968e28cc26fb221734bce6bc0c`.

| Evidence and title | Repository and revision | Source | SHA-256 |
| --- | --- | --- | --- |
| `savings`: Existing Savings authority | `brg444/arkade-runtime@a70823a28b596195e033c4c25e48d8d82e22a72d` | `internal/vault/savings/family.go` | `3e5f0494812727dd50be859d95a91123dd363227fb240dba0267bd3b3eec6a86` |
| `savings`: Existing Savings authority | `brg444/arkade-runtime@a70823a28b596195e033c4c25e48d8d82e22a72d` | `internal/vault/savings/trees.go` | `61b496eec169059e74ea6dfeada9777855c49ee464e5434c0c5fd5794418356f` |
| `savings`: Existing Savings authority | `brg444/arkade-runtime@a70823a28b596195e033c4c25e48d8d82e22a72d` | `internal/program/pins.go` | `7d2d55ec09c007cf8e42f2ced6e2af98b42bd419f0bb6ad9799913dc9980bfea` |
| `savings`: Existing Savings authority | `brg444/arkade-runtime@a70823a28b596195e033c4c25e48d8d82e22a72d` | `internal/program/program.go` | `4a5e66106ffc0aa96f1e3751df3e45e9d2ef689ff467d015df30385d0ba61123` |
| `admission`: Native input admission | `arkade-os/emulator@4feb9eaa81b49f8d321407e92dba107ec9ba5158` | `internal/application/onchain.go` | `5288a575c392cf93f30c99bfc4ffd70527e4c2de0cd7412eab47daeccc44cd6a` |
| `admission`: Native input admission | `arkade-os/emulator@4feb9eaa81b49f8d321407e92dba107ec9ba5158` | `internal/application/tx.go` | `cd2163c9aa6a4fb51176199a09c9e45c333df602e2d48657ef9a742bd3d7877f` |
| `admission`: Native input admission | `arkade-os/emulator@4feb9eaa81b49f8d321407e92dba107ec9ba5158` | `internal/application/prevout.go` | `548443a33fac133a97045bb52c42b5b0bc189562db7093e0a9219a12def03119` |
| `admission`: Backing VTXO admission | `arkade-os/arkd@f863e484719344edbe4a8d10cf5fe994b123f2c0` | `internal/core/application/service.go` | `530d53ab00abadae3e0e95319da5a5520e625a6cf88623501816a846ddbee72b` |
| `admission`: Backing VTXO admission | `arkade-os/arkd@f863e484719344edbe4a8d10cf5fe994b123f2c0` | `pkg/ark-lib/offchain/tx.go` | `156acb3dc47fe1ad798dc00e8decfa64bce7ec5d88cd65ad58fd5b93d53aa272` |
| `connector`: Hardware omission counterexamples | `brg444/arkade-runtime@9630b75dbe52ead1f99a4d634d82118ca8864b6c` | `experiments/connector/README.md` | `401eab12240afae7ae28772907d55d0c2a197c777f5d9cb8eaa40c7ec198ee9f` |
| `connector`: Hardware omission counterexamples | `brg444/arkade-runtime@9630b75dbe52ead1f99a4d634d82118ca8864b6c` | `experiments/connector/connector_test.go` | `4ab4fc3ac0706061d039466cc59481f54b7d6d8ebb8f55712a7b754a4b0fdcfb` |
| `light`: Native recovery archive | `brg444/vaulted-bitcoin-wallet@ab6c0e2e32101d21e1830166c482b02b68dcd96e` | `src/lib/vault/light/recovery.ts` | `2398646865ece61a061b30ef1f45935f792d42c373d6252254d27ab5651f53e1` |
| `light`: Native recovery archive | `brg444/vaulted-bitcoin-wallet@ab6c0e2e32101d21e1830166c482b02b68dcd96e` | `src/lib/vault/light/recoveryArchive.ts` | `93789b45b647777917c4379dbd01c80cfc3b3dec2bf34c1611afc453425caaa0` |

## Evidence limits

The user requires Operator-compatible cooperative operations and a retained timelocked recovery plan. The implementation direction remains provisional until admission, hardware behavior, and full recovery pass independently. Existing acceptance of an honest-cosigner L1 connector is a distinct trust outcome from mandatory hardware under compromise of every online signing key.

The connector task confirmed that no native Savings implementation exists in its candidate. Its consensus counterexamples and conventional-input signer qualification are reported evidence supported by inspected tests; this planning task did not rerun those experiments.

The Light task reported green CI, a confirmed generated-contract Mutinynet exit, and a confirmed recovery after enrollment, payment, and renewal. The final sweep reportedly recovered 39,702 sats at Mutinynet block 3402489, with only Bitcoin explorer access and the Vault service stopped. That report does not qualify native Savings. Private funded-test artifacts and their secrets are excluded from this collection. Source paths and source revisions are sufficient to locate reusable implementations.

[BIP 68](https://bips.dev/68/) and [BIP 112](https://bips.dev/112/) were read as consensus references. They are supplementary specifications outside the hashed source collection. Current service admission, mainnet device qualification, candidate delays, and full native Savings recovery remain unverified. Deployment alignment must be rechecked against live release manifests before release.

## Reconciliation update, 2026-09-06

[Connector reconciliation](connector-reconciliation.md) records the combined work
order and current branch drift. The source collection and its hashes above
remain the original immutable snapshot; `sourceDrift: none` in `hardening.json`
describes that inspection, not continuing alignment with main or live RC.
