# Arkade Runtime contributor guide

This repository builds Arkade Runtime and its first compiled profile,
`arkade-vault-v1`, using released Arkade protocol libraries and stock public
Operator interfaces.
`arkd` remains outside the repository's ownership and change scope. The
official Arkade SDK owns wallet-side transaction coordination.

## Where things live

- `cmd/authorizer` starts the one production process.
- `internal/authorizer` composes configuration, persistence, keys, external
  ports, the profile, and the HTTP server.
- `internal/application` owns the current enrollment, Savings, Spending,
  boarding, recovery, HTTP, and readiness workflows.
- `internal/profile/arkadevaultv1` declares the compiled profile and its
  persistence capabilities.
- `internal/runtime` validates immutable profile, module, program, policy,
  route, store, and key-scope identifiers.
- `internal/policy` is the authenticated SQLite ledger and policy sequence.
- `internal/program` contains canonical program and Spending-policy values.
- `internal/ports` contains the narrow `ArkResolver` and Emulator-compatible
  `Signer` interfaces. Boarding chain and Operator interfaces currently remain
  private to `internal/application`.
- `internal/vault/savings` constructs and verifies the Savings covenant.
- `internal/webauthn` parses and verifies passkey material.
- `internal/iface/http` is currently a thin composition shim. HTTP handlers
  still live in `internal/application/http*.go`.
- `fixture` is public test data only. Production rejects fixture identities.
- `contract-pack.json` is the wallet/server compatibility contract.
- `docs`, `deploy`, `Dockerfile.*`, and `railway.json` describe release and
  deployment behavior.

## Commands

- `make check` verifies modules, builds, vets, and runs the full test suite.
- `make race` runs the full race suite.
- `make lint` runs the pinned golangci-lint release.
- `make vuln` runs the pinned vulnerability scanner.
- `make images` builds both images and checks persistent-volume ownership.
- `make bench` runs policy benchmarks.
- `make ci` runs the complete local equivalent of GitHub CI.

Use Go 1.26.6. Run focused package tests while editing, then the relevant full
gate before pushing. A missing local Docker daemon is not a successful image
gate; GitHub's image job must pass instead.

## Frozen compatibility and security boundaries

Refactor PRs preserve all of the following:

- HTTP routes, methods, status codes, error codes, or JSON field shapes;
- `contract-pack.json`, its embedded hash, deployment pins, or SDK assumptions;
- schema DDL, canonical MAC preimages, HKDF inputs, digest domains, CBOR/DER
  encodings, PSBT canonicalization, or checked-in vectors and goldens;
- signing thresholds, keys, scripts, output order, timelocks, fee semantics,
  allowance semantics, lifecycle transitions, or recovery behavior;
- the single SQLite connection, the ledger mutex, MAC-before-use ordering, or
  the policy-sequence write and fsync ordering;
- passkey, PRF, cross-device recovery, or sign-count behavior;
- the pinned public Operator, indexer, Esplora, and Emulator trust boundaries.

If one of these must change, stop treating the work as a refactor. Isolate the
behavior change, add adversarial and compatibility tests, and review it as a
separate security-sensitive PR.

## Deliberate constraints

- Policy rows are MAC-verified before their state or time is trusted. SQL
  state/time filters are excluded because they could hide a tampered row.
- `SetMaxOpenConns(1)` and the mutex on each `policy.Ledger` preserve
  transaction, allowance, and sequence ordering. The production process owns
  one ledger instance.
- Economic mutations advance the independent policy sequence synchronously.
- Key capabilities accept semantic operations, not arbitrary digests or PSBTs.
- Enrollment, boarding, Spending, and recovery are one immutable named
  profile, not dynamically loaded plugins.
- The wallet owns transaction coordination through the official Arkade SDK;
  this server independently verifies and authorizes the named Vault Program.

## Test fixtures

Common application fixtures include `newEnv`, `vtxoTestEnv`,
`newSDKSpendFixture`, `newVaultBoardProofFixture`,
`newVaultBoardFinalFixture`, `newRecoveryEnv`, `signedReserveRequest`,
`passkeySessionAssertion`, `pendingProofForInputs`, `boundaryHTTPCall`, and
`testAuthorizer`. Add shared setup to the closest fixture; new tests avoid
copying a complete workflow setup.

Golden and vector changes require a reviewed behavior or contract change.
Expected digests remain fixed throughout refactor work.
