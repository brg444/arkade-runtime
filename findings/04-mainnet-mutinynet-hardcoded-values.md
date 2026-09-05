# Mainnet Breakages: Network-Generic Paths Hard-Pinned to Mutinynet (One Fails Open)

## Severity

Release blocker — latent. No mainnet deployment exists, so these are not
current user-fund incidents (per `VALIDATION-2026-09-04.md`), but the wallet
ships mainnet pins and the server runtime explicitly accepts mainnet
(`internal/authorizer/runtime.go:121-131`).

## Status

Static analysis.

## Affected Code

Wallet:
- `src/lib/vault/vtxo/boardingRecovery.ts:108`
- `src/lib/vault/vtxo/board.ts:14` + `src/vault-wallet-service-worker.ts:84` (also tracked as VBW-002)
- `src/lib/vault/vtxo/script.ts:14` (`VAULT_POLICY_V1_PINNED_DELEGATE`)

Server (`/home/ubuntu/arkade-vault-server`):
- `internal/application/ready.go:81`
- `internal/application/vtxo.go:657-660`
- `internal/application/vault_board_operator.go:124`
- `internal/application/vault_board_finalize.go:88`
- `internal/policy/schema.go:109`
- `internal/policy/vault_board.go:780-781`
- `internal/application/vtxo_tree.go:159`

## Summary

### Wallet

1. **`boardingRecovery.ts:108` — `getNetwork(descriptor.network)` throws on
   mainnet.** `descriptor.network` is `'mainnet' | 'mutinynet'`, but SDK
   `getNetwork` only accepts `'bitcoin' | 'testnet' | 'signet' | 'mutinynet'
   | 'regtest'`. Line 95 of the same file does it correctly
   (`getNetwork(networkPins(status.network).sdkNetwork)`). On mainnet,
   boarding recovery **always throws**.

2. **`board.ts:14` — `BOARDING_EXIT_DELAY` pinned to mutinynet at module
   scope**, consumed by the service worker; wrong timelock for mainnet
   (604672 vs 7776256). See VBW-002 for the dynamically-confirmed version.

3. **`script.ts:14` — `VAULT_POLICY_V1_PINNED_DELEGATE`** hardcodes the
   mutinynet delegate pubkey at module scope while enforcement correctly uses
   per-network pins.

### Server

- (a) `ready.go:81` — readiness requires mutinynet batch expiry → mainnet
  `/ready` always fails.
- (b) `vtxo.go:657-660` — destination HRP must equal testnet HRP → every
  mainnet destination rejected.
- (c) `vault_board_operator.go:124` — operator origin must equal
  `MutinynetArkIndexerOrigin` → every mainnet operator POST fails.
- (d) `vault_board_finalize.go:88` — decodes `MutinynetCheckpointForfeitPubHex`
  → wrong forfeit key → mainnet boarding final rejected.
- (e) `schema.go:109` — DDL `CHECK (exit_delay = 604672)` → mainnet
  boarding-enrollment INSERT (7776256) violates the CHECK.
- (f) `vault_board.go:780-781` — cooperative window uses 604672 instead of
  7776256 → closes ~90 days early on mainnet.
- (g) **`vtxo_tree.go:159` — FAILS OPEN.** `defaultVtxoPkScript` uses the
  mutinynet exit delay, so `refuseDefaultVtxoChange` (`vtxo.go:180-182`)
  builds the wrong script on mainnet and the guard preventing vault-policy
  funds from going to the policy-free DefaultVtxo address is silently inert.

## Recommendation

Parameterize all sites on the resolved `deployment.Identity` /
`networkPins(network)`; add a mainnet-build static check failing on any
remaining `Mutinynet*` reference in network-generic code.
