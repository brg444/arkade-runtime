# 10 sat/vB Feerate Cap Unenforced Off-Chain; Only the L1 Covenant Enforces It

## Severity

Medium

## Status

Static analysis. `assertTransitionFee` is dead code (no callers).

## Affected Code

- `src/lib/vault/program/spend.ts:40-44` — `requireFee` (absolute cap only)
- `src/lib/vault/program/spend.ts:257-261` — `assertTransitionFee` (feerate cap, uncalled)
- `/home/ubuntu/arkade-vault-server/internal/application/transition.go:42-144` — `SignTransition` (no fee validation)
- On-chain enforcers that DO agree: `src/lib/vault/program/script.ts:246-259` ≡ `internal/vault/savings/transition.go:158-177`

## Summary

Documented fee policy: "5000 sats absolute, 10 sat/vB feerate".

- **Absolute 5000-sat cap**: enforced by the wallet (`requireFee`) on
  transitions/claims/guardian-exits, and by the on-chain covenant.
- **10 sat/vB feerate cap**: enforced ONLY by the L1 covenant introspection
  script. The wallet's `assertTransitionFee` exists but has no callers; the
  server performs no fee validation in `SignTransition`.
- **Claim/guardian-exit paths**: no covenant at all, absolute cap only.
- **Savings handoff**: no fee cap (`savingsSpend.ts:43-44`).

A transition built (e.g., via `kitCli.ts:129,191`) with fee ≤ 5000 but
> 10 sat/vB × vbytes is cosigned by wallet + server and then **rejected by the
on-chain covenant** — a stuck transaction; the only remedy,
`bumpTransitionFee` (`spend.ts:222-230`), only increases fees.

## Recommendation

Wire `assertTransitionFee` into transition build/sign on both sides (vsize
from the finalized tx); add the same check server-side in `SignTransition`.
