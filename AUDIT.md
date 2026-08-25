# Arkade Vault Server — Full Code Audit

- **Commit audited:** `8cb9aaf` ("Arkade Vault Server v2"), branch `main`
- **Date:** 2026-08-25
- **Scope:** entire repository — ~13,900 lines of production Go across `cmd/`,
  `internal/{authorizer,application,policy,vault,webauthn,deployment,iface,program,contractpack,apperr,ports}`,
  plus Dockerfiles, Compose, Railway entrypoint, CI workflow, and docs.
- **Method:** manual line-by-line review of every production source file with a
  custody-signing threat model (signing-policy bypass, tenant isolation,
  ledger rollback, transaction-verification defects, secret exposure — the
  classes named in SECURITY.md), plus `go test ./...`, `go test -race`,
  `go vet`, and `staticcheck`. `govulncheck` could not fetch vuln.go.dev
  through this environment's egress proxy and should be run in CI instead.

## Executive summary

This is an unusually defensively written codebase for its maturity stage. The
core custody invariants hold up under review:

- **No signing-policy bypass was found.** Every VaultCosigner signature is
  produced only after the complete transaction is validated field-by-field
  against a MAC-authenticated, durably reserved operation, and the signing
  wrappers enforce a strict "exactly one expected signature added, nothing
  else mutated" delta invariant (`signExactArkStage`,
  `extractVerifiedSignerSig`, `requireOnlyVaultSignatureAdded`).
- **Savings transitions are covenant-bound, not just policy-bound.** The
  Arkade transition script pins output count (exactly 3), destination script,
  P2A anchor value, fee ceiling, and feerate (via `OP_TXWEIGHT`), and the
  cosigner signing key is tweaked by that script's hash
  (`internal/vault/savings/transition.go`), so the application-layer
  destination checks in `resolveTransitionBinding` are belt on top of
  suspenders. Value siphoning through extra outputs is structurally blocked.
- **Tenant isolation, invite consumption, and anti-rollback are sound.**
  Vault IDs are 128-bit random; invites are consumed by compare-and-swap in
  the same transaction that creates the vault; every persisted row is
  HMAC-authenticated with domain separation; and an external MAC'd monotonic
  sequence makes a rolled-back database fail closed at startup and at every
  reservation.
- The custom WebAuthn stack (assertion + create ceremony + minimal CBOR +
  strict DER) is correctly strict: UV+UP required, exact origin/RP-ID/type
  binding, challenge equality, low-S enforcement, sign-count regression
  checks, PRF-material rejection.

**All tests pass** (including `-race` on the core packages), `go vet` is
clean, and staticcheck reports only style nits and Go 1.26 deprecation
notices. No critical or high-severity vulnerability was identified.

The findings below are medium/low hardening, robustness, and availability
items — the most important being a **permanent wedge of the recovery signing
path after a single failed cosign attempt (M1)** and an **unbounded-memory
rate-limiter map reachable with arbitrary vault IDs (M2)**.

| ID | Severity | Finding |
| --- | --- | --- |
| M1 | Medium (availability, recovery path) | A failed or crashed transition cosign permanently wedges that recovery outpoint (`ErrRecoveryBusy` forever) |
| M2 | Medium (DoS) | Transition rate limiter grows without bound for arbitrary, never-validated vault IDs; package-global state |
| M3 | Medium (fail-open pattern) | `AdvanceSignCount` silently no-ops if the `webauthn_sign_count` table is missing |
| L1 | Low | `vaultMapMAC` and `signCountMAC` concatenate variable-length fields without length prefixes |
| L2 | Low | CBOR decoder accepts duplicate map keys and non-minimal length encodings |
| L3 | Low | Public error filtering is a substring blocklist; JSON decode errors bypass it |
| L4 | Low | Client-controlled `X-Request-Id` echoed/logged without length cap |
| L5 | Low (efficiency) | Exact-fee search is O(feeCap × input-count) CEL evaluations per reservation |
| L6 | Low | Secret scalar material passes through non-zeroizable `big.Int` |
| L7 | Low | Assertion-forging test helpers (`Synth`, `SignDigestLowS`) exported from the production `webauthn` package; `parseDeploymentPub` dead in production |
| L8 | Low | `matchReservedOutpoint` matches txids in both byte orders |
| I1–I9 | Info | Operational and dependency observations (below) |

---

## Medium-severity findings

### M1 — A failed transition cosign permanently wedges that recovery outpoint

**Location:** `internal/application/transition.go:94–146`,
`internal/policy/session.go:109–134` (`DecideReplay`)

`SignTransition` writes an **unsigned** `recovery_session` row
(`ApplyRecoveryReplay` with empty `Signature`) *before* signing, then signs
with the local VaultCosigner and then the **remote** ArkadeCosigner (a network
call to the public emulator with a 15s+ timeout), and only afterwards writes
the signed row. If the remote signing stage fails — emulator outage, network
error, process crash or restart mid-flight — the unsigned row persists, and
there is no TTL, lease, or cleanup path anywhere in the codebase
(`recovery_session` rows are never deleted, and `DecideReplay` returns
`ErrRecoveryBusy` whenever both the stored row and the incoming request are
unsigned — which is every client-driven retry).

**Impact:** the `initiate`/`clawback` signing path for that
`(vault, outpoint, purpose)` returns HTTP 429 forever. This is the
guardian-delay *safety* path — precisely the flow a user needs when a key is
lost or stolen. The phone+hardware 2-of-2 admin leaf remains as an escape
hatch, but it requires both keys, which is the situation recovery exists to
avoid. Recovery requires manual database surgery.

**Recommendation:** any of:
- clear the unsigned row (or mark it reclaimable) when `SignTransition`
  returns an error after the first `ApplyRecoveryReplay`;
- add an `updated_at`-based lease: treat an unsigned row older than a few
  minutes as `ReplayResign` instead of `ErrRecoveryBusy`;
- write the unsigned reservation only after the local signing stage succeeds,
  keeping the remote stage inside the same lease.

A regression test for "cosign fails once, retry succeeds" would lock the fix
in.

### M2 — Transition rate limiter: unbounded growth on arbitrary vault IDs, package-global state

**Location:** `internal/application/transition.go:370–396`

`allowTransition(req.VaultID)` runs **before** any check that the vault
exists (`loadVerifiedCredentialFor` comes after). Every request with a fresh
`vaultId` string inserts a new key into the package-global
`transitionRateHits` map, and keys are never removed — expired timestamps are
pruned but the key and empty slice remain. Any client that can reach the
private surface through the gateway (i.e., any wallet-origin browser, no
enrollment needed) can grow this map without bound: a slow memory-exhaustion
DoS against the signing process. It is also shared mutable package state
rather than `Service` state.

**Recommendation:** validate that the vault exists before registering a
rate-limit hit (or key the limiter on verified vault IDs only), delete
map entries whose slices prune to empty, and move the map onto `Service`.

### M3 — Sign-count enforcement silently disabled if its table is missing

**Location:** `internal/policy/signcount.go:24–26`

```go
if !hasTable(l.db, "webauthn_sign_count") {
    return nil
}
```

Schema validation at `OpenMainnetLedger` makes this unreachable today, but a
security control that silently no-ops on a missing table is a fail-open
pattern; a future schema variant or test-ledger misuse would drop clone
detection without any signal.

**Recommendation:** return an error. The strict-schema gate means this can
never fire in a healthy deployment, so the change is free.

---

## Low-severity findings

### L1 — Two MACs concatenate variable-length fields without length prefixes

**Location:** `internal/policy/vaultmap.go:71–78`,
`internal/policy/signcount.go:64–73`

`vaultMapMAC` computes `HMAC(domain ‖ vaultID ‖ kitHash ‖ payload)` and
`signCountMAC` computes `HMAC(domain ‖ vaultID ‖ credentialID ‖ count)` with
no field delimiters, unlike every other MAC in the codebase (which uses the
length-prefixed `appendCredentialField` canonical encoding). Field-boundary
ambiguity is only exploitable by an adversary who can already write the
database, and formats are fixed in practice (32-hex vault IDs, 64-hex kit
hashes), but it is an inconsistency in an otherwise uniformly careful MAC
discipline.

**Recommendation:** length-prefix these two the same way. This changes stored
MACs, so do it before mainnet freeze (it requires resealing rows or a
version bump in the domain string).

### L2 — CBOR decoder accepts duplicate map keys and non-minimal lengths

**Location:** `internal/webauthn/cbor.go`

The hand-rolled decoder is admirably minimal (no arrays, tags, floats,
indefinite lengths; 16-entry map cap; 4 KiB input cap), but `mapInt`/`mapText`
return the *first* match for duplicate keys, and `decodeCBORLen` accepts
non-minimal encodings (e.g. `0x18 0x05`). CTAP2 canonical CBOR forbids both.
Impact is contained because this server is the only authoritative parser for
its own descriptor (and the wallet independently rebuilds and hash-checks the
descriptor), but rejecting duplicates and non-minimal lengths removes a
parser-differential class outright.

### L3 — Public error filtering is a substring blocklist

**Location:** `internal/application/http.go:288–303` (`publicErrorMessage`),
`http.go:244–256` (`writeMutationError`)

`publicErrorMessage` suppresses messages containing "sqlite", "http ",
"panic", etc. A blocklist can miss novel internal strings (driver messages,
future dependencies). Separately, JSON decode errors are echoed verbatim via
`writeMutationError` without passing through the filter (these only describe
the client's own malformed input, so the leak is cosmetic — Go type names).

**Recommendation:** invert to an allowlist: return `apperr` code-derived
messages for known codes and a generic message otherwise. The `apperr`
package comment already says "HTTP maps Code, never substring-matches" — the
same philosophy should apply to message emission.

### L4 — `X-Request-Id` echoed and logged without bounds

**Location:** `internal/application/http.go:104–127`

The client-supplied header is trimmed and then echoed into the response and
written to the process log with no length cap or charset restriction. Go's
HTTP stack prevents CR/LF injection, so there is no response-splitting or
log-line-forging risk, but a client can inflate log volume with arbitrarily
long IDs. Cap it (e.g. 64 chars, `[A-Za-z0-9._-]`), else generate one.

### L5 — Exact-fee search cost

**Location:** `internal/application/vtxo.go:494–547` (`solveVtxoSpend`),
called from `selectSpendVtxos`

The change-fee solver iterates fee candidates `0..min(feeCap, total-amount)`
and runs a CEL fee-program evaluation per candidate, inside a loop over input
counts up to 50. With the current release caps (`AbsoluteFeeCeiling` = 5,000
sats) that is worst-case ~250k CEL evaluations for one reservation. The path
is gated behind a valid phone Schnorr signature, so only the enrolled wallet
can trigger it, and reservation holds the ledger lock while it runs — a buggy
or malicious *enrolled* client can stall the ledger for other tenants.
Fixed-point iteration (evaluate fee at a candidate, re-evaluate at the
result; converges in 2–3 steps for monotone fee programs) or a binary search
would remove the linear scan. Also: the `if candidate == math.MaxUint64`
guard is unreachable given the cap and can go.

### L6 — Secret scalars pass through `big.Int`

**Location:** `internal/authorizer/runtime.go:306` (`LoadVaultCosignerKey`),
`internal/policy/cosigner.go:180–189` (`scalarInRange`)

Range checks build a `big.Int` from the raw scalar/OKM. `big.Int` buffers
cannot be zeroized and may be copied by the GC. The process necessarily holds
the master scalar long-term anyway, so this is marginal — but both checks can
be done with `btcec.ModNScalar.SetByteSlice` (returns overflow) or a
constant-time byte comparison against N, keeping the raw-bytes hygiene the
rest of the file already practices.

### L7 — Test-signing helpers live in production packages

**Location:** `internal/webauthn/synth.go` (`Synth` — builds valid
assertions given a private key), `internal/webauthn/p256.go:77`
(`SignDigestLowS`), `internal/authorizer/runtime.go:317`
(`parseDeploymentPub` — no production callers)

None are reachable from request paths (each requires a caller-supplied
private key), but exporting an assertion forge from the same package that
verifies assertions invites accidental misuse and widens the reviewed
surface. Move to an internal `webauthntest` package; delete or test-file
`parseDeploymentPub`.

### L8 — Reserved-outpoint matching tries both txid byte orders

**Location:** `internal/application/vtxo.go:1189–1202`
(`matchReservedOutpoint`)

The function looks a PSBT outpoint up under both the wire-internal hash bytes
and the display-order (reversed) hex. Stored reservation txids are always
display-order (decoded from indexer hex), so only the second probe can match
in practice; forcing a byte-reversal collision between two real txids is a
2^128 problem. Still, dual-representation matching can mask an
encoding-direction bug elsewhere. Canonicalize to a single order at the
storage boundary and match once.

---

## Informational observations

- **I1 — Vault IDs are bearer capabilities for reads.** `GET /v1/map` and
  `GET /v1/vtxo/operation` authenticate by gateway secret + vault ID
  knowledge only (by design: a fresh device must fetch the encrypted Recovery
  Kit before it can authenticate). Vault IDs are 128-bit random, but
  `withRequestLog` writes `vault=<id>` for every request — the log stream
  becomes secret-adjacent. Consider logging a hash or prefix.
- **I2 — The 24h rolling allowance trusts the OS clock.** Row `CreatedAt`
  values are MAC'd, but `now` is wall-clock: an operator or NTP adversary who
  advances the clock collapses the window early. Backward jumps are safe
  (spend counts grow). Documented ledger-trust posture; mainnet may want a
  monotonic anchor.
- **I3 — Compose ships DB and policy sequence as two named volumes under one
  restore authority** — exactly the single-failure-domain the README and
  `deploy/ops.md` warn about. Fine for the Mutinynet RC; the mainnet runbook
  correctly requires independent storage/backup/restore authorities.
- **I4 — `VAULT_GATEWAY_SECRET` lives in process env for the process
  lifetime.** Comparison is SHA-256 + `subtle.ConstantTimeCompare` (good).
  The Railway entrypoint's unset-after-materialize pattern for the key/token
  secrets is careful; the gateway secret itself remains env-borne by design.
- **I5 — Lint gate is minimal.** `.golangci.yml` enables only `govet` +
  `unused`. staticcheck already runs clean apart from ST1005 (capitalized
  error strings, 8 sites) and SA1019 deprecations:
  `elliptic.Curve.IsOnCurve` (`webauthn/create.go:176`) and
  `ecdsa.PublicKey.X/.Y` reads (create.go, p256.go, synth.go) are deprecated
  as of Go 1.21/1.26. Usage is verification-side and currently correct;
  migrate to `crypto/ecdh`-style parsing (`ParseUncompressedPublicKey` /
  `PublicKey.Bytes`) as maintenance. Recommend enabling `staticcheck`,
  `errcheck`, `gosec` in golangci and adding `govulncheck` to CI
  (it could not reach vuln.go.dev from this audit environment).
- **I6 — `btcec` is force-downgraded.** `go.mod` `require`s
  `btcec/v2 v2.3.5` but a `replace` pins v2.3.3. If the pin exists for
  emulator-fork compatibility, document why; otherwise drop it — later 2.3.x
  releases carry fixes.
- **I7 — The covenant engine is an external PoC fork.** The `replace` of
  `github.com/arkade-os/emulator/pkg/arkade` to
  `brg444/arkade-2fa-vault-poc` (pseudo-version pinned, `go mod verify` in
  CI) is the module whose `Execute`/`ComputeArkadeScriptPrivateKey` gate
  every transition signature. It is inside the trust boundary but outside
  this repo; it should receive the same review depth as `internal/`, and
  vendoring it would freeze the reviewed bytes into this repo.
- **I8 — Deployment hardening is exemplary:** digest-pinned builder and
  runtime images, `CGO_ENABLED=0 -trimpath`, non-root UID, `read_only`
  rootfs, `cap_drop: ALL`, `no-new-privileges`, `noexec` tmpfs, host port
  bound to 127.0.0.1, file-backed 0600 secrets.
- **I9 — Duplicate-finish enrollment replay** (`acceptDuplicateFinishFromToken`)
  intentionally lets the invite token + user handle recover the enrolled
  Status after the pending row is consumed; the full canonical-equality
  re-derivation makes this safe, worth keeping under test (it is).

---

## What holds up well (verified, not assumed)

- **Gateway boundary:** unknown paths 404 only after the secret check; method
  allowlist; exact `Origin` equality on mutations; `DisallowUnknownFields`;
  1 MiB body cap with `MaxBytesReader`; strict Content-Type; single-JSON-value
  enforcement; CSP/anti-frame/no-store headers.
- **WebAuthn:** `crossOrigin` must be present *and* false; RP-ID hash checked
  against the *stored* enrollment RP; UV and UP both required; challenges are
  32-byte single-use with 2-minute TTL, consumed-before-verify (no retry
  oracle on one challenge); create ceremony requires the AT flag, fmt=none
  attestation, strict COSE (EC2/ES256/P-256, on-curve, round-trip); DER
  signatures parsed by `encoding/asn1` with trailing-byte rejection, zero/
  negative/range checks, low-S normalization; per-(vault, credential)
  MAC-sealed monotonic sign counts.
- **Spending state machine:** client-persisted 16-byte operation IDs; phone
  Schnorr proof over (opID, vault, purpose, destScript, amount) verified
  *before* any coin selection; reservation, overlap check, allowance check,
  input MACs, and monotonic-sequence advance in one `BEGIN IMMEDIATE`
  transaction; canonical bundle digest binds every economic field and the
  sorted input set; authorize re-verifies fee-policy digest, PSBT structure
  (version/locktime/sequences, checkpoint-output chaining, exact
  amounts/scripts, value conservation), user signatures cryptographically,
  and the WebAuthn challenge *is* the bundle digest; replays are compared
  field-by-field; `signed → submitted → finalized` transitions are CAS'd and
  concurrency-checked; finalization requires the pinned indexer to prove the
  reserved outpoints were spent by the recorded Ark txid and the change VTXO
  to exist with exact value.
- **Savings/recovery scripts:** NUMS internal keys derived from
  domain-separated context hashes; pairwise-distinct role keys with G/2G/NUMS
  forbidden; the transition covenant (exact output count, pinned destination,
  P2A value, fee and feerate ceilings, optional phone-CSFS binding) is
  enforced by the Arkade script whose hash tweaks the cosigner keys — the
  signature literally cannot exist for a non-conforming transaction.
- **External identity pinning:** operator signer key, checkpoint tapscript
  (decoded and structurally re-verified against release constants), emulator
  origin/version allowlist, indexer origin — all compile-time pins with no
  env overrides; both HTTP clients disable redirects, bound response sizes,
  and enforce content types; fee policy re-fetched and digest-compared before
  every signature.
- **Persistence:** every row MAC'd (HMAC-SHA256, domain-separated,
  length-prefixed canonical encodings, versioned); exact-schema validation on
  open down to normalized CHECK constraints and index columns; foreign keys
  enforced and `foreign_key_check` after vault creation; `synchronous=FULL`;
  atomic tmp+rename+dirsync writes for the monotonic file.

## Test and tooling results

```
go test ./... -count=1        → ok (all 13 packages with tests)
go test -race ./internal/policy ./internal/application ./internal/authorizer → ok
go vet ./...                  → clean
staticcheck ./...             → ST1005 ×8 (style), SA1019 ×7 (deprecations); no bug-class findings
govulncheck                   → not runnable from audit environment (vuln DB fetch blocked); add to CI
```

The test suite is a genuine asset: dedicated adversarial suites for DER and
assertion handling (`der_security_test.go`, `assert_security_test.go`),
tenant isolation, fail-closed signer behavior, protocol-domain uniqueness
across packages, browser-captured WebAuthn fixtures, and HKDF/tree test
vectors under `testdata/`.

## Prioritized remediation

1. **M1** — add a lease/cleanup for unsigned recovery sessions (protects the
   safety path; small change, add the crash-retry regression test).
2. **M2** — validate vault existence before rate-limit registration; prune
   empty keys; move state onto `Service`.
3. **M3 + L1** — make `AdvanceSignCount` fail closed on a missing table and
   length-prefix the two odd MACs (both cheap; L1 easiest before any real
   deployment data exists).
4. **L3/L4** — allowlist error emission, cap `X-Request-Id`.
5. **CI** — add `govulncheck` and broaden golangci linters; resolve the
   `btcec` downgrade question (I6); schedule an equal-depth review of the
   `arkade-2fa-vault-poc` covenant module (I7) before mainnet.

None of the above blocks continued Mutinynet operation. The mainnet gates
already documented in `docs/mainnet-v2-baseline.md` (bounded-history
allowance scan, independent storage authorities, private Emulator endpoint,
hardware isolation) remain the correct larger blockers.
