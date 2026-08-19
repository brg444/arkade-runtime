# Three independent version axes

Schema integer, program identity, and domain-separator literals are
**not a shared generation ladder**. They share digits by coincidence.
Bumping one does not bump the others.

`credential-record/v3` and `enrollment-pop/v3` are two contracts that
happen to end in `v3`. Schema 8 is a SQLite layout. Template
`phone-hww-recovery-staged-v6` is an on-chain tree family. None of
those is a release number.

| Axis | What it versions | Example | When it moves | What does not move |
| --- | --- | --- | --- | --- |
| **Program** | On-chain tree shape, stored as `template_version` | `phone-hww-recovery-staged-v6` | New address family. Old UTXOs stay on the old template. | SQLite layout. HMAC/HKDF strings. |
| **Schema** | SQLite layout (`schema_meta.version`) | `7` | Server migration. Coins do not move. | Tree shape. Domain strings, unless that migration *also* reseals a named domain. |
| **Domain** | One HMAC or HKDF string | `arkade-2fa-vault/recovery-session/v2` | That one MAC or derived key only. | Every other domain. On-chain keys, unless this *is* the vault-cosigner domain. |

Do not collapse domains to `arkade-vault/1/prf`. Independent suffixes
are how recovery sessions were re-sealed without rotating the
vault-cosigner salt.

The `arkade-2fa-vault/` prefix is a historical module name, not a 2FA
claim and not a generation. Do not rename it until the prefix-cut
checklist at the bottom is actually true.

## Talk about the program by job

The only enrollable program is the staged program,
`phone-hww-recovery-staged-v6`. That is what `/v1/enroll/*` mints.

Leftover template ids may still exist on the live ledger:

| Job | `template_version` | Enrollable |
| --- | --- | --- |
| Daily leftover | `phone-direct-p256-routine-3of3-admin-phone-hww-v4` | no |
| Prior staged leftover | `phone-hww-recovery-staged-v5` | no |
| Live staged | `phone-hww-recovery-staged-v6` | yes |

v5 and v6 share schema `arkade-vault/v5`. v6 adds cancellation with the
remaining user keys. The phone app watcher is best-effort local polling,
not a watchtower.

`RefuseLegacyDatabase` refuses a non-empty singleton `credential` table
and `cosigner_mode = 'legacy-direct-v0'`. It does **not** inspect
`template_version`. “Is the ledger empty?” is a gate, not a footnote.

## Domain blast radius

Listing the strings tells you what exists. Listing what breaks is why
you cannot touch the first row after reading `DeriveVaultCosignerScalar`
and still proposing a new salt.

| Domain | Frozen literal | Rotating it costs |
| --- | --- | --- |
| vault-cosigner | `arkade-2fa-vault/vault-cosigner/hkdf-sha256-v1` plus info `vault-cosigner/v1` | New on-chain keys. Every enrolled vault loses server-assisted routine spend. Admin and CSV claim still work. |
| prf | `arkade-2fa-vault/prf/v1` | Client-side derivation changes; requires re-enrollment. |
| kek | `arkade-2fa-vault/kek/v1` | Client-side derivation changes; requires re-enrollment. |
| direct-p256 | `arkade-2fa-vault/direct-p256/v1` | Client-side derivation changes; requires re-enrollment. |
| enrollment-pop | `arkade-2fa-vault/enrollment-pop/v3` | New enroll proofs only. Existing vaults stay. |
| credential-record | `arkade-2fa-vault/credential-record/v3` | Re-seal or refuse the singleton credential row. No on-chain effect. |
| issuance-record | `arkade-2fa-vault/issuance-record/v3` | Re-seal or reset the allowance ledger. No on-chain effect. |
| vault-record | `arkade-2fa-vault/vault-record/v4` | Re-seal tenant descriptor rows. No on-chain effect. |
| vault-credential | `arkade-2fa-vault/vault-credential/v1` | Re-seal passkey↔vault bindings. No on-chain effect. |
| recovery-session | `arkade-2fa-vault/recovery-session/v2` | Re-seal server-side session rows. No on-chain effect. |
| credential-envelope / vault-envelope | `…/credential-envelope/v1`, `…/vault-envelope/v4` | Re-seal PRF envelopes. No on-chain effect. |

Do not bump a domain string unless you intend to rotate **that** key or
MAC.

## Domain rotation template

A domain bump is three parts, in this order. “Migrate then drop”
compresses out the part that is easy to botch.

1. **New preimage under a new domain string.** Seal and verify on the
   new literal only for newly written rows.
2. **Migration that re-seals.** Walk existing rows. Re-seal **only**
   rows that fail the new verify and still pass the old verify. Rows
   that already verify as new are left alone. Rows that verify as
   neither fail closed.
3. **Verify accepts only the new preimage.** Hot-path `verify*` must
   not dual-accept after the migration has run. Dual-accept is the
   window.

Then, after every live ledger that can boot this binary is confirmed
at or past the schema integer that performed step 2, **delete the old
preimage**. Leaving `canonical*` / `verifiesOld` in tree after that
point is a valid forgery recipe.

That is the schema-6→7 recovery-session lesson, finished:

- new domain `recovery-session/v2` (covers sighash + signature)
- `verifySession` accepts v2 only
- production no longer contains the v1 preimage
- `MigrateRecoverySessions` fails closed on any row that is not v2
- live Railway had **zero** `recovery_session` rows, so 6→7 is an
  empty-table version bump

A retired v1 payload exists **only in tests**, to prove verify and
migrate reject it.

Schema stays an integer. Programs stay enrollable-or-not in the pack.

## Live ledger (not greenfield)

Queried Railway `authorizer-next` `/app/data/vault.sqlite` on
2026-08-19. Non-empty Mutinynet ledger:

| Fact | Value |
| --- | --- |
| `schema_meta.version` | live integer; this binary migrates forward |
| vaults | **4**, all `hkdf-sha256-v1` (1 leftover v3, 1 leftover v4, 2 leftover v5) |
| enroll program | `phone-hww-recovery-staged-v6` (no v6 rows yet) |
| `recovery_session` | 0 |
| singleton `credential` | 0 |

This is not an empty-ledger cut. Do not treat a `git clone` as a
fresh start.

```sql
SELECT version FROM schema_meta;
SELECT template_version, cosigner_mode, COUNT(*) FROM vault GROUP BY 1, 2;
```

Do not paste production vault ids into this file.

## Prefix cut (`arkade-2fa-vault/` → `arkade-vault/`)

Legitimate only when all of this is deliberate and already done:

- new on-chain addresses (vault-cosigner domain rotated)
- every live vault re-enrolled under the new strings
- funds moved by the owner, not by a server rewrite
- empty or newly created ledger; no funded leftover rows
- both contract packs published together

Until then the prefix stays. A sentence here is cheaper than a
silent rotation.
