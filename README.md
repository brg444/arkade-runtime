# arkade-vault-server

> [!WARNING]
> This is an experimental reference signer, not a production custody service.
> It runs on Mutinynet only and refuses to start on any other network. The
> cosigner key is a file on disk, not an HSM. Do not secure significant funds
> with it.

This binary is the signer for Arkade Vault. It holds one cosigner key and the
policy ledger. It is not the wallet, not the chain, and not custody — the
product, the phone app, and the tree design live in
[arkade-wallet-vault](https://github.com/brg444/arkade-wallet-vault).

The vault itself is a family of Taproot trees on Bitcoin, running on Mutinynet.
Arkade supplies the second cosigner signature and the script extensions the
leaves use; it is a counterparty in the tree, not the chain the coins live on.
Every path through the trees is enforced by Bitcoin script and relative
timelocks.

**Spending and savings.** Spending is the everyday balance: the phone can
send from it, up to a cap, with a passkey tap. Savings is the reserve, and no
leaf in it contains a key this server can use to pay an arbitrary recipient.

Spending is not a hot wallet in the usual sense. It is still a 3-of-3 vault
output with a per-transaction cap and a rolling allowance — the phone cannot
spend it alone, it just doesn't need your hardware wallet for small amounts.

## How the vault is constructed

A staged-program vault is a family of L1 Taproot trees derived from two or
three keys — `phone`, `hardware`, and an optional `recovery` key — plus the two
cosigner keys. All of it is rebuilt from those keys on every startup. The
server never trusts a script or address supplied by a client.

Two trees hold money. The app calls them **Spending** and **Savings**; the code
and this document call the first one `daily`, which is the same tree.

**Spending** (`daily`) accepts three kinds of spend:

```text
routine    phone + VaultCosigner + ArkadeCosigner      (capped, this server)
admin      phone + hardware                            (no server)
initiate   claimant + VaultCosigner + ArkadeCosigner   (starts a transition)
```

**Savings** is the same, minus the routine leaf:

```text
admin      phone + hardware                            (no server)
initiate   claimant + VaultCosigner + ArkadeCosigner   (starts a transition)
```

That single omission is the whole savings guarantee. There is no leaf in the
Savings tree that this server can help spend to an arbitrary recipient, so
"it cannot take Savings" is a structural fact about the tapscript rather than
a policy this process promises to honor.

## What this process is

Three things, in one binary, deliberately:

```text
phone app  →  /v1  →  this process
                        holds the VaultCosigner private key
                        owns the authoritative SQLite ledger
                        brokers the second signature from the public Arkade signer
```

The key and the ledger live in the same process on purpose. The rolling
allowance is only meaningful if the thing enforcing it is the same thing
holding the key — otherwise an attacker who reaches the key skips the ledger.

## What it is not

- **Not a custodian.** It holds one of three keys on the Spending routine path
  and one of three on the transition paths. It is never sufficient on its own.
- **Not able to strand your coins.** It cannot take Savings, cannot spend
  alone, and cannot block a claim that is already pending. It *is* required to
  begin a staged recovery, so it is not irrelevant to recovery — see above.
- **Not an HSM.** The cosigner scalar is a hex file read at startup.
- **Not the chain, and not the Arkade VTXO service.** The trees are ordinary L1
  Taproot outputs. This process never proxies `/v1/onchain-tx`.
- **Not mainnet.** `deployment.Config.Validate` structurally rejects every
  network except regtest and Mutinynet, and the authorizer rejects regtest too.

## Programs

A *program* is a named Taproot template. The stored `template_version` on each
vault says which one it was minted under, and that string is frozen for the
life of the vault. v5 and v6 share the `arkade-vault/v5` descriptor schema and
have different template identities. Only v6 is enrollable:

| Job | `template_version` | `enrollable` |
| --- | --- | --- |
| **Daily leftover** | `phone-direct-p256-routine-3of3-admin-phone-hww-v4` | no. Existing rows still load. |
| **Prior staged leftover** | `phone-hww-recovery-staged-v5` | no. Existing rows still load. Cancel still needs both cosigners. |
| **Staged program** | `phone-hww-recovery-staged-v6` | yes. Optional recovery. Pending can be cancelled with remaining user keys, no server. |

### Moving money out without the server

`admin` needs both your devices and no server. That is the cooperative exit.
The interesting case is when one device is lost or stolen, which is what the
transition machine is for.

Each claimant — phone, hardware, or recovery — can *initiate* a move out of
Spending or Savings into a **pending** output that belongs to that claimant.
Pending is a race:

```text
                       initiate                    claim (after CSV)
 Spending / Savings  ──────────────▶  Pending  ──────────────────────▶  claimant
                                         │
                                         │ clawback (valid immediately)
                                         ▼
                                    Quarantine  ──▶  everyone except the claimant
```

The pending output has two competing paths:

- **Claim** is the claimant alone, after a relative timelock that starts when
  the pending output confirms. No server, no counterparty.
- **Clawback** is any *other* claimant plus both cosigners, and it is valid
  immediately. It sweeps the funds into a **quarantine** output spendable only
  by the remaining parties — the initiator is excluded entirely.

So whoever moves first has to wait, and whoever objects does not. The delays
are per-claimant and encode how much each key is trusted:

| Claimant | Delay | Why |
| --- | --- | --- |
| `hardware` | 6 blocks | Most-protected key. Little reason to stall it. |
| `phone` | 144 blocks | Most-exposed key. The widest objection window. |
| `recovery` | 288 blocks | Last resort, longest objection window. |

These are block counts, not wall-clock. On a 10-minute chain they are roughly
an hour, a day, and two days. **Mutinynet produces blocks far faster than
that**, so on the live demo the same delays elapse in a small fraction of those
times — do not size a testing plan, or a stolen-phone story, off the mainnet
figures.

If your phone is stolen, the thief can initiate but must wait out 144 blocks.
You use your hardware wallet to clawback into quarantine, which the stolen
phone cannot touch. If your hardware wallet is lost, your phone initiates,
waits 144 blocks, and claims.

This server cosigns `initiate` and `clawback`. It cannot cosign `claim`, because
claim is a timelock and a single key — no cosigner appears in that leaf. So a
compromised or offline server cannot stop a recovery that has already been
initiated. What it can do is refuse to start one, which leaves `admin` as the
only exit until it returns.

## The routine spending path

Routine spends are the only place this server enforces a *stateful* policy,
and they are the only place it needs to. The design is that the script and
the server enforce the same rules, so compromising the server does not lift
the caps.

Every routine spend must be exactly this shape, or both layers reject it:

```text
input   one, the Spending vault output, spending the routine leaf
out 0   recipient, native segwit, ≥ dust, ≤ 50,000 sats
out 1   change, back to the same Spending vault, ≥ dust
out 2   the Arkade emulator packet, zero value, last
```

Mandatory recursive change is what stops the routine path being used to drain
the vault: whatever you do not spend must return to the same script. There is
no version of a routine spend that empties the address.

The caps are pinned in code, mirrored into the tapscript, and re-checked
against the stored descriptor at startup:

| Limit | Value | Enforced by |
| --- | --- | --- |
| Recipient per transaction | 50,000 sats | script + server |
| Rolling 24h outflow | 100,000 sats | server ledger only |
| Absolute fee | 5,000 sats | script + server |
| Feerate | 10 sat/vB | script + server |
| Dust floor | 330 sats | script + server |

Only the rolling allowance is server-only, because Bitcoin script cannot see
across transactions. Everything else is enforced twice.

### The request flow

```text
1. POST /v1/draft       build an unsigned, empty-witness PSBT
2. POST /v1/preflight   → challenge (the witness-masked Arkade sighash)
3. (on device)          passkey ceremony over the challenge, producing a
                        WebAuthn assertion and a PRF-derived P-256 signature
4. POST /v1/bind        verify both, write the P-256 signature into the packet
5. (on device)          phone signs the routine leaf with its BIP340 key
6. POST /v1/authorize   verify everything, reserve allowance, add both
                        cosigner signatures  → 3-of-3 complete
7. POST /v1/publish     broadcast; GET /v1/tx to poll confirmation
```

Setting the packet witness in step 4 does not change the challenge — the
Arkade sighash masks witness bytes — so the signature from step 3 stays valid
over the transaction it authorized.

Two independent user signatures are required, and they are different keys for
different reasons. The **WebAuthn assertion** proves a live passkey ceremony
happened on the enrolled credential, and is checked off-chain. The
**DirectP256 signature** is a PRF-derived key that the tapscript itself
verifies with `OP_CHECKSIGFROMSTACK`. Bitcoin cannot parse `clientDataJSON`,
so the on-chain check uses a key the script can actually verify, while the
off-chain check gets the full ceremony guarantees.

### How allowance is actually enforced

`/v1/authorize` reserves before it signs, inside a `BEGIN IMMEDIATE`
transaction:

1. Look up the (vault, sighash) row. If it is already `completed`, return the
   stored signature — an exact retry is a replay, not a second spend.
2. Otherwise sum every `reserved`, `vault_signed`, and `completed` row in the
   rolling 24-hour window, verifying each row's MAC as it counts.
3. Reject if `recipient + fee` does not fit under the remaining allowance.
4. Insert a `reserved` row, then release the lock and sign.

Signing is two persisted stages — VaultCosigner first, then the public
ArkadeCosigner — so an ambiguous timeout against the external signer can be
retried without ever reusing the private key on a different transaction. Every
row is authenticated with a per-vault derived HMAC key, so editing the SQLite
file to refill an allowance fails verification.

The window is rolling, not calendar-day, deliberately: a calendar refill lets
you spend the cap at 23:59 and again at 00:01.

## Components

| Path | What it is |
| --- | --- |
| `cmd/authorizer` | The binary. Flags and env, then hand off to `internal/authorizer`. |
| `internal/authorizer` | Startup. Loads the key, opens the ledger, runs migrations, dials the external signer, refuses to boot if any of it is wrong. |
| `internal/application` | The service. Enrollment, routine spends, transitions, publishing, passkey sessions. |
| `internal/policy` | The ledger. Allowance accounting, record MACs, tenant rows, recovery sessions, migrations. |
| `internal/vault` | The routine `AuthorizationScript`, PSBT construction, finalization, and signature verification. |
| `internal/vault/v5` | The staged program: tree family, transition scripts, public descriptor. |
| `internal/webauthn` | Passkey verification. Assertion, attestation, CBOR, DER, P-256. |
| `internal/deployment` | Runtime identity. Origin, RP ID, network, CSV delays — and what is refused. |
| `internal/iface/http` | The HTTP surface. Parses and maps errors; owns no keys. |
| `contract-pack.json` | Frozen names shared byte-identically with the phone app. |

### Why startup is so strict

`internal/authorizer` refuses to boot in a surprising number of situations,
and each one is deliberate:

- Network is not Mutinynet, or `VAULT_GATEWAY_SECRET` is unset.
- The database path is relative or in-memory — the ledger must be durable.
- The cosigner key is not a 32-byte scalar in `[1, n-1]`, or is a known
  public test fixture (`G` or `2G`).
- Any two key roles collide on their x-only identity.
- A stored credential's MAC does not verify, or migration changed the first
  vault's descriptor.
- The external Arkade signer's advertised pubkey or version does not match the
  release pin.

A signer that starts in a misconfigured state is worse than one that does not
start, because the failure surfaces as a signature rather than an error.

## Two enforcement layers

The most important structural property of this codebase is that the server is
not trusted to enforce policy. `internal/vault/script.go` builds a tapscript
that independently checks transaction version, locktime, input count, sequence,
output count, the recipient cap and dust floor, recursive change to the same
vault, the packet output's exact hash, non-negative fee, the absolute fee
ceiling, and the feerate ceiling using `OP_TXWEIGHT`.

`internal/application/classify.go` checks the same things in Go before signing.

The server check exists to give a good error message and to enforce the one
rule script cannot see. The script check exists because the server might be
wrong. When they disagree, Bitcoin wins.

## Run it

Generate the two file-backed secrets and the gateway secret:

```bash
install -d -m 700 ./secrets
umask 077
openssl rand -hex 32 > ./secrets/vault-cosigner-key
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n' > ./secrets/enrollment-token
chmod 0600 ./secrets/*

cp .env.example .env
printf 'VAULT_GATEWAY_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env
# then set VAULT_CLIENT_ORIGIN, VAULT_RP_ID, VAULT_EXTERNAL_OWNER_WALLET_PUB
```

Bring it up and check liveness:

```bash
docker compose up -d --build
set -a; . ./.env; set +a
curl -fsS -H "X-Vault-Gateway-Secret: $VAULT_GATEWAY_SECRET" \
  http://127.0.0.1:8788/health
```

`VAULT_GATEWAY_SECRET` is required and the process refuses to start without
it. Every route except `/health` is rejected with 401 unless the request
carries it in `X-Vault-Gateway-Secret`. It is the only thing standing between
the open internet and the signing API, so treat it like the cosigner key.

The cosigner key and the enrollment token are files rather than environment
variables on purpose: environment blocks leak into process listings, crash
reports, and orchestrator dashboards far more readily than a `0600` file does.

Two things not to do, both of which the code will refuse anyway: do not put
trees or caps in the environment — they are code-pinned and cross-checked
against every stored descriptor — and do not use the curve generator as a key.

Live deploy is Railway `authorizer-next`. See [deploy/README.md](deploy/README.md).

```bash
go test ./...
```

Go 1.26.6.

## API surface

Everything is `POST` with `Content-Type: application/json` and an exact
`Origin` match, except where noted. Unknown JSON fields are rejected.

| Route | Purpose |
| --- | --- |
| `GET /health` | Liveness. The only unauthenticated route. |
| `GET /v1/status` | Public status, or one vault's status with `?vault=`. |
| `GET /v1/invite` | Whether an invite token can still enroll. |
| `/v1/enroll/start` | Reserve a vault id and a create-ceremony challenge. |
| `/v1/enroll/propose` | Preview the descriptor without consuming the invite. |
| `/v1/enroll/finish` | Verify the ceremony and CAS-consume the invite. |
| `/v1/draft` | Build an unsigned routine PSBT. |
| `/v1/preflight` | Return the challenge for a PSBT without signing. |
| `/v1/bind` | Verify the passkey ceremony, bind the P-256 witness. |
| `/v1/authorize` | Reserve allowance and add both cosigner signatures. |
| `/v1/initiate` | Cosign Spending/Savings → Pending. Staged program only. |
| `/v1/clawback` | Cosign Pending → Quarantine. |
| `/v1/publish` | Broadcast a completed transaction. |
| `GET /v1/tx` | Poll publication status. |
| `/v1/passkey/challenge` | Start a passkey session for install or recover. |
| `/v1/passkey/binding` | Build the canonical recovery binding to sign. |
| `/v1/passkey/install` | Store the encrypted credential envelope. |
| `/v1/passkey/recover` | Return it to an authenticated fresh device. |

Enrollment verifies the passkey create ceremony and the server-built public
descriptor. Hardware and optional recovery keys are public-key inputs; the
enrollment API does not request or verify ownership signatures for them.

There is no route that signs an arbitrary PSBT. Every signing route is bound
to a specific rebuilt script and a specific policy.

## Security model

The server is assumed to be compromisable. The design question is what an
attacker gets, and the answer is bounded by script:

| If an attacker gets | They can | They cannot |
| --- | --- | --- |
| Network access to `/v1` | Nothing without the gateway secret | Reach any route but `/health` |
| The gateway secret | Reach the API | Sign anything without a valid passkey ceremony |
| Full control of the process and key | Cosign routine spends within the script caps | Exceed 50k/tx, skip recursive change, touch Savings, or block a `claim` |
| The public Arkade signer | Refuse to sign | Produce a valid third signature |
| Write access to the SQLite file | Corrupt or delete rows, causing refusal to start | Forge an issuance row that verifies, or refill an allowance |

Nothing above lets an attacker take Savings, because no leaf in the Savings
tree contains a key this server holds in a spending role.

One limit of the ledger MACs is worth stating plainly rather than leaving for
someone to discover: they authenticate the *contents* of each row, so they do
not detect a deleted row or a wholesale rollback to an older SQLite file.
Noticing that needs a monotonic value stored outside this database.

Live `recovery_session` verify is the v2 preimage only (sighash and
signature included). The v1 preimage is gone from production. Migrate
fails closed on any row that is not v2. A retired v1 payload exists
only in tests. See [docs/versions.md](docs/versions.md).

Report anything that makes this process sign an address it did not build
itself, skip the invite gate, or use its master key on chain. See
[SECURITY.md](SECURITY.md). Do not open a public issue with a live exploit.

## Docs

| Where | What |
| --- | --- |
| [deploy/README.md](deploy/README.md) | Docker and Railway. |
| [SECURITY.md](SECURITY.md) | Reporting. |
| [contract-pack.json](contract-pack.json) | Names shared with the phone app. |
| [arkade-wallet-vault](https://github.com/brg444/arkade-wallet-vault) | The product and the tree design. |
