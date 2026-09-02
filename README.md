# Arkade Vault Server

> [!WARNING]
> This release candidate runs only on Mutinynet. Real-fund custody is out of
> scope. Mainnet requires reviewed Emulator and Operator pins and
> hardware-isolated VaultCosigner keys.

Arkade Vault Server is the protected policy and signing service for
[Arkade Wallet Vault](https://github.com/brg444/arkade-wallet-vault). It owns
the VaultCosigner key and the authoritative policy ledger. It does not build a
general wallet, broadcast arbitrary transactions, or expose a raw signing API.

The wallet and server independently validate the same versioned Vault Program.
The server may add a VaultCosigner signature only after the complete operation
matches that program and its stateful allowance. Bitcoin scripts and committed
transaction paths retain the structural spending and recovery constraints.

This release hosts one compiled program, `vault-policy-v1`, with an immutable
policy instance and protection tier for each vault. `standard` forbids a
recovery key; `advanced` requires a recovery key distinct from the other
enrolled roles. Enrollment freezes both values before the passkey ceremony.
The Spending choice is Lower exposure (25,000 sats per send and 50,000 sats
per rolling 24 hours), Everyday (50,000 and 100,000 sats respectively), or
custom values for those two limits. Every choice uses the release-managed
ceilings of 5,000 sats and 10 sat/vB. The wallet and server independently
rebuild the same descriptor and persist the selection in the authenticated
vault record. The service does not load arbitrary policy code or allow these
conditions to change after enrollment.

## Responsibilities

The service is organized around four product workflows:

| Workflow | Server responsibility | Wallet responsibility |
| --- | --- | --- |
| Enrollment | Validate and freeze the selected protection tier and Spending preset, consume an invitation, verify the passkey ceremony, derive the tenant VaultCosigner, and persist the immutable descriptor. | Choose a protection tier and Spending preset, create the device credential and permitted keys, reconstruct and review the proposed descriptor, and retain encrypted recovery material when applicable. |
| Spending | Authenticate and reserve policy VTXOs, enforce the rolling allowance and fee cap, validate the complete Arkade transaction and checkpoints, sign, and reconcile an ambiguous response by operation ID. | Persist the operation, phone-sign the reservation, confirm the quoted fee, obtain device authorization, coordinate the Operator exchange, finalize, and post the receipt. |
| Savings | Rebuild and verify the L1 Savings program when authorizing a recovery transition. | Construct and sign Savings transfers with the device and hardware keys. The server does not publish them. |
| Recovery | Authorize `initiate` and `clawback` transitions, verify passkey sessions, and store authenticated encrypted map data. | Hold claimant and guardian keys, broadcast transitions, and claim after the committed delay. |

Spending uses `vault-policy-v1`. Its collaborative leaf requires the user,
VaultCosigner, and Arkade Operator. Savings remains an L1 vault and has no
routine path that the VaultCosigner can use to pay an arbitrary recipient.

The VaultCosigner key and ledger intentionally share one protected process.
Separating the key from the authoritative allowance would create a path that
could sign without observing the policy state.

## VTXO lifecycle

A Spending send is one durable operation, not a collection of unrelated HTTP
requests:

1. The wallet persists a client-generated operation ID, signs the canonical
   operation ID, vault, purpose, destination script, and amount with the phone
   key, then calls `reserve`. The server verifies that proof before selecting
   and locking VTXOs and debiting the rolling allowance. An exact retry returns
   the original reservation.
2. `authorize` validates the unsigned checkpoints, user-signed Arkade PSBT, and
   a canonical phone-signed pending-transaction proof for the exact reserved
   inputs. It adds the VaultCosigner signature to the Arkade transaction and
   proof, then stores both before returning them.
3. The wallet submits the operation to the Operator once. If the response is
   ambiguous, it presents the dual-signed proof through the official pending-
   transaction interface and accepts only the exact Arkade transaction and
   checkpoints recorded by the reservation.
4. `checkpoints/authorize` requires those checkpoints to match the stored
   operation and adds the VaultCosigner checkpoint signatures.
5. `finalize` verifies that the authorized Arkade transaction spent the
   reserved VTXOs. `GET /v1/vtxo/operation` lets the wallet recover ambiguous
   Vault-service responses. Operator submission recovery uses the deployed
   pending-transaction interface, which makes a second `submitTx` call
   ineligible.

The current Mutinynet slice accepts between one and 50 canonical inputs and a
`tark` destination for the same release-pinned Operator. It supports exact
no-change sends and the Operator's bounded intent fee policy. It does not
silently fall back to an onchain send or VTXO offboarding. See
[the Spending contract](docs/vault-policy-v1-spend.md).

## Boarding boundary

`vault-board-v1` is the only boarding program. Its cooperative leaf requires a
wallet-worker boarding key, a distinct VaultBoardCosigner, and the pinned
Arkade Operator. The phone key is reserved for recovery after the enrolled CSV
delay; routine boarding does not prompt for Face ID.

The official Arkade SDK owns discovery, intent construction, persistence,
retries, and settlement. The service verifies and submits four exact SDK phases
without returning its signature or replacing the SDK lifecycle. One confirmed
input may settle only into the enrolled `vault-policy-v1` Spending contract.
See [the boarding contract](docs/boarding.md).

Boarding principal does not debit the rolling allowance. The ordinary Spending
policy applies when the resulting VTXO pays another destination. Mainnet
parameters remain a separate release decision.

## HTTP surface

Mutation routes require JSON, the exact configured `Origin`, and the gateway
secret header. Unknown JSON fields are rejected. The gateway secret protects
the private service boundary; passkeys and transaction signatures provide user
authorization.

Tenant read routes are also behind the gateway, but currently use the random
vault ID as their capability; operation recovery additionally requires the
random operation ID. Request logs emit only a hashed vault tag. Mainnet must
explicitly qualify that privacy boundary or add a purpose-bound read session
without breaking fresh-device recovery and lost-response recovery.

| Route | Purpose |
| --- | --- |
| `GET /health` | Process liveness only. |
| `GET /ready` | Database and release-pinned signer/resolver readiness. |
| `GET /v1/status` | Public service status or one vault's status with `?vault=`. |
| `GET /v1/invite` | Invitation availability. |
| `POST /v1/enroll/start` | Freeze the protection tier and canonical policy digest, reserve a vault ID, and return the create-ceremony challenge. |
| `POST /v1/enroll/propose` | Return the Savings and `vault-board-v1` descriptors for wallet review. |
| `POST /v1/enroll/finish` | Verify the complete enrollment and consume the invitation. |
| `POST /v1/vtxo/board/prepare` | Reconcile and prepare one exact boarding attempt. |
| `POST /v1/vtxo/board/register` | Verify, cosign, and submit the exact registration intent. |
| `POST /v1/vtxo/board/release` | Verify, cosign, and submit release of a retained prior intent. |
| `POST /v1/vtxo/board/final` | Verify and submit the SDK-validated final commitment artifacts. |
| `POST /v1/vtxo/reserve` | Authenticate and create an immutable VTXO operation. |
| `POST /v1/vtxo/authorize` | Validate and sign the Arkade transaction and its pending-transaction recovery proof. |
| `POST /v1/vtxo/checkpoints/authorize` | Validate and sign Operator checkpoints. |
| `POST /v1/vtxo/finalize` | Verify the recorded spend and finalize the operation. |
| `GET /v1/vtxo/operation` | Read one operation for retry reconciliation. |
| `POST /v1/initiate` | Authorize a Savings-to-Pending recovery transition. |
| `POST /v1/clawback` | Authorize a Pending-to-Quarantine transition. |
| `POST /v1/passkey/challenge` | Issue a purpose-bound passkey challenge. |
| `POST /v1/passkey/binding` | Build the authenticated Recovery Kit binding. |
| `POST /v1/passkey/install` | Install a passkey credential envelope. |
| `POST /v1/passkey/recover` | Recover a passkey credential envelope. |
| `GET`, `POST /v1/map` | Read or write authenticated encrypted Recovery Kit map data. |

The boarding phase routes use release-pinned public Operator and Esplora adapters;
they accept no runtime origin override. Savings broadcast and ordinary
Spending submission remain wallet responsibilities.

## Persistence and failure handling

The v2 database starts at schema version 1 and accepts no other nonempty
schema. Every new economic-outflow reservation also advances an authenticated
policy sequence outside SQLite. Startup fails when the database is behind that
sequence.

The database and policy sequence require independently controlled storage,
permissions, backup jobs, and restore decisions. Two paths or two named volumes
under one restore authority leave a single failure domain. Losing sequence
persistence is a fail-closed event and never permits recreation from a database
backup.

The current Railway Mutinynet deployment does not meet that topology: both
files share one volume and restore authority. Its sequence detects
database-only rollback or sequence loss, but not restoration of the whole
volume. This is an accepted Mutinynet limitation, not mainnet evidence.

Allowance evaluation authenticates ledger rows before trusting their state or
time. The current implementation therefore has a bounded-history mainnet gate:
load tests must establish an operational ledger limit, or an authenticated
accumulator must replace the unbounded scan.

## Run the Mutinynet candidate

Create the two file-backed secrets, then configure the private service origin:

```bash
install -d -m 700 ./secrets
umask 077
openssl rand -hex 32 > ./secrets/vault-cosigner-key
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n' > ./secrets/enrollment-token
chmod 0600 ./secrets/*

cp .env.example .env
# Set VAULT_CLIENT_ORIGIN, VAULT_RP_ID, and VAULT_GATEWAY_SECRET.
docker compose up -d --build
```

Check liveness and readiness separately:

```bash
curl -fsS http://127.0.0.1:8788/health
curl -fsS http://127.0.0.1:8788/ready
```

Route wallet traffic only after readiness succeeds. Keep the
VaultCosigner scalar and enrollment token in `0600` files. Replacing the token
file provisions one additional invitation on the next restart; reusing the
same token is idempotent. Hosted
deployment may materialize them from the platform secret store at entrypoint,
then remove the raw values from the process environment before starting the
server.

## Mainnet release gates

The complete gate and operations posture are recorded in
[docs/mainnet-v2-baseline.md](docs/mainnet-v2-baseline.md) and
[deploy/ops.md](deploy/ops.md). The confirmed mainnet Emulator discovery
endpoint is `https://mainnet-signer.invalid/v1/info`, whose advertised signer matches the
official SDK pin. The release uses `arkade.computer` and the official Arkade
SDK as deployed; it does not require a modified `arkd` or a Vault-specific
Operator API. Mainnet configuration must pin and qualify the deployed Emulator
and Operator identities, checkpoint policy, delays, and fee bounds before the
Contract Packs are regenerated. The supported policy schema and bounds must be
reviewed as release parameters; individual vaults may then choose any valid
instance during enrollment.

Ordinary VTXO send and boarding still require live qualification against
`arkade.computer`, along with the documented storage, rate-limit, and hardware
checks. Outbound Lightning uses the wallet's published swap-package adapter;
its funding transaction is an ordinary VTXO send, so this service adds no
Lightning endpoint or schema. Invoice, quote, solver, refund, and live-payment
qualification remain wallet release gates.

## Repository map

| Path | Responsibility |
| --- | --- |
| `cmd/authorizer` | Process configuration and shutdown. |
| `internal/authorizer` | Protected runtime assembly, secrets, ledger, and release-pinned adapters. |
| `internal/application` | Enrollment, VTXO, Savings transition, and recovery workflows. |
| `internal/policy` | Fresh ledger, authenticated records, allowance, and policy sequence. |
| `internal/vault` | L1 Vault Program scripts and transaction verification. |
| `internal/iface/http` | Constrained HTTP adapter. |
| `contract-pack.json` | Versioned names and parameters shared with the wallet. |

Run the full checks with Go 1.26.6:

```bash
go test ./... -count=1
go vet ./...
go test -race ./internal/policy ./internal/application ./internal/authorizer -count=1
```

Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.
