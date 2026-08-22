# Arkade Vault Server

> [!WARNING]
> This branch is the mainnet v2 refactor, not a production custody service.
> The current binary remains pinned to Mutinynet while mainnet
> identities, delays, and upstream lifecycle fixes are reviewed. Its
> VaultCosigner key is file-backed, without hardware isolation. Real-fund use
> remains blocked.

Arkade Vault Server is the protected policy and signing service for
[Arkade Wallet Vault](https://github.com/brg444/arkade-wallet-vault). It owns
the VaultCosigner key and the authoritative policy ledger. It does not build a
general wallet, broadcast arbitrary transactions, or expose a raw signing API.

The wallet and server independently validate the same versioned Vault Program.
The server may add a VaultCosigner signature only after the complete operation
matches that program and its stateful allowance. Bitcoin scripts and committed
transaction paths retain the structural spending and recovery constraints.

## Responsibilities

The service is organized around four product workflows:

| Workflow | Server responsibility | Wallet responsibility |
| --- | --- | --- |
| Enrollment | Consume an invitation, verify the passkey ceremony, derive the tenant VaultCosigner, and persist the immutable descriptor. | Create the device credential and keys, verify the proposed descriptor, and retain encrypted recovery material. |
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
2. `authorize` validates the unsigned checkpoints and user-signed Arkade PSBT,
   then adds the VaultCosigner signature to the Arkade transaction.
3. The wallet submits the operation to the Operator. The Operator rebuilds and
   signs the checkpoints.
4. `checkpoints/authorize` requires those checkpoints to match the stored
   operation and adds the VaultCosigner checkpoint signatures.
5. `finalize` verifies that the authorized Arkade transaction spent the
   reserved VTXOs. `GET /v1/vtxo/operation` lets the wallet resume after any
   ambiguous response.

The current Mutinynet slice accepts between one and 50 canonical inputs and a
`tark` destination for the same release-pinned Operator. It supports exact
no-change sends and the Operator's bounded intent fee policy. It does not
silently fall back to an onchain send, VTXO offboarding, or the retired
`/v1/draft` pipeline. See
[the Spending contract](docs/vault-policy-v1-spend.md).

## Boarding boundary

Boarding is coordinated by the wallet and SDK, not by an HTTP signing route in
this service. An onchain receive or Savings transfer first enters the distinct
`vault-board-v1` contract, then settles into `vault-policy-v1`.

That intermediate currently requires the phone and Operator, but not the
VaultCosigner. The rolling allowance begins only after settlement. A
compromised phone and Operator can therefore collude during the boarding
window. Boarding real funds is blocked until review either proves an
acceptable bound for that window or redesigns the intermediate so Vault policy
applies earlier.

## HTTP surface

Mutation routes require JSON, the exact configured `Origin`, and the gateway
secret header. Unknown JSON fields are rejected. The gateway secret protects
the private service boundary; passkeys and transaction signatures provide user
authorization.

| Route | Purpose |
| --- | --- |
| `GET /health` | Process liveness only. |
| `GET /ready` | Database and release-pinned signer/resolver readiness. |
| `GET /v1/status` | Public service status or one vault's status with `?vault=`. |
| `GET /v1/invite` | Invitation availability. |
| `POST /v1/enroll/start` | Reserve a vault ID and create-ceremony challenge. |
| `POST /v1/enroll/propose` | Return the descriptor for wallet review. |
| `POST /v1/enroll/finish` | Verify enrollment and consume the invitation. |
| `POST /v1/vtxo/reserve` | Authenticate and create an immutable VTXO operation. |
| `POST /v1/vtxo/authorize` | Validate and sign the Arkade transaction. |
| `POST /v1/vtxo/checkpoints/authorize` | Validate and sign Operator checkpoints. |
| `POST /v1/vtxo/finalize` | Verify the recorded spend and finalize the operation. |
| `GET /v1/vtxo/operation` | Read one operation for retry reconciliation. |
| `POST /v1/initiate` | Authorize a Savings-to-Pending recovery transition. |
| `POST /v1/clawback` | Authorize a Pending-to-Quarantine transition. |
| `POST /v1/passkey/*` | Challenge, bind, install, or recover a passkey envelope. |
| `GET`, `POST /v1/map` | Read or write authenticated encrypted Recovery Kit map data. |

There is no server publisher and no `VAULT_ESPLORA_URL` dependency. Savings
broadcast and Operator submission remain wallet responsibilities.

## Persistence and failure handling

The v2 database is a fresh schema. It does not import the Mutinynet
ledger, singleton credentials, or historical migration generations. Every new
economic-outflow reservation also advances an authenticated policy sequence
outside SQLite. Startup fails when the database is behind that sequence.

The database and policy sequence require independently controlled storage,
permissions, backup jobs, and restore decisions. Two paths or two named volumes
under one restore authority leave a single failure domain. Losing sequence
persistence is a fail-closed event and never permits recreation from a database
backup.

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
then removes the raw values from the process environment before starting the
server.

## Mainnet release gates

The complete gate and operations posture are recorded in
[docs/mainnet-v2-baseline.md](docs/mainnet-v2-baseline.md) and
[deploy/ops.md](deploy/ops.md). The release remains blocked by the boarding
trust window, live ordinary-send qualification, a mainnet-specific
guardian delay, upstream arkd/SDK intent lifecycle defects, independent
rollback-control storage, shared durable edge rate limiting, and the
authenticated ledger performance bound.

Ordinary VTXO send and recovery behavior must stabilize before boarding is
enabled. Both precede real-fund mainnet use. Lightning is a later durable saga
and cannot share the ordinary-send operation by adding optional fields.

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
