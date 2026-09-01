# `vault-board-v1`

`vault-board-v1` is the sole program for moving confirmed Bitcoin into the
enrolled `vault-policy-v1` Spending contract. The official Arkade SDK owns
input discovery, intent construction, Batch Output participation, persistence,
retries, and settlement. The Vault service supplies a narrow policy and
cosigning adapter for this named program.

There is no boarding selector, legacy compatibility path, or alternative
enrollment flow. A fresh vault enrolls Savings and boarding together through
`/v1/enroll/propose` and `/v1/enroll/finish`.

## Program

The cooperative leaf requires three distinct keys:

1. the wallet worker's scoped boarding key;
2. the tenant VaultBoardCosigner;
3. the release-pinned Arkade Operator signer.

The recovery leaf is the enrolled phone key behind a 604672-second CSV delay.
The wallet and service reconstruct the exact tree independently from the
enrollment record and release pins. A changed key, role, delay, script, address,
or destination fails before signing. Routine boarding does not use or unlock
the phone key.

The Mutinynet release accepts one confirmed boarding input and one BTC
recipient. That recipient must be the enrolled `vault-policy-v1` Spending
address. Boarding principal does not debit the rolling allowance. A later
payment from the resulting VTXO uses ordinary Spending authorization and the
allowance ledger.

## Phase boundary

The service exposes four program-specific mutation routes:

| Route | Result |
| --- | --- |
| `POST /v1/vtxo/board/prepare` | Verifies the confirmed outpoint, recovery window, exact recipient, fee, current attempt, and chain facts. Returns an authenticated short-lived handle. |
| `POST /v1/vtxo/board/register` | Verifies the SDK registration proof, adds the VaultBoardCosigner signature, and submits the exact intent through the stock public Operator API. |
| `POST /v1/vtxo/board/release` | Verifies and cosigns the SDK deletion proof for a retained prior attempt, then submits it through the stock public Operator API. |
| `POST /v1/vtxo/board/final` | Verifies the SDK-validated Batch Output expiry, commitment, tree, forfeits, input indexes, and exact Spending recipient before submitting the final artifacts. |

The service never returns a VaultBoardCosigner signature. It records the
authorization, outbound dispatch, and known Operator outcome so a lost HTTP
response cannot create a second authoritative attempt. An unknown outcome
remains ambiguous. The SDK retries by asking `prepare` again; the service may
return the exact finalized commitment, require an acknowledged release, or
keep the input blocked.

Only stock public Operator routes are used: `registerIntent`, `deleteIntent`,
and `submitForfeitTxs`. The service does not require a modified `arkd`, private
Operator state, a replay endpoint, or a Vault-specific Operator deployment.

## Release pins

The Mutinynet release pins:

- Operator origin: `https://mutinynet.arkade.sh`;
- Operator signer: `03301078808e4f7bc0dadfe29e34b1df8eaf0108ef06b1722274075ebc107a127a`;
- Esplora origin: `https://mempool.mutinynet.arkade.sh/api`;
- Batch Output expiry: exactly 604672 seconds.

Startup installs the resolver, Operator identity, chain adapter, and expiry
policy before persisted vaults are loaded. `/ready` remains false when any pin
or dependency is unavailable.

## Persistence and recovery

Enrollment, operation, authorization, dispatch, and submission rows are
authenticated. Every new authorization, dispatch, or submission mutation also
advances the external policy sequence. Database and sequence backup and restore
remain independently controlled; restoring both to an earlier point defeats
rollback detection.

The cooperative path closes when the Bitcoin median-time-past threshold reaches
the recovery delay. After that cutoff, the service refuses new cooperative
authorization and the phone recovery leaf is the valid path. Mutinynet release
qualification must exercise both sides of the cutoff.

## Qualification

Deployment remains blocked until a fresh vault passes enrollment, onchain
receive, Savings-to-Spending, reload, worker wake, offline recovery, response
loss at every phase, retained-intent release, exact final reconciliation,
balance and activity convergence, and recovery after the CSV cutoff. Mainnet
parameters and per-device worker-key registration remain separate release
decisions.
