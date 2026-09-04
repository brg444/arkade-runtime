# Mainnet v2 baseline

Vaulted Guardian begins with a fresh v2 service and database. The executable
remains Mutinynet-only until the mainnet pins and release gates in this document
close. Mainnet does not import Mutinynet databases, vault identifiers,
allowance rows, keys, or contract packs.

## Service boundary

The product boundary contains five workflows:

- `enrollment`: invitations, passkeys, and immutable Vault Program creation;
- `spending`: VTXO reservations, policy authorization, submission recovery,
  and receipts;
- `savings`: verification of the L1 Savings descriptor and delayed recovery
  transitions;
- `recovery`: Recovery Kit map storage and staged recovery authorization;
- `platform`: SQLite, WebAuthn, HTTP, Bitcoin data, and Arkade Operator
  adapters.

The VaultCosigner key and authoritative policy ledger remain in the same
protected process. Narrow application interfaces prevent access through a
shared mutable service object.

## Persistence

The v2 database begins at schema version 1 with the complete table set. Startup
creates an empty schema or opens that exact schema. It rejects any other
non-empty database before changing it.

Future schema changes use small forward migrations from this baseline only.

## API

Routes are grouped by enrollment, Spending, Savings, and recovery. HTTP
handlers decode and encode; application services enforce workflows; domain
packages validate complete transactions independently. The API exposes no raw
signing endpoint.

Every mutating operation has one durable identifier, one canonical digest, and
an explicit state machine. The wallet persists its VTXO operation ID before
requesting a reservation and authenticates the canonical reservation with the
phone key. An ambiguous Vault-service response is reconciled by reading that
operation. Before the first Operator submission, `authorize` persists a
phone-and-VaultCosigner proof bound to the exact reserved inputs. The wallet
submits once, then uses the deployed pending-transaction interface after an
ambiguous response. An exact client retry cannot allocate a second allowance
or reuse an input.

Every newly reserved VTXO outflow also advances an authenticated sequence
outside SQLite. Startup
refuses a database whose durable outflow count is behind that sequence. The
database and sequence must use independently controlled durable storage,
permissions, backups, and restore decisions. Separate paths or named volumes
under one authority fail to establish independent failure domains. Restoring
both to the same earlier point defeats rollback detection.

The recovery envelope uses `arkade-vault/recovery-binding/v4`. Its signed
preimage includes the authenticated credential, complete Savings descriptor,
the selected protection tier, and every immutable Spending and boarding field.
The server rebuilds those fields from its release-pinned program and enrolled
policy when it creates or installs the binding; substituted or incomplete
descriptors fail closed.

## Release gates

Ordinary VTXO transfers and boarding must stabilize before Lightning. Outbound
BOLT11 delegates invoice, RFQ, VHTLC, and contract-registration semantics to
the published swap package in the wallet. Funding is an ordinary VTXO transfer
to the package-verified lockup address, so this service applies its existing
allowance and transaction policy without Lightning-specific routes, schema, or
signing logic. Lightning receive is a different program and release gate.

Mainnet uses `https://arkade.computer` and the official Arkade SDK as existing
dependencies. Vault code must stay within the deployed `getInfo`, indexer,
`submitTx`, `finalizeTx`, and pending-transaction interfaces. Vault-specific
changes to `arkd`, exact intent-release endpoints, replayable event streams,
and private Operator lifecycle state are outside the deployment boundary.

The confirmed mainnet Emulator discovery endpoint is
`https://emulator.arkade.computer/v1/info`. Its
advertised signer,
`0239c196415da47b26456a101daaa12ba9e445bfe153197f1e2b750bf40e52092e`,
matches the official SDK pin. Mainnet remains fail-closed until that identity
and the deployed Operator origin, network identity, signer keys, checkpoint
policy, delay units, fee bounds, and rotation policy are qualified and pinned
in both Contract Packs.

The compiled Vault Program remains fixed. Each fresh vault selects Standard
without a recovery key or Advanced with a distinct recovery key, then selects
an immutable `vault-spending-policy-v1` instance during enrollment. The
current user controls are the per-payment cap and rolling 24-hour allowance;
the 5,000-sat and 10-sat/vB fee ceilings remain release-managed. Mainnet review
must approve these tiers, presets, and bounds before the Contract Pack is
frozen. No post-enrollment mutation or arbitrary policy execution is part of
this release.

The resolver is startup-critical for the VTXO-first release. Readiness requires
the exact release-pinned Operator signer and checkpoint unroll closure. Remote
GetInfo data cannot change the checkpoint key, closure type, or CSV delay that
the VaultCosigner will authorize.

## Boarding programs

`vault-board-v1` is the only boarding program. It requires a worker-owned board
key, a distinct VaultBoardCosigner, and the pinned Arkade Operator for
cooperative boarding. The service verifies the exact fixed Spending recipient,
fees, registration proof, Batch Output expiry, commitment tree, and final
artifacts. It submits only through the stock public Operator routes and never
returns its signature. The phone-only 604672-second recovery leaf remains
available after the cooperative window closes.

The lifecycle records authorization, dispatch, and known Operator outcomes.
An unacknowledged submission remains ambiguous, while a retained intent must be
released before another registration attempt. Live response-loss, reload,
worker wake, retained-intent, and CSV-cutoff qualification remain mainnet gates.
Mainnet also requires a reviewed per-device board-key registration and
revocation policy. The Mutinynet key model is not a mainnet release pin.

## Ordinary Spending qualification

The Mutinynet implementation supports up to 50 canonical VTXO inputs, optional
change, and the Operator's bounded intent fee policy. Reservation digests bind
every input, the exact fee-policy digest and fee, and the optional change
shape. Both signing stages reject fee-policy drift.

Mainnet qualification covers fragmented balances, exact no-change sends,
nonzero and amount-dependent fees, reloads, dropped responses, ambiguous
Operator submissions, empty and mismatched pending lookups, checkpoint
reordering, and concurrent attempts against `arkade.computer`.

The client-generated operation ID closes lost reserve responses, the phone
signature prevents a caller who only knows a vault ID from creating a
reservation, and server state transitions use compare-and-swap updates. Edge
rate limiting remains necessary for load protection.

The current tenant read routes remain behind the shared gateway but use the
random vault ID as their capability; operation recovery additionally requires
the random operation ID. Application logs record only a hashed vault tag. A
mainnet release must either qualify this privacy boundary explicitly or add a
purpose-bound read session without breaking fresh-device Recovery Kit and
lost-response reconciliation flows.

## Availability boundaries

Passkey challenge issuance is intentionally possible before tenant
authentication. The application-level pending cap is not denial-of-service
protection. Mainnet traffic remains blocked until the production edge enforces
a shared, durable rate limit by client address and vault identifier across all
instances for passkey challenges and VTXO reservation. The in-memory gateway
bucket is only a local development guard.

Allowance evaluation MAC-verifies every row before using its state or time.
Predicates over unauthenticated fields could hide a debit and therefore cannot
bound this scan safely. Mainnet load testing must establish a supported ledger
bound, or the ledger must gain an authenticated accumulator before that bound
is exceeded.

The indexer adapter paginates spendable VTXOs through the deployed response
contract and fails closed above 3,200 results. Submitted-operation recovery
uses the official exact-outpoint filter for at most 50 reserved inputs plus the
expected change output, avoiding a full script-history scan.

Wallet send and boarding locks depend on the browser Web Locks API and fail
closed when it is absent. Mainnet qualification must define the supported
browser boundary and cover deterministic two-context race tests.

Hardware and recovery signing use external PSBT exchange. Mainnet qualification
must prove that supported devices preserve the custom tapscript fields and
sign the intended leaves without exposing private keys to the browser.

## Deployment gates

The database and authenticated policy sequence require separate storage
permissions, backup jobs, restore authorities, and failure drills. Deleting a
nonempty deployment's sequence file is fatal. Restoring the database and
sequence together to an earlier point defeats rollback detection.

The current Railway Mutinynet service deliberately falls short of this gate:
its database and sequence share one volume and backup/restore authority. That
topology may be used for test funds only and cannot be promoted to mainnet.

The Mutinynet 4,608-second guardian delay is not a mainnet pin. Mainnet tree
vectors and both Contract Packs must be regenerated from the deployed Operator
identity, qualified Emulator signer, and reviewed mainnet parameters.

The current Go module replaces the official Emulator signing package with a
narrow fork that adds packet-entry binding, previous-output bounds, and scalar
edge-case checks. Mainnet distribution requires those checks in a reviewed
official Emulator release, followed by removal of the private module replace.
This package gate does not require or authorize any change to `arkd`.

The server repository also requires an explicit distribution license before a
public mainnet release.

## Current qualification evidence

The release branch passes the full Go test suite, full race suite, `go vet`,
and `govulncheck`. The allowance benchmark records approximately 1.1 ms for 100
authenticated historical rows, 16 ms for 1,000 rows, and 115 ms for 10,000 rows
on an Apple M1. These measurements confirm linear work and keep the supported
history bound open until deployment load tests establish the initial limit.

On August 23, 2026, `https://arkade.computer/v1/info` reported network
`bitcoin`, version `v0.9.16-rc.11`, signer
`038202...779c`, a 605,184-second unilateral exit delay, and a 200-sat onchain
output intent fee. These are observed compatibility facts, not release pins.
The final manifest must capture and verify the complete values immediately
before Contract Pack generation.

On September 4, 2026, the candidate pin check observed Operator version
`v0.9.16` with the same signer, forfeit key, checkpoint tapscript, and delays,
and Emulator version `v0.0.7` with signer
`0239c196415da47b26456a101daaa12ba9e445bfe153197f1e2b750bf40e52092e`.
The current mainnet profile freezes those identities and rejects drift. Real
traffic still requires the independent-storage and shared-edge declarations,
plus external audit evidence that those controls are actually provisioned.
