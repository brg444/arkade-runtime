# Mainnet v2 baseline

This branch defines a fresh v2 service and database. The executable remains
Mutinynet-only until the mainnet pins and release gates in this document close.
It never imports Mutinynet databases, vault identifiers, allowance rows, keys,
or contract packs into a later mainnet deployment.

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

Historical singleton credentials, v3-to-v9 transforms, `.pre-v4` and `.pre-v5`
backup generations, legacy cosigner modes, deprecated signer arrays, and
Mutinynet recovery rows are deleted from this branch. Future mainnet schema
changes use small forward migrations from this new baseline only.

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

## Release gates

Ordinary VTXO transfers and boarding must stabilize before Lightning. Outbound BOLT11
Lightning is a separate durable saga binding the payment request, quote,
solver, amount, fees, expiry, VHTLC, and policy refund destination. Lightning
receive is a different program and release gate.

Mainnet uses `https://arkade.computer` and the official Arkade SDK as existing
dependencies. Vault code must stay within the deployed `getInfo`, indexer,
`submitTx`, `finalizeTx`, and pending-transaction interfaces. Vault-specific
changes to `arkd`, exact intent-release endpoints, replayable event streams,
and private Operator lifecycle state are outside the deployment boundary.

The remaining unavailable external dependency is the private mainnet Emulator
endpoint. Mainnet code remains fail-closed until that endpoint is supplied and
the deployed Operator origin, network identity, signer keys, checkpoint policy,
delay units, fee bounds, and rotation policy are pinned in both Contract Packs.

Vault Program parameters and policy adjustments are deliberately deferred
until ordinary Mutinynet Spending and recovery are qualified. The current
cleanup retains the current Mutinynet policy values.

The resolver is startup-critical for the VTXO-first release. Readiness requires
the exact release-pinned Operator signer and checkpoint unroll closure. Remote
GetInfo data cannot change the checkpoint key, closure type, or CSV delay that
the VaultCosigner will authorize.

## Boarding trust assumption

The current boarding intermediate is a phone-plus-Operator contract. The
VaultCosigner and rolling allowance begin governing the value only after the
Operator settles it into `vault-policy-v1`. A compromised phone and Operator
can therefore collude during that interval. This is an explicit property of the
standard SDK boarding path and must remain visible in the release threat model.

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

The Mutinynet 4,608-second guardian delay is not a mainnet pin. Mainnet tree
vectors and both Contract Packs must be regenerated from the deployed Operator
identity and reviewed mainnet parameters after the Emulator endpoint is
available.
