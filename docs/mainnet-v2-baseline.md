# Mainnet v2 baseline

This branch is a fresh service, not a migration release. It accepts a new
mainnet database and new vault enrollments only. Mutinynet databases, vault
identifiers, allowance rows, keys, and contract packs are not imported.

## Service boundary

The process contains five application modules:

- `enrollment`: invitations, passkeys, and immutable Vault Program creation;
- `spending`: VTXO reservations, policy authorization, submission recovery,
  and receipts;
- `savings`: onchain transaction construction and the device-plus-hardware
  signing ceremony;
- `recovery`: Recovery Kit map storage and staged recovery authorization;
- `platform`: SQLite, WebAuthn, HTTP, Bitcoin data, and Arkade Operator
  adapters.

The VaultCosigner key and authoritative policy ledger remain in the same
protected process. Narrow application interfaces prevent access through a
shared mutable service object.

## Persistence

The mainnet database begins at schema version 1 with the complete mainnet table
set. Startup creates an empty schema or opens that exact schema. It rejects any
other non-empty database before changing it.

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
an explicit state machine. An ambiguous response is reconciled by reading that
operation. A client retry cannot allocate a second allowance or reuse an input.

Every newly reserved economic outflow, whether an onchain issuance or a VTXO
operation, also advances an authenticated sequence outside SQLite. Startup
refuses a database whose durable outflow count is behind that sequence. The
database and sequence must use separate durable volumes and separate restore
decisions. Restoring both to the same earlier point defeats rollback detection.

## Release gates

Ordinary VTXO transfers and boarding ship before Lightning. Outbound BOLT11
Lightning is a separate durable saga binding the payment request, quote,
solver, amount, fees, expiry, VHTLC, and policy refund destination. Lightning
receive is a different program and release gate.

Mainnet code remains fail-closed until the Operator origin, network identity,
signer keys, supported versions, delay units, fee bounds, and rotation policy
are frozen. The arkd intent lifecycle corrections and Redis concurrency tests
must be upstream and deployed before boarding is enabled.

The resolver is startup-critical for the VTXO-first release. Readiness requires
the exact release-pinned Operator signer and checkpoint unroll closure. Remote
GetInfo data cannot change the checkpoint key, closure type, or CSV delay that
the VaultCosigner will authorize.
