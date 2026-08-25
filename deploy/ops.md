# Arkade Runtime operations

This runbook covers the Mutinynet `arkade-vault-v1` profile at audited source
`36cde909cc2ed745fef3efd4ecafc4371cfd8298`. It defines a coherent recovery
decision for the authenticated SQLite database and the independent policy
sequence without changing their schema, bytes, KDF domains, or runtime paths.
It does not authorize a mainnet deployment or a migration from another
database.

## State and recovery boundary

One Runtime instance owns two durable artifacts:

- `VAULT_DB_PATH=/app/data/vault.sqlite`
- `VAULT_POLICY_SEQUENCE_PATH=/app/sequence/policy-sequence`

SQLite stores authenticated tenant, recovery, map, and economic-outflow rows.
The policy-sequence file independently authenticates the number of durable
economic-outflow reservations. Runtime startup rejects a database behind the
sequence, a missing sequence for nonempty policy state, or a sequence with the
wrong MAC.

A recovery snapshot packages copies of both files with one manifest. They are
one restore unit: never select the database from one unit and the sequence from
another. The files remain independent inside the unit so the verifier can
compare their authenticated counts.

Restoring a matched older database and sequence can still defeat the in-process
rollback check. Store each accepted manifest digest and policy-sequence high-
water mark in an access-controlled system outside the restore unit. A restore
approval must compare the candidate with that record. The verifier detects
mismatched or modified artifacts; it cannot detect an administrator who rolls
back the entire unit and its external evidence together.

## Offline state tool

Build the operator tool from its reviewed operations revision and record that
revision separately from the Runtime source and image identity:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -o ./bin/runtime-state ./cmd/runtime-state
file ./bin/runtime-state
sha256sum ./bin/runtime-state
```

The build target must match the maintenance host reported by `uname -m`.
Railway reported `x86_64` during the disposable drill; an ARM64 verifier was
rejected before state access. Record the target architecture with the verifier
source commit and binary digest.

`runtime-state` has no network or signing route. It loads the file-backed
VaultCosigner only long enough to derive the existing record-integrity key,
then wipes both from memory. It never prints either value. The tool:

- validates the exact schema and SQLite quick/foreign-key checks;
- verifies every MAC-protected database row;
- authenticates the policy sequence without advancing it;
- requires the sequence and economic-outflow counts to match exactly;
- binds both artifact digests, the Contract Pack, source commit, and image
  digest in `manifest.json`;
- rejects symlinks, group/world-readable state, unknown unit files, release
  mismatches, and restore attempts without explicit stopped/replacement
  acknowledgements.

The three commands emit only the key-free manifest. Protect the output unit as
user-sensitive operational data even though it contains no plaintext signing
key. The manifest's `sourceCommit` identifies the Runtime binary whose state
was captured; it does not identify the verifier binary. Record the verifier's
source commit and binary digest beside every operator approval.

## Snapshot procedure

1. Record the active deployment ID, full source commit, immutable image digest,
   `/ready` body, database path, sequence path, volume identity, aggregate state
   counts, verifier source commit, and verifier binary digest.
2. Drain wallet traffic at the edge. Confirm the request count is zero, stop
   every Runtime replica, and confirm no process has either state file open.
3. Confirm the database has no `-journal`, `-wal`, or `-shm` sidecar. A clean
   shutdown and the absence of sidecars are mandatory. The command refuses a
   sidecar, and operator review must establish whether it contains committed
   state.
4. Create a private parent directory on the backup staging filesystem.
5. Run one snapshot command with the release identity read back from the
   platform:

```bash
install -d -m 0700 /secure/runtime-snapshots
./bin/runtime-state snapshot \
  --db /app/data/vault.sqlite \
  --policy-sequence /app/sequence/policy-sequence \
  --vault-cosigner-key-file /run/secrets/vault-cosigner-key \
  --output /secure/runtime-snapshots/arkade-runtime-20260826T010203Z \
  --source-commit 36cde909cc2ed745fef3efd4ecafc4371cfd8298 \
  --image-digest sha256:<audited-image-digest> \
  --service-stopped
```

6. Copy the completed directory to encrypted backup storage without changing
   its three files. Record the manifest digest and policy-sequence count in the
   independent recovery evidence system.
7. Run `runtime-state verify` from a separate operator context before declaring
   the snapshot usable. Restart the same image only after verification passes,
   then require both `/health` and `/ready` before restoring traffic.

A failed snapshot is not a restore unit. Remove its private staging directory
after reviewing the error, correct the cause, and start again with a new output
name.

## Restore procedure

Practice restores on a new disposable service, volume, and hostname. A
production restore requires an incident record, two-person approval for the
state decision, and a separately approved use of the existing VaultCosigner
secret.

1. Keep the target stopped and unrouted. Record its service, environment,
   volume, source commit, and intended immutable image digest.
2. Select one complete state unit. Compare its manifest digest and policy
   sequence with the external high-water record. A candidate below the latest
   accepted record requires an explicit data-loss decision; a candidate above
   the record requires incident review before the evidence system is updated.
3. Verify before writing:

```bash
./bin/runtime-state verify \
  --unit /secure/runtime-snapshots/arkade-runtime-20260826T010203Z \
  --vault-cosigner-key-file /run/secrets/vault-cosigner-key \
  --expected-source-commit 36cde909cc2ed745fef3efd4ecafc4371cfd8298 \
  --expected-image-digest sha256:<audited-image-digest>
```

4. Restore both artifacts in one stopped maintenance action:

```bash
./bin/runtime-state restore \
  --unit /secure/runtime-snapshots/arkade-runtime-20260826T010203Z \
  --db /app/data/vault.sqlite \
  --policy-sequence /app/sequence/policy-sequence \
  --vault-cosigner-key-file /run/secrets/vault-cosigner-key \
  --expected-source-commit 36cde909cc2ed745fef3efd4ecafc4371cfd8298 \
  --expected-image-digest sha256:<audited-image-digest> \
  --service-stopped \
  --replace
```

The command stages both files before replacement, preserves the prior files
until the new pair verifies, and rolls the first replacement back if the
second or final authenticated check fails. Any error keeps the service stopped.
A failed attempt requires a new restore command covering both artifacts;
manual one-artifact copy is forbidden.

5. Run `verify` again against the installed paths or capture a new key-free
   verification report. Confirm schema version, authenticated row counts, and
   exact policy count against the manifest.
6. Start the exact manifest-bound image. Require startup success, `/health`
   `200 ok`, `/ready` `ok: true`, the expected network and release pins, and
   aggregate state counts matching the manifest before routing traffic.
7. Exercise read-only status and one synthetic, non-fund-bearing workflow in a
   disposable drill. Production recovery testing uses synthetic state and
   avoids transaction creation or funds broadcast merely to prove storage
   recovery.

## Required failure drills

Run these only with disposable copies and a disposable Runtime service:

| Drill | Expected result |
| --- | --- |
| Matched database and sequence from one verified unit | Offline verification and exact-image startup succeed. |
| Database from an earlier point with the current authenticated sequence | Verifier rejects a rolled-back database; exact Runtime startup fails closed. |
| Current database with an earlier or missing sequence | Verifier rejects a rolled-back or missing sequence. Restore acceptance requires an equal pair before Runtime startup. |
| Sequence bytes or database authenticated row modified | MAC or artifact-digest verification fails. |
| Manifest source commit, image digest, Contract Pack, or artifact digest changed | Verification fails before target replacement. |
| Wrong VaultCosigner key | Database/sequence authentication fails; never substitute a new key. |
| Exact-image rollback after a failed candidate deployment | Platform returns to the recorded image digest; state is restored only from a separately verified compatible unit. |

The normal Runtime may advance a sequence that is behind a newer database
after a crash-safe reservation path. Disaster recovery is stricter:
`runtime-state verify` requires equality and refuses to reinterpret a stale
sequence as a crash. This prevents a restore operator from silently converting
a rollback into a repair.

## Image rollback

Source rollback and state rollback are separate approvals. Platform rollback
must select a deployment whose immutable image digest was previously recorded.
A moving-branch rebuild is outside rollback. Confirm the digest afterward.
Binary rollback across a schema or Contract Pack boundary requires a reviewed
compatible state unit and migration posture.

For the current candidate, rollback qualification uses source
`36cde909cc2ed745fef3efd4ecafc4371cfd8298` and its recorded Railway image
digest. A source-upload message is supporting evidence; the image digest and
clean Git-tree record remain authoritative.

Railway's `redeploy` action can rebuild identical source under a new image
digest. Exact-image rollback selects a prior deployment whose `canRollback`
field is true, verifies its recorded image digest, and invokes Railway's
deployment rollback for that exact ID:

```bash
railway api \
  'mutation Rollback($id: String!) { deploymentRollback(id: $id) }' \
  --raw-var id=<reviewed-deployment-id> \
  --compact
```

The resulting deployment must report `reason=rollback`, the selected immutable
digest, successful health and readiness checks, and authenticated state counts
matching the accepted manifest. A successful Railway `redeploy` is insufficient
when its digest differs.

## Credential rotation

### Gateway secret

The Runtime accepts one gateway secret and has no dual-secret window. Drain
traffic, generate the replacement in a protected secret manager, update the
Runtime and trusted edge/injector under one maintenance action, restart the
same image, and validate an authenticated read without logging headers. Keep
the old value only in the secret manager's recoverable version history until
the new path is confirmed, then revoke it. Alert on unexpected `401` responses
during and after the cutover.

### Enrollment invitation

There is no HTTP invitation-minting route. Replace the protected enrollment
token file or platform variable with one 32-byte base64url token and restart.
Startup provisions exactly one new single-use invitation and is idempotent when
the same token is presented again. Verify aggregate invitation count, expiry,
and unused status without logging the token. Expired or consumed invitations
remain historical rows. Rotation uses the supported startup flow; direct SQLite
editing is forbidden.

### VaultCosigner

In-place VaultCosigner rotation is unsupported. The scalar determines signing
keys and the existing database/sequence MAC key. A replacement key cannot open
the existing state and must never be used as a recovery shortcut. Preserve the
same secret for disaster recovery under separate access controls. A future key
migration requires a separately designed protocol and is outside this release.

## Monitoring and alert gates

Route traffic only while `/ready` reports the expected schema, Mutinynet,
enrollment template, Operator/Emulator origin, and release version. `/health`
is liveness only.

Alert without recording secrets or user payloads when any of these occur:

- startup or restart failure containing schema, Contract Pack, MAC, policy-
  sequence, Operator identity, Emulator identity, or readiness errors;
- `/ready` failure, release-pin drift, unexpected restart count, or image-digest
  drift;
- database/sequence permission change, missing file, filesystem saturation,
  SQLite integrity error, or sequence temporary-file residue;
- snapshot verification failure, snapshot age beyond policy, failed offsite
  copy, or disagreement with the external policy-count high-water record;
- sustained `401`, `403`, `429`, or `5xx` rates, readiness latency, or shared
  edge-rate-limit failure for challenge issuance and VTXO reservation;
- unresolved/signed operation age outside the documented reconciliation
  window, reported only as aggregate counts and ages.

Retain deployment IDs, immutable image digests, manifest digests, aggregate
counts, timestamps, verifier versions, and operator approvals. Never retain
gateway headers, invitation tokens, private keys, passkey assertions, PSBTs,
map payloads, or row-level wallet data in operational logs.

## Release checks

Before publishing or deploying an operations change, run Go 1.26.6:

```bash
go test ./... -count=1
go vet ./...
go test -race ./internal/policy ./internal/application ./internal/authorizer ./internal/operations -count=1
```

Then run the matched, mismatched, and exact-image rollback drill in an isolated
Mutinynet environment. Remove the disposable service, volume, hostname, and
secrets afterward. Record that deletion is permanent and whether the platform
retains delayed-deletion tombstones.
