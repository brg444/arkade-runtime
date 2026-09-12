# Guardian security model

Guardian verifies complete, named operations before its scoped key capability
signs. It does not offer a raw-digest signing endpoint. Wallet proofs, passkeys,
enrolled scripts, external chain facts, and authenticated ledger state are
separate inputs to authorization.

## Signing authority

Cooperative Spending requires the owner, Guardian, and Arkade Operator.
Guardian enforces the enrolled per-payment, rolling allowance, and fee policy.
Bitcoin Script verifies its committed spending conditions, while the Guardian
maintains the rolling allowance ledger.

Ledger Savings authorizes named initiate and clawback transitions. Its scoped
Guardian key derives from the enrolled network and vault identity. The required
user signature and any phone proof commit the retained transaction, whose
inputs, outputs, fees, scripts and key origins are independently checked.

Finite delegated renewals retain owner-presigned authority for exact inputs,
receivers, fees, and deadlines. Guardian cannot sign a replacement generation
without new owner authorization. Persisted nonce transcripts and retained
candidate bytes prevent a retry from becoming a different signing request.

## State and privacy

The service authenticates ledger rows before trusting their content. An
independent sequence detects database state behind a previously observed
economic mutation. Restoring both stores to the same earlier point defeats
that comparison; separate paths alone are insufficient evidence of independent authority.
See [storage](storage.md).

Gateway credentials restrict the service boundary, while user proofs authorize
mutations. Capability-based reads also depend on private, unguessable wallet
and operation identifiers. Keep credentials, key material, and complete private wallet data out of request
logs.

Recovery archive sessions grant access to authenticated ciphertext. The server
cannot establish that a backup is decryptable, current, or contains a complete
Bitcoin exit graph. Clients must validate the public binding and recovered data.

## Availability

Uncertain transactions and renewal cleanup retain their input fences until
supported evidence establishes an outcome. A no-match response is not proof
that an Operator registration was never selected. Timeouts preserve existing signing authority and the fences on potentially
spent inputs.

Service failure can pause cooperative payments and new service-assisted
Savings recovery. Independent Bitcoin exits require the exact enrolled keys,
transaction paths, fees, and waiting periods. Previously captured authorization
applies only to its retained transaction.

The supplied process and Linux templates provide no TEE, remote-attestation,
or HSM guarantee. Root or process compromise can expose the signing key while
loaded. Host protection and storage administration are deployment properties.
Report defects through [SECURITY.md](../SECURITY.md).
