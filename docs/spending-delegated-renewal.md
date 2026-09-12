# Native renewal for every Spending wallet

Guardian can execute finite owner-authorized renewals while the wallet is
closed. Light, Standard, and Advanced renew into their exact enrolled Spending
script, including the original delegate and recovery leaves. Shared Spending has one current program, with Savings absent or provided by Ledger. Savings scripts, withdrawal authority and retained key derivation remain unchanged.

The existing opt-in `VAULT_LIGHT_DELEGATION_ENABLED=true` (or
`--light-delegation-enabled=true`) enables the shared Spending API, using one scheduler and authenticated journal.
Its default remains false. `VAULT_LIGHT_ENABLED` independently controls new
Light enrollment. Enabling renewal requires qualification for every supported
Spending program; a Light-only funded test does not qualify Standard or
Advanced.

## Enrolled authority

The server reconstructs a context from authenticated enrollment, validates its
complete compiled tree, and derives the existing scoped VTXO key. The request
cannot select a key domain or supply authoritative tree parameters. The named program is `vault-policy-v1` for Light, Standard and Advanced. Light uses shared Spending with device recovery; protected Savings uses Ledger.

The context digest is SHA256 of the UTF-8 prefix
`vaulted-vtxo/renewal-context/v1:` followed by compact JSON with ordered fields
`program,network,vaultId,protectionTier,ownerPub,cosignerPub,operatorPub,scriptPubKey,spendingPolicy`.
Public keys are lowercase x-only hex; the script is the exact enrolled P2TR
output. Spending policy retains its existing canonical field order. Wallet and
Guardian independently reconstruct this binding, with shared test vectors for
both networks. Historical vector rows leave with their programs; retained expectations remain fixed.

## Bounded authorization set

POST `/v1/vtxo/delegate/schedule` accepts these ordered semantic fields:

```json
{
  "program": "vault-policy-v1",
  "descriptorHash": "...",
  "vaultId": "...",
  "setId": "...",
  "plans": [
    {
      "operationId": "...",
      "intent": { "proof": "...", "message": "..." },
      "forfeitTxs": ["..."],
      "deleteIntent": { "proof": "...", "message": "..." },
      "expiresAt": 1,
      "ownerSignature": "..."
    }
  ]
}
```

There must be 1–50 distinct plans, with unique operation IDs and input
outpoints. The existing 1 MiB request limit also applies. Each plan authorizes
one committed live input and one replacement using the byte-identical enrolled
Spending script. Registration, partial forfeit, deletion proof, current fee
verification, and finite deadlines retain the rules in
[the native renewal lifecycle](delegated-renewal-lifecycle.md).

Each plan's `ownerSignature` is BIP340 over SHA256 of
`vaulted-vtxo/delegate-schedule/v1:` plus ordered
`program,descriptorHash,vaultId,operationId,intent,forfeitTxs,deleteIntent,expiresAt`.
The outer request also carries an `ownerSignature` over SHA256 of
`vaulted-vtxo/delegate-schedule-set/v1:` plus the complete ordered semantic
object above, including every per-plan signature.

Every retained account supplies `authorization` with
`credentialId,clientDataJSON,authenticatorData,signature,directSig`.
The existing enrolled WebAuthn credential validates presence, origin, RP ID,
and user verification; PhoneDirectP256 signs the set digest. The WebAuthn
presence challenge need not equal that digest.

All plans and one strict credential-counter acceptance commit atomically.
Failure cannot leave partial authority or consume the counter. Nonzero counters
must increase for a new set; authenticators that return zero retain the existing
zero-counter behavior. A counter already consumed by login, recovery, or a
payment cannot authorize another set through an equality exception.

The response contains `setId` and the operations in the submitted order, with
verified receiver identities but no embedded recovery graphs. Full graphs are
returned by the dedicated status endpoint, keeping a 50-plan receipt bounded.
An exact owner-authenticated retry returns the persisted set, including after its
deadlines or a later unrelated ceremony. It grants no additional authority and
does not consume the supplied assertion. Changed membership, order, program,
context, set ID, or plan cannot extend that receipt. Set and operation IDs are
16-byte lowercase hex, and context hashes are 32-byte lowercase hex. Vault IDs
retain their exact enrolled opaque UTF-8 value; current public enrollment assigns 16-byte hex IDs for every retained configuration.
Identifiers are never decoded, lowercased, or Unicode-normalized for key
derivation or signing.

## Authenticated readback

The shared POST `info` endpoint takes `vaultId` and returns the enrolled program,
context hash, delegate key/address, and limits. Shared `status`, `list`, and
`cancel` require the owner's BIP340 signature over their corresponding
`vaulted-vtxo/delegate-{purpose}/v1:` domain. Status and cancel use ordered
`program,descriptorHash,vaultId,operationId,expiresAt`; list substitutes
`afterOperationId` for `operationId`. These authorizations expire within five
minutes and cannot be exchanged across purposes.

The historical Light profile, standalone renewal API and backup API are removed. Retired routes return 404, including for preflight requests. Current delegation requires the enrolled program, descriptor hash and authenticated set membership; a historical operation cannot fall back to the current context.

Schema 12 retains the current journal's table names, serialization and MAC domains. MAC verification and complete set membership checks precede use. A missing or substituted member fails closed, while global set-ID collisions cannot combine different vaults. Further historical-account storage retirement and the coordinated Contract Pack update remain required before release.

## Execution and recovery

Armed plans consume no allowance. Per-plan claim keeps the existing input and
vault execution fences and reserves only the renewal fee. Final Guardian
forfeit signing still requires a complete verified signed replacement graph.
The scoped key checks the compiled program and immutable signing transcript;
changed peer nonces cannot be signed after restart. A finite owner authorization
cannot renew a replacement output recursively.

The existing uncertain registration, final submission, and cleanup behavior
remains conservative. No-match is not proof of deletion, and an unresolved
signed operation retains its fence. The wallet must import and verify the new
recovery graph and update its encrypted archive on return; an earlier archive
cannot contain a graph produced after it was saved.
