# Running Guardian

`cmd/authorizer` is the production entrypoint. The repository provides container
and Linux service examples; they are configuration templates, not a record of
any particular hosted installation.

| File                                            | Purpose                                            |
| ----------------------------------------------- | -------------------------------------------------- |
| [Dockerfile.mutinynet](../Dockerfile.mutinynet) | Local Mutinynet image                              |
| [Dockerfile.railway](../Dockerfile.railway)     | Hosted image that binds the configured port        |
| [Dockerfile.linux](../Dockerfile.linux)         | Binary image for file-backed key loading           |
| [.env.example](../.env.example)                 | Local environment variables                        |
| [mainnet.env.example](mainnet.env.example)      | Additional mainnet configuration requirements      |
| [Linux service examples](linux/README.md)       | Service account, key loading, and filesystem paths |
| [Enrollment access](enrollment-access.md)       | Open and invitation-based admission                |

The RC signing address is `https://rc.getvaulted.xyz`. Set
`VAULT_CLIENT_ORIGIN=https://rc.getvaulted.xyz` and
`VAULT_RP_ID=rc.getvaulted.xyz`, as shown in both mainnet examples. The wallet
reads these values from Guardian before starting a passkey ceremony. A different
signing address causes it to navigate to that address.

Changing the signing address requires a coordinated Guardian restart and its
interactive unlock. Preserve the database and independent policy sequence when
changing only the address; initialize fresh state only for an explicitly scoped
reset. Verify `/ready` reports schema 12 and `vaulted-spending-v1`, and
`/v1/status` reports the expected signing origin and RP ID.

Set the client origin and WebAuthn RP ID for the wallet that will use the
service. Use separate signing keys, data, sequence state, and credentials for
different networks. Keep gateway secrets and private key files outside source
control and browser build variables.

The configured network selects compiled Operator, signer, and program
parameters. Unsupported overrides and inconsistent identities fail startup
or readiness. Mainnet also requires the declarations in `mainnet.env.example`;
those declarations require independent verification of the claimed infrastructure properties.

Check `/health` for process liveness and `/ready` for usable dependencies and
state. Route signing traffic only to a ready process. [Storage](../docs/storage.md)
describes authenticated persistence and sequence continuity. The current schema
and supported upgrade boundary are specified in the
[ledger migration contract](../docs/ledger-schema-migration.md).

Hardware isolation and remote attestation require separate implementation and verification.
See [the security model](../docs/security.md) before relying on a deployment.
