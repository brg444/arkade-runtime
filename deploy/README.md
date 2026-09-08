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
describes schema 7, supported migrations, and sequence continuity.

Hardware isolation and remote attestation require separate implementation and verification.
See [the security model](../docs/security.md) before relying on a deployment.
