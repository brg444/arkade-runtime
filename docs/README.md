# Arkade Vault Server documentation

| Document | Scope |
| --- | --- |
| [Mainnet v2 baseline](mainnet-v2-baseline.md) | Fresh persistence and API boundary, threat model, and unresolved release gates. |
| [Versioned contracts](versions.md) | Database, program, and domain identifiers in the fresh v2 service. |
| [`vault-policy-v1` one-input spend](vault-policy-v1-one-input.md) | Exact Mutinynet transaction shape and current functionality limits. |
| [`vault-policy-v1` guardian delay](vault-policy-v1-guardian-delay.md) | Mutinynet delay pin and the separate mainnet decision. |
| [Deployment](../deploy/README.md) | Image, secret, persistence, readiness, and operations entry points. |
| [Contract pack](../contract-pack.json) | Machine-readable programs shared byte-for-byte with the wallet. |

The wallet owns transaction coordination, device ceremonies, user-facing
recovery, and SDK integration. Its current documentation lives in
[arkade-wallet-vault](https://github.com/brg444/arkade-wallet-vault/tree/vault-mode/docs).
