# Retained contract baseline v3

Baseline v3 admits shared Spending for all accounts and optional Ledger Savings.
The wallet and runtime share the exact Contract Pack bytes for each network.
Mutinynet and mainnet retain their distinct Operator, delegate, delay and fee
pins; a pack from another network fails the runtime digest check.

| Contract | Current declaration |
| --- | --- |
| Database | Schema 12, with authenticated retirement from the exact schema 11 baseline |
| Public enrollment and readiness template | `vaulted-spending-v1` |
| Spending program | `vault-policy-v1` |
| Boarding program | `vault-board-v1` |
| Optional Savings program | `phone-ledger-guardian-savings-v1`, admitted through its qualified capability |
| Recovery Kits | Shared Spending v5 and Ledger v4 |
| Map backup | v3 |
| Recovery bindings | Shared Spending v4 and Ledger v6 |

The manifest removes `savings-recovery-v1`, `savings-connector-v1` and
`savings-connector-dual-v2`, their retired recovery-session and connector-binding
domain declarations, and the connector enrollment kit format. No parser or
signer compatibility layer accompanies those removals. The Ledger format entry
now identifies current runtime schema 12. The top-level Recovery Kit declaration
names both retained account formats, replacing the obsolete v3 kit declaration.

Retained scripts, CSV delays, fee and allowance bounds, key derivation domains,
enrollment encodings and recovery bindings preserve their existing values.
Renewal fixtures retain four protected contexts across mainnet/Mutinynet and
Standard/Advanced, with their exact context and digest expectations. Their
account labels identify Ledger directly; historical Light and duplicate connector
rows are removed. The fixed renewal set keeps its exact body, signatures,
transaction bytes and digest. Expected signing outputs remain independently
fixed throughout this change.

The runtime freezes both pack hashes in the embedded loader and compatibility
barrier. Wallet tests freeze the same hashes and require the retained program
set. Both sides qualify public status and readiness on each network, and the
wallet rejects successful readiness responses outside schema 12. Recovery
artifacts must be rebuilt from the final wallet producer revision and pinned by
the wallet consumer revision before final candidate qualification.
