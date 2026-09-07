# Light Spending contract

This package constructs `vault-light-policy-v1` for the `vaulted-light-v1`
profile. Cooperative Spending requires the owner, policy cosigner, and stock
Arkade Operator. The separate Bitcoin exit uses the owner key after its
committed delay. Bitcoin Script does not compute the rolling allowance.

Enrollment binds the independently derived cosigner, immutable policy, network,
and descriptor. `testdata/contracts.json` is shared with the wallet; each
implementation reconstructs scripts, output keys, and hashes independently.
Light identities have their own authenticated template and key domains.

`VAULT_LIGHT_ENABLED` controls new Light enrollment and defaults to false.
Existing wallets and started ceremonies remain usable when it is disabled.
`VAULT_INVITE_ONLY` independently selects invitation-based or open admission.

The application implements [foreground renewal](../../../docs/light-renewal.md)
and optional [delegated renewal](../../../docs/light-delegated-renewal.md).
An independent exit also requires saved transaction paths, restored owner
access, Bitcoin fee funding, and the script's confirmation and delay conditions.
