# Light contract candidate

This package constructs the candidate `vault-light-policy-v1` contract for the future `vaulted-light-v1` profile. Production enrollment and signing routes remain on the current profile; this package has no service, store, key derivation, or signing capability.

The cooperative leaf requires the owner, independent Vault policy cosigner, and stock Arkade Operator. The second leaf gives the same owner a delayed Bitcoin exit. Mainnet and Mutinynet use their current frozen Operator and delay pins. Light's eventual enrollment must bind its independently derived cosigner to the immutable policy; the script itself cannot enforce a rolling allowance.

The owner exit runs outside cooperative payment limits. Its Bitcoin script-engine tests cover the correct owner, early claims, timelock units, transaction version, and the relative-locktime disable flag. A complete funded exit also requires the verified transaction chain, lifecycle state, confirmation timing, available fees, and owner-key restoration.

`testdata/contracts.json` is shared byte-for-byte with the wallet's Light tests. The SDK and Go independently reconstruct both scripts, output keys, and descriptor hashes. Existing program, profile, Contract Pack, policy-ledger, and route behavior remain unchanged.

Before activation, implement separate Light enrollment identity and scoped key derivation, authenticated policy persistence and authorization, backup and restoration, SDK lifecycle integration, and fresh funded qualification. Keep the existing Standard and Advanced validation intact.
