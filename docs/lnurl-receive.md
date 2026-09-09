# Lightning address receiving

An enrolled Vaulted wallet can authorize a reusable address at
`ln.getvaulted.xyz`. Guardian authenticates setup and revocation with separate,
single-use passkey purposes and sends the receiving process the enrolled public
Spending destination. Neither operation grants the process a signing key.

The receiving process requests an exact-total invoice from the solver. It saves
the quote, preimage, and claim registration before returning the invoice. Once
the solver funds the swap, it saves the prepared constrained claim and complete
funding ancestry before revealing the preimage to the Emulator. Settlement
requires both the exact indexed payout and the solver's completed status.

The wallet imports funded receipts and validates their invoices, contracts,
payouts, and recovery graphs against its enrollment and release pins. Imported
transactions use the same exit repositories as other Spending recovery data.
Unpaid requests remain outside wallet history. Revocation stops new invoices;
it preserves pending claims, receipts, and recovery data.

## Deployment configuration

Build the receiving repository's `vaulted` Docker target and configure
`deploy/vaulted.env.example` and `deploy/vaulted.compose.yml` from that repository.
The initial qualification range is 1,000–5,000 sats paid, with a 25-sat receive
fee ceiling and one allowed enrollment. Each registration retains its original
fee ceiling; increasing the service configuration cannot increase that ceiling.

Guardian requires these two settings:

```dotenv
VAULT_LNURL_ORIGIN=https://ln.getvaulted.xyz
VAULT_LNURL_TOKEN_FILE=/etc/vaulted/lnurl-bridge-token
```

The token file contains 32 random bytes encoded as 64 lowercase hexadecimal
characters, with permission `0600` and ownership allowing the Guardian process
to read it. The receiving process needs a separate readable file containing the
same token and a distinct random 32-byte encryption key. Keep the encryption key
with protected backups; the SQLite file alone cannot restore receiving state.
The receiving container runs as UID 1000, so its data directory and token file
must be readable and writable as appropriate by that UID.

Point `ln.getvaulted.xyz` to the receiving host and terminate HTTPS at its reverse
proxy. Only the public receiving port needs forwarding. The admin listener stays
on container loopback. `/healthz` checks the local database; it does not certify
solver liquidity, external service availability, or recovery economics.

Set `VITE_VAULT_LNURL=true` only in the qualified wallet build. The mainnet CSP and
gateway routes already include the receiving domain and the three Guardian
setup routes. The normal invoice prompt remains the default; the reusable
address expands from its own control.

## Activation checks

Before enabling a live wallet, deploy the receiving process with its persistent
volume, backup key, TLS, and enrollment allowlist. Update Guardian, coordinate
its interactive unlock, and verify authenticated registration and revocation.
Use one small funded payment to confirm payer completion, receipt and balance
convergence with the phone closed, process restart, and recovery import after
local cache loss. Export and restore the resulting Recovery Kit, then assess
whether the output can cover its onchain recovery fees.

Regtest qualification demonstrates service restarts and constrained payout. It
does not establish a funded mainnet exit or economical recovery for small
outputs. Broad activation remains gated on those qualifications and the final
independent reviews.

## Rollback

Disable new registrations and invoice callbacks through the enrollment allowlist
or revoke the affected addresses. Keep the receiving process and its stored
claims available until funded swaps resolve. Hiding the wallet control or
removing DNS is insufficient because invoices may already be held by payers.
Preserve the receiving database and its schema until all pending claims resolve.
