# Enrollment access

`VAULT_INVITE_ONLY` controls admission for the deployed Guardian. It is separate from the immutable vault deployment identity, so changing it does not change enrolled keys, descriptors, policies, or recovery paths.

| Setting | New setup |
| --- | --- |
| Unset or `true` | Requires an operator-issued invite. |
| `false` | Offers open signup using an automatically issued setup session. |

The equivalent process flag is `--invite-only=true` or `--invite-only=false`. Invalid environment values prevent startup. Configuration is read at startup; apply a change through the normal Guardian restart and manual unlock procedure. Keep the current database, policy sequence, and signing key intact.

For the RC Guardian, set `VAULT_INVITE_ONLY=false` in its protected service environment. To restore invite-only signup later, set it to `true` and restart through the same procedure. Verify that RC's public `/v1/status` reports `enrollmentMode: "open"` or `"token"`, respectively. The wallet follows this response and refreshes it on setup navigation, window focus, and every 30 seconds while those screens are open; a frontend rebuild is unnecessary.

Open signup issues a random 256-bit token from `POST /v1/enroll/session`, with a ten-minute expiry and authority to create one vault. The existing challenge, protection-tier and policy binding, atomic completion, and duplicate-finish checks remain in force. The browser keeps this admission token in tab session storage across canceled passkey prompts, then clears it after enrollment completes. A new public session is refused when invite-only is enabled, while previously issued sessions can finish until their existing expiry.

The mainnet gateway permits five session requests per client address per minute, within its existing overall request limit. The Guardian ledger additionally permits at most 30 issued tokens per minute and 1,000 active unused tokens. These counters include operator-issued invites and survive server restarts. Expired unused records older than 24 hours are removed during issuance; consumed records remain available for lost-response reconciliation. The session route retains the existing gateway authentication, Origin checks, request bounds, and no-store response policy.

Enable open admission only on the intended Guardian deployment. A browser-side flag or an RC hostname check alone cannot change server admission policy. Returning to invite-only affects new enrollment; existing vaults retain sign-in, payment, and recovery access.
