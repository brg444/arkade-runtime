# Linux service examples

This directory provides service units and helper scripts for a dedicated
Guardian account. Review the paths and settings for the target host before
installing them. Host provisioning and hardware isolation require separate configuration and
verification.

| File                             | Role                                          |
| -------------------------------- | --------------------------------------------- |
| `vaulted-guardian.service`       | Guardian process and filesystem restrictions  |
| `cloudflared-guardian.service`   | Optional tunnel process                       |
| `guardian.env.example`           | Non-secret process configuration              |
| `cloudflared-config.example.yml` | Optional tunnel configuration                 |
| `sysusers.conf`                  | Dedicated service account                     |
| `tmpfiles.conf`                  | Runtime directory creation                    |
| `unlock.sh`                      | Interactive encrypted-key loading and startup |

The service uses file-backed key loading. The unlock helper decrypts configured
age-encrypted files into runtime storage, starts the service, and removes
remaining plaintext after a failed start. The authorizer removes its plaintext
signing-key file after loading. The key remains in process memory while signing;
root or process compromise can expose it.

The supplied unit does not automatically unlock signing after reboot. Inspect
`unlock.sh` and the service unit together for required files and arguments.
Gateway credentials must remain outside browser builds and source control.

The database and policy sequence are separate durable state inputs that require
consistent database backups, authentication keys, and independent sequence
continuity. [Storage](../../docs/storage.md) describes what rollback detection
can and cannot establish. After startup, check `/health` and `/ready` separately to distinguish process
liveness from usable signing dependencies.

Optional network-access templates leave storage independence and host
administration trust to the deployment; they provide no remote attestation.
