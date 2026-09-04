# Hetzner CX22 for Vaulted Guardian

Buy this yourself. The CLI here cannot complete payment.

## Order

1. https://console.hetzner.cloud
2. New project: `vaulted-mainnet` (not the Mutinynet Railway project).
3. Add an SSH key for rescue/console only.
4. Create server:
   - Location: **Ashburn (ash)** — same region class as the Upstash `iad1` rate-limit store
   - Image: Ubuntu 24.04
   - Type: **CX22** (2 vCPU, 4 GB RAM, 40 GB local disk)
   - Networking: public IPv4 is fine; **do not open ports**
   - Cloud config: paste `hetzner-cloud-init.yaml`
5. Volumes (independent restore authorities):
   - `vaulted-data` 10 GB → `/var/lib/vaulted-guardian/data`
   - `vaulted-sequence` 1 GB → `/var/lib/vaulted-guardian/sequence`
6. Firewalls: inbound **deny all**. Outbound allow 53, 80, 443, and UDP 41641 (Tailscale).

## First login

Use the Hetzner web console, then:

```bash
sudo tailscale up
```

Approve the machine in Tailscale. Later admin is `ssh operator@<tailscale-ip>` only.

## Then

Copy `deploy/linux/` onto the VM over Tailscale and follow `README.md`.
Do not run `cloudflared` until `cloudflared tunnel login` has been done on
an admin laptop and the tunnel credentials exist.
