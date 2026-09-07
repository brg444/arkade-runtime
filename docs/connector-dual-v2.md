# Ledger connector v2

New Savings connector enrollments use `savings-connector-dual-v2` and
`phone-connector-recovery-savings-v2`. Existing v1 enrollments retain their
scripts, derivations, recovery paths and operation history. The release changes
neither the current Emulator nor SQLite schema 5.

Two 500-sat hardware reserves occupy inputs 0 and 1; Savings occupies input 2.
The hardware signer approves both reserves with `SIGHASH_SINGLE`, without
`ANYONECANPAY`, before the wallet requests phone or service signatures. Input 0
commits to the recipient. Input 1 commits to protected Savings change for a
partial withdrawal, or the first returned reserve for a full withdrawal.

The signer sees all monetary outputs. After hardware approval, the wallet adds
the zero-value Emulator packet as the final output, preserves the hardware
signatures, and persists the resulting candidate before phone approval.
Savings signatures use `SIGHASH_DEFAULT` and commit to that complete candidate.

The current Emulator independently reconstructs both hardware signature digests
and verifies them with `OP_CHECKSIGFROMSTACK`. Its program also checks the fee,
protected change, both returned reserves, anchor, transaction layout and exact
packet contents. Streaming hashes keep intermediate stack elements within the
current interpreter's limits. The larger proof increases transaction fees;
the existing absolute and feerate caps remain enforced.

Guardian verifies the enrolled family, parents, phone signature, program and
packet. It also requires the final Bitcoin witnesses to contain the same
hardware approvals as the packet before writing an authorization. Otherwise a
valid packet could reserve an unbroadcastable candidate. The semantic signing
capability repeats these checks against the retained candidate.

The existing authenticated operation record stores all candidate bytes. The
second reserve is derived from those bytes after MAC verification; no new
column or migration is needed. Atomic conflict checks cover all three inputs,
including a reserve appearing in a different position in another candidate.
Exact retries retain the same operation and signing stages. Unknown chain
outcomes and reorgs retain ownership until the existing reconciliation rules
prove a resolution.

Duplicate enrollment completion reconstructs the stored template. A v1 proposal
that never completed before upgrade is refused until the wallet obtains and
approves a new v2 proposal; the server does not silently change its commitment.
Recovery reconstructs the enrolled family for either version, including after
restart and in the pinned offline companion.

## Qualification and activation

The shared vectors cover both networks, protection tiers, signer types and
full/partial withdrawals. Go and TypeScript must reproduce the same program,
Savings script, leaf, control block and enrollment digest. Completed transaction
fixtures execute through Bitcoin validation and the current Emulator. The v1
vectors remain unchanged.

The wallet's [Ledger qualification](https://github.com/brg444/vaulted-bitcoin-wallet/blob/codex/ledger-dual-connector-20260907/tools/connector-signers/LEDGER.md)
records the firmware simulator and Emulator evidence. Physical hardware and
funded production relay acceptance remain separate qualifications. The
Emulator verifies the destination approved by the hardware; it cannot infer
whether that destination matches the user's intention. Bitcoin does not execute
the Arkade Script program, so its policy still depends on an honest enforcing
cosigner.

Deploy the paired wallet and runtime with byte-identical network Contract Packs
and the verified recovery companion. Stage the new binary while the existing
Guardian runs. Activation requires the operator's interactive unlock, followed
by readiness and capability verification before wallet promotion. Existing
wallets require no fund migration. Once v2 contracts or authorizations exist,
an older runtime that does not understand them is not a safe rollback target.
