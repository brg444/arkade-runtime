# Vaulted Operator-compatible contingency

Status: preparation only, 2026-09-05. The branch contains a design and implementation handoff; production contracts and deployment configuration retain their baseline values.

The [connector reconciliation](connector-reconciliation.md) is the current mapping
of reusable experiments, excluded L1 assumptions, hardware trust outcomes, and
branch alignment. Its ordered proof work precedes production integration.

## Evidence Basis

The current Savings contract has a phone-plus-hardware normal path and program-cosigned recovery initiation. The proposed L1 connector adds program cosigning to ordinary transfers. Upstream native transaction admission requires checkpoint-backed inputs; adding an Operator key to the existing onchain signing request does not convert that request into a native transaction.

The [source inventory](context.md) pins the inspected revisions and separates source evidence from other agents' qualification reports. Upstream revisions are research evidence, not declarations of deployed service versions.

[Emulator PR 102 context](upstream-signing-library.md), added 2026-09-06, introduces an embeddable execution/signing engine. It adds a deployment simplification candidate while retaining the native admission, key-authority, and complete-recovery gates.

## Constraints

Prepare native Savings without changing funded vaults or reusing the old contract identity. Retain a Bitcoin-enforced timelocked recovery path with a complete, locally saved transaction graph. Evaluate the entire script tree under each compromise model, including recovery and key-path authority. Keep private signing-service configuration out of distributable artifacts.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Separate cooperative policy from durable recovery | Native input admission, connector bypass tests, Savings recovery scripts, Light recovery archive | 1. Retain existing Savings; 2. Research native Savings with committed recovery | Prepare Option 2 while Option 1 remains the deployed baseline | [Architecture and trust boundaries](proposals/native-savings.md) |

## Recommendation Summary

Native Savings is the contingency candidate because its cooperative transaction can use the supported Operator flow. Its hardware approval mechanism and complete recovery graph still need proof. Start with those two feasibility gates before implementing enrollment, new policy storage, or a delegate service.

Light provides useful lifecycle and recovery patterns, but its owner-only exit does not establish Standard or Advanced protection. Reuse qualified components under a separately named contract after examining their assumptions. Keep the conventional L1 connector as evidence; merging it would add a dependency that this contingency is intended to resolve.

## Next Decisions

The immediate work is specified in the [implementation and timelocked-recovery plan](implementation/native-savings.md). That work must produce an exact authority matrix, an admitted transaction, and a complete outage recovery before a funded migration can be considered. Hardware omission under compromised signing keys and enforcement by an honest online cosigner remain separate outcomes. Existing acceptance of the latter for the L1 candidate cannot be presented as proof of the former for native Savings.
