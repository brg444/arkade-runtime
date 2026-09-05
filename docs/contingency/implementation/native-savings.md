# Native Savings implementation and timelocked recovery

## Selected Design And Constraints

Native Savings is selected for contingency investigation, with production activation still gated by the [architecture proposal](../proposals/native-savings.md). Branch preparation does not select a weaker hardware model or approve a funded migration. The first target is a supported cooperative transfer and a service-independent delayed exit with both user keys available. Key-loss recovery has its own gate.

## Source Revision And Drift Check

Runtime baseline: `a70823a28b596195e033c4c25e48d8d82e22a72d`, tree `99405ac214e7f59633f2b1c12dc6e1294bf84235`.

Wallet baseline: `53c597393c68374afaec06108a8f803f24d7de6e`, tree `0582dd149b1ee59233d1347419abba4d43bf2f1f`.

The [evidence inventory](../context.md) and `sourceEvidence.collectionSha256` in [the structured analysis](../hardening.json) bind the reviewed source. These branches begin at fetched main revisions. Before implementation and again before release, fetch main, review intervening changes, and compare with actual deployment manifests. Matching a previously recorded tree is historical alignment, not a fresh runtime attestation.

## Affected Components

Runtime: a future isolated Savings contract experiment, the named profile/program declarations, semantic authorization, and recovery lifecycle persistence if the selected graph needs it. Existing `internal/vault/savings`, policy MAC/sequence behavior, and production routes stay intact during feasibility.

Wallet: native SDK transaction coordination, hardware signing transport, contract handler, recovery archive, recovery kit, and lifecycle UI. Light `recovery.ts` and `recoveryArchive.ts` provide reuse candidates. Their owner-only assumptions must be replaced by the selected Savings authority, with cross-profile rejection tests.

## Ordered Work Packages

### Admission and hardware transaction

Use disposable keys and local services with pinned source versions. Construct the smallest supported native Savings transfer with exact checkpoint ancestry. Record the Operator leaf requirements, output rules, program packet, signing order, and final transaction bytes. A successful interpreter run without accepted protocol inputs is insufficient.

Test direct hardware authorization and a native connector only where the actual hardware wallet can sign and display the complete transaction. Require the intended strong sighash mode and independently verified previous outputs. Reject missing or substituted hardware evidence, attacker outputs, duplicate inputs, and weaker sighash modes. Keep the existing conventional-input signer tests as historical evidence.

Deliver the accepted transaction fixture and the unsupported cases before implementing enrollment or connector tracking. Stop expanding the connector if native admission or hardware display cannot be demonstrated.

### Complete authorization matrix

List every normal, renewal, recovery-initiation, pending, cancellation, quarantine, and key-path authority. Name phone, hardware, recovery key, Guardian, program cosigner, and Operator separately. Test each alone, relevant pairs, phone plus all online keys, and recovery key plus all online keys. Include loss of each user key and simultaneous service outage.

For each attack, distinguish program rejection from Bitcoin-consensus rejection. Report the honest-cosigner outcome and the all-online-keys-compromised outcome separately. A required Operator signature supplies an additional signing authority; it supplies hardware approval only if the selected construction enforces that property under the stated model.

### Timelocked graph

The proposed outage path is `committed ancestors -> confirmed Savings exit output -> user-key sweep after CSV -> chosen Bitcoin destination`. Determine whether the supported native tree can express the selected phone-plus-hardware delayed leaf before adding any enrollment fields. Prove every ancestor and signature from an enrolled output; a leaf funded directly is only a component test.

The key-loss candidate is `committed ancestors -> constrained recovery initiation -> confirmed pending output -> delayed claimant sweep`, with a competing cancellation path to a precisely defined protected destination. This is a graph to construct and test, not an established capability. If initiation requires a fresh online signature after outage, record key-loss recovery as service-dependent. If presigning is proposed, specify setup signatures, key deletion assumptions, amounts, change, fees, replacement, repeated withdrawals, and regenerated graphs after renewal. A fixed one-payment presignature does not qualify a reusable wallet.

| Situation | Planned authority | Timing and acceptance gate |
| --- | --- | --- |
| Online services unavailable, phone and hardware intact | Both user keys, no fresh online signature | Unroll saved ancestors and sweep only after the selected exit CSV matures |
| Phone lost | Hardware and any explicitly selected recovery setup | Construct the exact claim/cancellation graph; independent availability remains unproven |
| Hardware lost | Phone and any explicitly selected recovery setup | A lone-phone immediate spend is not an implicit fallback; test its delay and cancellation |
| Optional recovery key used | Explicit Standard/Advanced policy | Establish which surviving keys can cancel and control the protected destination |
| All user recovery material lost | No asserted recovery authority | Report unrecoverability because the selected user signatures remain necessary |

There are separate clocks. VTXO expiry determines when renewal or exit must be arranged. Bitcoin relative locks begin from the relevant confirmed output, not a button press, registration timestamp, or emulator clock. Pending recovery adds another delay if its output confirms later. Time-based sequence locks use 512-second units and chain median-time-past; block-based locks use height. Verify exact maturity through Core, including one unit early, the first valid inclusion, and a reorg. Sources: [BIP 68](https://bips.dev/68/) and [BIP 112](https://bips.dev/112/).

Current runtime Spending pins use a mainnet exit delay of 605184 seconds, while existing Savings pending claims use 6, 144, or 288 blocks according to claimant. These are different contracts and units, not candidate native Savings parameters. Determine the supported minimum, each graph's confirmation anchor, cancellation window, and all competing expiry/reclaim conditions before selecting new delays. Completion estimates must account for ancestor confirmation and fee conditions.

### Recovery archive and lifecycle

Retain the exact descriptor and program version, user-key derivation/recovery instructions, current outpoints and values, scripts and control blocks, signed commitment/tree/checkpoint/transition transactions, ancestry links, timelock conditions, expiry data, and fee-bump plan. Verify parent hashes, input amounts, signatures, script membership, network, and final destinations independently of archive metadata. Preserve secrets only in the existing protected backup mechanism; public diagnostics contain no signing-service endpoint.

Capture recovery evidence after receipt, partial spend/change, renewal, recovery initiation, and cancellation. Retain the previous complete archive until its successor is verified and durable. Fault-inject between submit, accepted response, signature delivery, archive write, and UI completion. An operation that finalized remotely before local capture must remain explicitly unresolved until reconciliation; an old archive cannot be labeled current. Require a clean-device restore without Vault, Operator, signer, or their indexers.

Record who can keep an archive current while the owner is offline. Defer noninteractive delegation for Savings until this is solved or the selected recovery guarantee explicitly includes a separate data-availability dependency. Avoid introducing a delegate database or scheduler just to bypass that question.

### Integration and qualification

Once the graph and trust model are selected, assign a new immutable profile/program/descriptor identity and shared wallet/runtime vectors. Integrate through the official SDK and semantic signing methods. Reuse Light's reviewed archive and durable reconciliation components only after reviewing the exact merged source and schema compatibility. Keep the legacy decoder and recovery tools available for old outputs.

Run a complete Mutinynet drill: enroll, receive, transfer to Spending, preserve Savings change, renew, restart, restore from backup, stop every online service dependency, and confirm the final recovery sweep. Run each supported key-loss/cancellation path separately. Record device model, firmware, software wallet, transaction display, and exact release revisions.

## Compatibility And Migration

Old descriptors and signed recovery records identify old scripts permanently. New behavior requires new outputs and addresses. Migration must identify the source generation, use its authorized spending path, verify the destination generation, and retain recovery evidence for change on both sides. An emptied test vault does not establish that all installations or retained records can be discarded.

## Tactical Protections During Migration

Keep existing normal transfers, recovery tooling, private service configuration, named-program validation, MAC-before-use, and policy-sequence ordering. A service-admission incident should mark only affected capabilities unavailable, with funds remaining under their existing authorization rules. Preserve current RC deployment until a separate release qualifies.

## Tests And Security Validation

Admission, program interpretation, hardware approval, and Bitcoin recovery are independent gates. Include all alternate leaves, valid-looking forged archives, incomplete ancestry, stale generations, replay, duplicate inputs, concurrent spend/renewal, insufficient fee reserves, fee mutation, package rejection, cancellation/claim races, renewal reset of ancestry, expiry boundaries, and backup freshness after browser storage failure.

## Performance And Resource Benchmarks

Measure signing latency, end-to-end transfer completion, recovery archive size/write latency, peak memory, restore duration, exit transaction count, total fees, and required external fee UTXOs. Compare one output and repeated spend/renewal histories against the qualified Light lifecycle where comparable. Set explicit bounds after measurement; recovery must remain possible within supported storage and fee limits. Record measured results with their workload and release revision.

## Rollout And Rollback

This preparation branch is documentation-only and can be dropped without changing a contract. Later candidate enrollment stays default-off until its release gates pass. Rollout requires matching wallet/runtime artifacts, current deployed-branch compatibility, funded recovery evidence, and the selected trust model. Disabling enrollment stops new funds entering the candidate; recovery support remains until existing candidate funds drain. A database change needs a compatible rollback binary, and a funded script change needs an authorized Bitcoin transaction.

## Acceptance Criteria

- An accepted native transfer proves input admission and actual device approval under the selected model.
- Every spendable route has a tested authority entry; all-online-keys bypass results are reported without relabeling.
- The full post-spend, post-renewal recovery confirms using saved artifacts and the selected user keys while online services are unavailable.
- Each offered key-loss route passes its complete initiation, delay, cancellation, and final-claim drill. Unsupported combinations remain explicit limitations.
- Old-generation recovery and current deployed behavior remain compatible; new scripts and records use distinct identities.
- No private signing-service endpoint appears in committed files, wallet assets, public responses, or diagnostics.

## Open Decisions

Select native hardware signing or a proved native connector; select the normal and recovery authority matrix; select exact delays and fee provisions; decide who maintains recovery data during unattended renewal. These decisions are required for activation, while admission and recovery experiments can proceed with disposable keys now.
