# Embeddable signing engine: emulator PR 102

Reviewed 2026-09-06 at [PR 102](https://github.com/arkade-os/emulator/pull/102), head `e222684a8da4eb68642164f8c3c429c417f973b1`, base `4feb9eaa81b49f8d321407e92dba107ec9ba5158`. The PR was open with changes requested. This is supplementary source evidence for the contingency, with no dependency or production change.

## Execution and transaction coordination

The PR exports `pkg/emulator` as a Go module. Its constructor receives a program-signing private key, the Operator public key, an optional finalizer, and an optional indexer. With a nil finalizer, native submission executes the program and returns signed transaction/checkpoint packets; the caller owns the subsequent submit/finalize round trip. The library still performs checkpoint validation and signature-role checks before the applicable return. See [`service.go`](https://github.com/arkade-os/emulator/blob/e222684a8da4eb68642164f8c3c429c417f973b1/pkg/emulator/service.go) and [`tx.go`](https://github.com/arkade-os/emulator/blob/e222684a8da4eb68642164f8c3c429c417f973b1/pkg/emulator/tx.go).

Louis's [review](https://github.com/arkade-os/emulator/pull/102#pullrequestreview-4742477878) favors keeping the exported package focused on execution and signing, with submission/finalization in the Operator application. The current PR retains an injectable finalizer, so the final exported boundary remains under discussion. Neither the review nor this PR establishes a deployed Operator integration.

For Vaulted, the preferred integration boundary is a named program authorizer using a qualified upstream engine, with transaction coordination remaining in the existing SDK/application lifecycle. Evaluate embedding before adding another standalone daemon or duplicating interpreter and signing code. Construct concrete adapters only for the selected deployment; a generic provider framework is unnecessary at this stage.

## Hosting and key authority are separate choices

Embedding the engine inside the Operator signer is compatible with the native Savings direction. It still requires qualification of the actual Operator integration, supported program keys, transaction shape, and lifecycle behavior. The PR supplies the program-signing private key separately from the Operator public key, so it does not establish a construction using one signature or one key for both roles.

Embedding an engine under Vault's control could remove a separate process or external program-signing dependency. The exported [`SubmitOnchainTx`](https://github.com/arkade-os/emulator/blob/e222684a8da4eb68642164f8c3c429c417f973b1/pkg/emulator/onchain.go) also retains ordinary Bitcoin program signing while rejecting leaves containing the configured Operator key. A separately operated signer with its own key is therefore an L1 deployment alternative in principle. It would need its own admission, signing, and recovery qualification, and it cannot sign existing outputs that commit to someone else's key.

Placing both Guardian authorization and the other program-signing key under the same administrative control removes their independence under that compromise model. A second process or second key on the same controlled host does not restore that property. This alternative needs an explicit trust decision; it is not an equivalent replacement for an independent honest cosigner. Keep the native Savings contingency and the current funded contract while evaluating that choice.

## Recovery and admission gates remain

Native `SubmitTx` still validates checkpoint-backed inputs. Signing-only mode separates submission responsibility; it does not admit an ordinary hardware UTXO into the native flow. Hardware approval of the actual transaction and the all-online-keys bypass experiment remain required.

Neither embedded execution nor a nil finalizer creates a committed fallback. The complete post-spend and post-renewal recovery graph must still succeed with online services unavailable. The caller must durably reconcile submit/finalize outcomes and capture successor recovery evidence, including failures after signatures have already been added to a packet.

Before adopting this head, resolve its outstanding review and qualify required indexer behavior. In the inspected `intent.go`, `expiryForScript` calls the indexer after detecting `OP_PUSHEXPIRY` without a nil check, although construction permits a nil indexer. Renewal qualification must include that configuration case. This observation comes from source inspection; no new runtime reproduction or full PR security review was performed here.

The next feasibility experiment should identify the engine's host, key owner, accepted transaction flow, finalization owner, and recovery-data owner together. That will determine which deployment components can be removed without changing the selected authority model.
