# Spike 0 — `vault-policy-v1` yes/no table

Date: **2026-08-19**. Public pins only. Throwaway probe code is not product.

Later PR5 tree (not this spike): collaborative spend/intent is 3-key
`[user, VTXO VaultCosigner, Arkade Operator]`. The emulator is not a
VTXO tree signer. Row 4's 4-pub was a spike result, not the shipped tree.

| Pin | Value recorded this run |
| --- | --- |
| Emulator | `https://emulator.mutinynet.arkade.sh` |
| arkd | `https://mutinynet.arkade.sh` |
| SDK | `@arkade-os/sdk@0.4.28` (`arkade-wallet-vault/node_modules` and `arkade-os__ts-sdk`) |
| boltz-swap | `@arkade-os/boltz-swap@0.3.33` |
| Emulator source | `/Users/alexb./code/arkade-repo-mirrors/arkade-os__emulator` (matches advertised `v0.0.7-rc.1`) |

`GetInfo` has no opcode field. Do not treat absence of that field as presence of `OP_TUNNEL`.

## Live GetInfo (2026-08-19)

Emulator `GET https://emulator.mutinynet.arkade.sh/v1/info`:

```json
{"version":"v0.0.7-rc.1", "signerPubkey":"03f823b9b2febc81f4af967e77aed2f541cbd3397c6d8f5a72e32eb7b471af889a", "deprecatedSignerPubkeys":[]}
```

arkd `GET https://mutinynet.arkade.sh/v1/info` (trimmed):

```json
{
  "version": "",
  "signerPubkey": "03301078808e4f7bc0dadfe29e34b1df8eaf0108ef06b1722274075ebc107a127a",
  "checkpointTapscript": "03080040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac",
  "network": "mutinynet",
  "unilateralExitDelay": "2048",
  "boardingExitDelay": "604672",
  "maxOpReturnOutputs": "3"
}
```

## Summary table

Board-blocker column is the design gate. **No** on a board-blocker row stops board / spend / Lightning (PR 5–10). It does not stop PR 2 (KDF + listing without `exit`).

| # | Question | Answer | Kind | Board-blocker? | Stops board? |
| --- | --- | --- | --- | --- | --- |
| 1 | Custom leaf inject on 0.4.28 | **Yes** | code | Yes if no | no |
| 2 | `DefaultVtxo` change fallback — used or refuse? | **Used by SDK; can refuse** | code | Yes if cannot refuse | no (we can refuse) |
| 3 | Operational UTXO as settle/board input | **No** | code | Yes for direct daily board | **yes** |
| 4 | arkd 4-pub `[user, vtxoVault, tweakedEmu, arkd]` | **Yes** | code-only | Yes | no |
| 5 | Checkpoint signatures on kernel `SubmitTx` | **Yes** (API signs them; live success not obtained) | live endpoint + code | Yes | no |
| 6 | `signMultiple` used? | **No** on `SingleKey` page-local path | code | No | — |
| 7 | Metadata survival for custom contract type | **Yes**, client-local by script key | code | Yes | no |
| 8 | `UnilateralExitDelay` value + unit; in 144…2016 blocks (or equivalent seconds)? | **2048 seconds. Out of range.** | live + code | Yes | **yes** |
| 9 | `OP_TUNNEL` on the pinned public emulator | **No** | live + code | Yes | **yes** |
| 10 | arkd accepts 2-of-2 tunnel leaf + separate 4-pub on same tree | **Yes** | code-only | Yes | no |
| 11 | Upgrade vs fork (stay 0.4.28) | **Stay 0.4.28. No silent bump.** | record | Record only | — |
| 12 | L1 3-of-3 on unmodified arkd commitment without OP_RETURN / txid change? (a) or (b) | **No.** (a) no for vault daily. (b) no. `SubmitOnchainTx(same PSBT)` is not a yes. | live + code | Yes | **yes** |
| 13 | boltz-swap 0.3.33 `sendLightningPayment` assumes `DefaultVtxo`? | **Yes** (uses `wallet.send`) | code | No (do not call that API) | — |
| 14 | `updateContract` inactivate baseline `DefaultVtxo` after `Wallet.create`? | **Partial / no for `getVtxos()`** | code | No | — |

## Row evidence

### 1. Custom leaf inject on 0.4.28 — **Yes** (code)

`contractHandlers.register` is the public inject API. Built-ins (`default`, `delegate`, `vhtlc`) register the same way. `ContractManager.createContract` requires a registered handler and checks `handler.createScript(params)` against the provided `script`.

- `@arkade-os/sdk@0.4.28` `packages/ts-sdk/src/contracts/handlers/registry.ts` `register`
- `packages/ts-sdk/src/contracts/handlers/index.ts` registers `VHTLCContractHandler` as a non-default type
- `packages/ts-sdk/src/contracts/contractManager.ts` `upsertContract` throws `No handler registered for contract type`

A `vault-policy-v1` handler can be registered from the app without an SDK fork. Not live-exercised against arkd (no funds / no tree). The inject itself is SDK-local.

### 2. `DefaultVtxo` change fallback — **used; can refuse** (code)

`Wallet.create` always builds `offchainTapscript` / `boardingTapscript` as `DefaultVtxo.Script` (or `DelegateVtxo` if a delegate provider is set). `wallet.send` change is that tapscript. `initializeContractManager` `createContract`s those scripts as `state: "active"`.

Refuse by never calling `wallet.send` / `getAddress()` / omitted `settle()` dest, and by server-forcing change to `vault-policy-v1`. That is the product path. SDK cannot be configured to stop using DefaultVtxo internally; the app can refuse to consume it.

Board-blocker is only “if cannot refuse.” We can refuse.

### 3. Operational UTXO as settle/board input — **No** (code) — **board-blocker**

arkd boarding validation requires a VtxoScript whose every forfeit closure contains the **arkd signer pubkey**, and whose smallest exit delay is not shorter than `boardingExitDelay` (live **604672 seconds**).

Vault daily/normal L1 is a 3-of-3 `[PhoneRoutine, L1 VaultCosigner, tweaked emulator]`. It does **not** contain arkd. `TapscriptsVtxoScript.Validate` returns `"invalid forfeit closure, signer pubkey not found"`.

- `arkd/pkg/ark-lib/script/vtxo_script.go` `Validate`
- `arkd/internal/core/application/utils.go` `newBoardingInput` → `boardingScript.Validate(signerPubkey, boardingExitDelay, …)`
- `arkd/internal/core/application/service.go` `validateBoardingInput` same check

Advertising extra leaves that are not on the confirmed output breaks the tapkey match. No live register of a vault daily UTXO was attempted (would fail this check). Direct board of live daily UTXOs is **no**.

### 4. arkd 4-pub `[user, vtxoVault, tweakedEmu, arkd]` — **Yes** (code-only)

`MultisigClosure` encodes N-of-N `CHECKSIGVERIFY`…`CHECKSIG` with no 2-key cap. `Validate` only requires the arkd signer among forfeit pubs. A 4-pub leaf that includes arkd passes that check.

arkd e2e already registers a custom tree with a 3-pub `CLTVMultisigClosure` plus the classic 2-pub collaborative leaf (`internal/test/e2e/e2e_test.go`). SDK `MultisigTapscript.encode` accepts `pubkeys.length >= 1` of 32-byte x-only keys.

No live 4-pub VTXO was created on Mutinynet this run. Do not read this as a live batch accept.

### 5. Checkpoint signatures on kernel `SubmitTx` — **Yes** (live endpoint + code)

Proto and pin source: `SubmitTx` executes the Arkade script on the ark tx, then `signInput` on the matching checkpoint (`emulator/internal/application/tx.go`). Script does not execute on checkpoints.

Live 2026-08-19:

- `POST /v1/tx` `{}` → `{"code":3,"message":"missing ark tx"}`
- `POST /v1/tx` ark tx without checkpoints → `{"code":3,"message":"missing checkpoint txs"}`
- `POST /v1/tx` with a throwaway ark PSBT + dummy checkpoint whose packet script is `<0> OP_TUNNEL` → HTTP 500 `{"code":13,"message":"internal error"}` (handler maps all application errors to Internal; see `emulator_handler.go`)

A successful live checkpoint signature was not obtained (script exec fails first; see row 9). The pin does require and sign checkpoints on that RPC.

### 6. `signMultiple` used? — **No** (code; not a board-blocker)

`BatchSignableIdentity.signMultiple` exists. `isBatchSignable` is a type guard. `staticDescriptorProvider` is the call site.

`SingleKey` (the page-local `Wallet.create` identity) only implements `sign()`. Default path is `identity.sign`, not `signMultiple`. Implementation detail; droppable if unused.

### 7. Metadata survival for custom contract type — **Yes** (code)

`Contract.type` / `params` / `metadata` live in the client `contractRepository` (IndexedDB), keyed by `script`. arkd/indexer do not store contract type.

Same policy `script` across board/send/change keeps the type. `Wallet.send` change is hard-wired to `offchainTapscript` (`DefaultVtxo`) and would drop policy; we do not use that path. `createContract({ type: "vault-policy-v1", script })` is how type survives.

### 8. `UnilateralExitDelay` — **2048 seconds, out of range** (live + code) — **board-blocker**

Live arkd: `"unilateralExitDelay":"2048"`.

Unit: seconds. arkd client-lib and SDK treat `>= 512` as seconds (`LocktimeTypeSecond`). `checkpointTapscript` `03080040b275…` is BIP68 seconds (type flag + value 8 → 4096s unroll), consistent with a seconds-mode server.

Range gate: ship only if 144…2016 **blocks** or equivalent seconds. 144 is `program.OperationalCSVBlocks` (L1 Pending CSV). The VTXO hatch must not be the fast hole v5 removed from Normal.

| Reading | 144-block floor | 2016-block ceiling | 2048 seconds |
| --- | --- | --- | --- |
| Mutinynet ~30s/block | 4320 s | 60480 s | **below floor** (~68 blocks) |
| ark-lib `SECONDS_PER_BLOCK = 1` | 144 s | 2016 s | **above ceiling** |

Both readings are out of range. Frozen hatch must not be 2048 seconds.

### 9. `OP_TUNNEL` on the pin — **No** (live + code) — **board-blocker**

`GetInfoResponse` is only `version`, `signer_pubkey`, `deprecated_signer_pubkeys`. Recorded version: **`v0.0.7-rc.1`**.

Pin source `pkg/arkade/opcode.go`: byte `0xf7` is `OP_UNKNOWN247` → `opcodeInvalid`. No `OP_TUNNEL` symbol anywhere in the tree.

Unmerged [emulator#139](https://github.com/arkade-os/emulator/issues/139) / [PR #140](https://github.com/arkade-os/emulator/pull/140) (`feat/op-tunnel`) assigns `OP_TUNNEL = 0xf7`. That PR is **not** on the pin.

Throwaway probe 2026-08-19, Arkade script `<0> OP_TUNNEL` = `00f7`:

| Probe | Result |
| --- | --- |
| Local `Engine.Execute` on pin source | `attempt to execute invalid opcode OP_UNKNOWN247` |
| Live `POST /v1/onchain-tx` PSBT with type-`0x01` packet script `00f7` + tweaked-emu 1-pub leaf | HTTP 500 `{"code":13,"message":"internal error"}` (handler does not echo the opcode error) |
| Live `POST /v1/tx` same script + dummy checkpoint | same 500 Internal |

Opcode is not present. Do not substitute `enforceSelfSend`. **Do not board.**

### 10. 2-of-2 tunnel leaf + 4-pub on the same tree — **Yes** (code-only)

`TapscriptsVtxoScript` is an arbitrary list of closures. Forfeit closures are `MultisigClosure` / `CLTV` / `Condition`. Both `[tweakedTunnelEmulator, arkd]` and `[user, vtxoVault, tweakedEmulator, arkd]` contain arkd, so `Validate` accepts both on one tree. Tweaks are just different 32-byte keys; arkd does not know ArkScript.

No live two-tweak tree was submitted. Same caveat as row 4.

### 11. Upgrade vs fork — **stay 0.4.28** (record)

npm latest `@arkade-os/sdk` is `0.4.64` (includes an unverified `0.4.62`). Pin is `0.4.28`. Custom handler register works on 0.4.28 (row 1). Do not bump. Do not fork the SDK for leaf inject. Stay.

### 12. L1 3-of-3 on unmodified commitment — **No** (live + code) — **board-blocker**

Yes only if **(a)** a kernel API signs the routine leaf on **unmodified** commitment bytes without adding OP_RETURN / changing txid, **or (b)** arkd already emits/accepts a vault Emulator Packet on that commitment without tree-break.

`FindEmulatorPacket` scans **bitcoin tx outputs**, not PSBT unknowns (`pkg/arkade/emulator_packet.go`). `SubmitOnchainTx` fails `"no emulator packet found in transaction"` when there is no type-`0x01` OP_RETURN (`internal/application/onchain.go`). Adding an OP_RETURN changes the commitment txid and breaks the VTXO tree. **`SubmitOnchainTx(same PSBT)` is not a yes.** `Wallet.settle` only identity-signs.

**(a) no for vault daily.** `SubmitFinalization` can sign remaining intent-proof outpoints onto a commitment *without* writing an OP_RETURN on that commitment (`internal/application/finalization.go`). Live RPC exists (`POST /v1/finalization` `{}` → `missing signed intent`). That path still requires:

1. arkd to accept the outpoint as a boarding input — **row 3 is no** (no arkd pub on the daily leaf);
2. an Emulator Packet on the **intent proof**, then a prior emulator signature on that proof.

It does not sign an arbitrary L1 3-of-3 onto an unmodified arkd commitment that never went through `SubmitIntent` as an emulator-cosigned boarding script. A “script accepted” is not a yes.

**(b) no.** arkd commitment builder does not emit a vault type-`0x01` Emulator Packet. `maxOpReturnOutputs: 3` is a limit, not a vault packet. No arkd code path attaches `PacketType = 0x01` to the commitment.

Both (a) and (b) no → **do not board** (same stop as `OP_TUNNEL`). L1 `sendRoutineSpend` to a vault-built policy P2TR is dest change only, not board.

### 13. boltz-swap 0.3.33 `sendLightningPayment` assumes DefaultVtxo? — **Yes** (code)

Pinned `0.3.33` `sendLightningPayment` is `this.wallet.send({ address: lockup, amount: expectedAmount })`. Wallet change is `offchainTapscript` = `DefaultVtxo`. Expected. LN must not call `wallet.send` / `sendLightningPayment`. Not a board-blocker.

### 14. `updateContract` inactivate baseline DefaultVtxo? — **Partial / no for `getVtxos()`** (code)

`updateContract(script, { state: "inactive" })` persists and `watcher.updateContract`. `getWatchedContracts` drops inactive contracts that have no `lastKnownVtxos`.

`Wallet.getVtxos()` calls `getContractsWithVtxos()` with **no state filter**, so inactive DefaultVtxo VTXOs still mix in. Coin-select must not use `getVtxos()`. Not a board-blocker.

## Gate (PR 5–10)

This 2026-08-19 gate is for the superseded OP_TUNNEL / boarding design
this spike evaluated. It does not block the later SDK DelegatorManager
design. Fulmine `multi-presigned-signature` capability remains fail-closed;
do not treat delegation forwarding as production-ready.

Board-blocker **no** on this run: **3** (daily UTXO not a boarding input), **8** (`UnilateralExitDelay` 2048 seconds out of range), **9** (`OP_TUNNEL` absent on `v0.0.7-rc.1`), **12** (neither (a) nor (b) for unmodified-commitment 3-of-3). **That OP_TUNNEL / boarding design must not proceed.** Do not board, do not ship spend or Lightning, do not freeze `exit` / tunnel bytes. **PR 2 (KDF + pack listing without `exit`) may still land.** Re-run this table when the public emulator ships `OP_TUNNEL` and arkd boarding/exitDelay constraints are revisited; do not treat this file as a standing yes.
