# vault-policy-v1 one-input spend

Collaborative spend is a one-VTXO MVP. Reserve rejects any bundle that is
not exactly one spendable policy VTXO covering `amount + dust`. The wallet
must coin-select a single VTXO; it must not imply general multi-input
spending.

The Arkade script matches emulator `recursive_covenant_test.go`: one input,
dest bounds, change taproot equals the input VTXO script, change value
equals input minus dest. The SDK builds a v3 checkpoint
`[checkpoint output, P2A]` and an ark tx that spends the checkpoint and
appends P2A after caller outputs. The client inserts one
`EmulatorEntry{Vin:0, Script: exactScript}` with an empty witness
immediately before P2A, the same way emulator `addEmulatorPacket` does.

Version, locktime, sequence, P2A, and the packet are enforced by the
server. They are not encoded as script-number equals against LE32 inspect
pushes.
