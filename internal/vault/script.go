package vault

import (
	"bytes"
	"crypto/elliptic"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// RoutineWitnessBytes is the serialized witness contribution expected
// by OP_TXWEIGHT for the Operational 3-of-3 Routine leaf: marker+flag,
// five witness items, three 64-byte signatures, the multisig script and its
// three-leaf control block. Tests bind this constant to the generated tree and
// a finalized witness so a template edit cannot silently weaken the feerate
// check committed below.
const RoutineWitnessBytes int64 = 399

// RoutineWitnessSize is the same count the on-chain OP_TXWEIGHT policy
// commits to. AuthorizationScript must keep using RoutineWitnessBytes;
// tests fail if this estimate and the committed constant drift.
func RoutineWitnessSize(script, control []byte) int64 {
	return int64(2 + compactSize(5) +
		3*(compactSize(64)+64) +
		compactSize(len(script)) + len(script) +
		compactSize(len(control)) + len(control))
}

func compactSize(n int) int {
	switch {
	case n < 0xfd:
		return 1
	case n <= 0xffff:
		return 3
	case n <= 0xffffffff:
		return 5
	default:
		return 9
	}
}

// AuthorizationScript is the committed transaction-local Operational policy.
// It requires the canonical one-input recipient/change/packet shape, caps the
// recipient and fee, requires recursive change to this exact vault, and then
// verifies the transaction-bound PhoneDirectP256 signature.
//
// The initial stack is a single compact low-S 64-byte P-256 signature over
// the current transaction's Arkade sighash. The enrolled key is the
// PRF-derived direct-auth P-256 public key, never the WebAuthn credential
// ES256 public key. WebAuthn clientDataJSON/authenticatorData and the stateful
// daily allowance stay in the private authorizer.
func AuthorizationScript(compressedDirectP256 []byte, policy AuthorizationPolicy) ([]byte, error) {
	if err := parseCanonicalCompressedP256(compressedDirectP256); err != nil {
		return nil, err
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	// The script commits to the exact last extension output by reconstructing
	// its constant envelope around OP_INSPECTPACKET's runtime content. Because
	// the packet itself contains this script, derive the envelope by length
	// until the script/envelope pair reaches a fixed point.
	var packetOutputPrefix []byte
	for i := 0; i < 8; i++ {
		script, err := buildAuthorizationScript(compressedDirectP256, policy, packetOutputPrefix)
		if err != nil {
			return nil, err
		}
		next, err := exactPacketOutputPrefix(len(script))
		if err != nil {
			return nil, err
		}
		if bytes.Equal(next, packetOutputPrefix) {
			return script, nil
		}
		packetOutputPrefix = next
	}
	return nil, fmt.Errorf("authorization script packet envelope did not converge")
}

func buildAuthorizationScript(compressedDirectP256 []byte, policy AuthorizationPolicy, packetOutputPrefix []byte) ([]byte, error) {
	key := append([]byte{0x11}, compressedDirectP256...)
	b := txscript.NewScriptBuilder().
		// Canonical transaction and input shape.
		AddOp(arkade.OP_INSPECTVERSION).
		AddInt64(2).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTLOCKTIME).
		AddInt64(0).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTNUMINPUTS).
		AddInt64(1).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTINPUTSEQUENCE).
		AddInt64(int64(wire.MaxTxInSequenceNum)).
		AddOp(txscript.OP_EQUALVERIFY).
		// Output zero is the recipient.
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(policy.RecipientDustSats).
		AddOp(txscript.OP_GREATERTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(policy.RecipientCapSats).
		AddOp(txscript.OP_LESSTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		// A native witness recipient prevents a second/moved extension from
		// occupying output zero. Combined with the exact extension-output hash
		// below, this pins the single packet output to the final position.
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(0).
		AddOp(txscript.OP_GREATERTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DROP).
		// Routine spends always contain recipient+recursive-change+packet.
		// Requiring non-dust same-script change prevents this path from being
		// used for a full drain or policy replacement.
		AddOp(arkade.OP_INSPECTNUMOUTPUTS).
		AddInt64(3).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(policy.RecipientDustSats).
		AddOp(txscript.OP_GREATERTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		// Compare the change witness program and Segwit version with the
		// current input's prevout, committing change to the same vault.
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(1).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddInt64(1).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(2).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(0).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(int64(arkade.PacketType)).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(txscript.OP_VERIFY).
		AddData(packetOutputPrefix).
		AddOp(txscript.OP_SWAP).
		AddOp(arkade.OP_CAT).
		AddOp(txscript.OP_SHA256).
		AddInt64(2).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(-1).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(txscript.OP_SUB).
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(txscript.OP_SUB).
		// Fee must be non-negative and satisfy both absolute and exact
		// feerate caps using the final three-signature witness size.
		AddOp(txscript.OP_DUP).
		AddInt64(0).
		AddOp(txscript.OP_GREATERTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DUP).
		AddInt64(policy.AbsoluteFeeCeilingSats).
		AddOp(txscript.OP_LESSTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DUP).
		AddOp(arkade.OP_TXWEIGHT).
		AddInt64(RoutineWitnessBytes).
		AddOp(txscript.OP_ADD).
		AddInt64(3).
		AddOp(txscript.OP_ADD).
		AddInt64(4).
		AddOp(txscript.OP_DIV).
		AddInt64(policy.FeerateCeilingSatPerV).
		AddOp(txscript.OP_MUL).
		AddOp(txscript.OP_LESSTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DROP).
		// Bind the user-authorized PhoneDirectP256 signature to this transaction.
		AddOp(txscript.OP_0).
		AddOp(arkade.OP_SIGHASH).
		AddData(key).
		AddOp(arkade.OP_CHECKSIGFROMSTACK)
	return b.Script()
}

// exactPacketOutputPrefix returns every byte of the canonical one-packet ARK
// extension script before the Emulator Packet content. Concatenating this
// prefix with OP_INSPECTPACKET's content reconstructs the exact scriptPubKey.
func exactPacketOutputPrefix(authScriptLen int) ([]byte, error) {
	if authScriptLen <= 0 {
		return nil, fmt.Errorf("authorization script length required")
	}
	packet, err := arkade.NewPacket(arkade.EmulatorEntry{
		Vin:     0,
		Script:  make([]byte, authScriptLen),
		Witness: wire.TxWitness{make([]byte, 64)},
	})
	if err != nil {
		return nil, err
	}
	content, err := packet.Serialize()
	if err != nil {
		return nil, err
	}
	outputScript, err := extension.Extension{packet}.Serialize()
	if err != nil {
		return nil, err
	}
	if len(outputScript) <= len(content) || !bytes.Equal(outputScript[len(outputScript)-len(content):], content) {
		return nil, fmt.Errorf("canonical packet output envelope")
	}
	return append([]byte(nil), outputScript[:len(outputScript)-len(content)]...), nil
}

// parseCanonicalCompressedP256 is a DirectP256 check, not a WebAuthn
// credential parse. It requires the unique compressed SEC1 encoding of an
// on-curve P-256 point.
func parseCanonicalCompressedP256(compressed []byte) error {
	if len(compressed) != 33 {
		return fmt.Errorf("compressed p256 key must be 33 bytes")
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		return fmt.Errorf("direct p256 compressed prefix")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return fmt.Errorf("direct p256 point is off-curve")
	}
	if !bytes.Equal(elliptic.MarshalCompressed(elliptic.P256(), x, y), compressed) {
		return fmt.Errorf("direct p256 compressed encoding is not canonical")
	}
	return nil
}
