package v5

import (
	"bytes"
	"crypto/elliptic"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	P2AScriptHex          = "51024e73"
	P2AValueSats          = 240
	P2AOutputIndex        = 1
	PacketOutputIndex     = 2
	TransitionOutputCount = 3
	TransitionSequence    = 0xfffffffd
	WitnessBytes399       = 399
	WitnessBytes431       = 431
	DirectP256CSFSPrefix  = 0x11
)

var p2aProgram = []byte{0x4e, 0x73}

// InitiateWitnessBytes is the OP_TXWEIGHT contribution for a 3-of-3
// initiate leaf. Daily phone/hardware sit one merkle level deeper.
const WitnessBytes367 int64 = 367

func InitiateWitnessBytes(kind, claimant string, hasRecovery bool) int64 {
	if hasRecovery {
		if kind == "daily" && (claimant == "phone" || claimant == "hardware") {
			return WitnessBytes431
		}
		return WitnessBytes399
	}
	if kind == "savings" && claimant == "hardware" {
		return WitnessBytes367
	}
	return WitnessBytes399
}

func ClawbackWitnessBytes() int64 { return WitnessBytes399 }

// BuildTransitionScript pins dest, funded P2A, packet, fee, and optional
// PhoneDirectP256 CSFS. Phone initiate is the only bound path.
func BuildTransitionScript(destScript []byte, phoneDirect []byte, witnessBytes int64) ([]byte, error) {
	dest, err := p2trProgram(destScript)
	if err != nil {
		return nil, err
	}
	if witnessBytes <= 0 {
		return nil, fmt.Errorf("witness bytes required")
	}
	var phone []byte
	if len(phoneDirect) > 0 {
		if err := parseCanonicalCompressedP256(phoneDirect); err != nil {
			return nil, err
		}
		phone = append([]byte(nil), phoneDirect...)
	}
	var prefix []byte
	for i := 0; i < 8; i++ {
		script, err := assembleTransitionScript(dest, prefix, phone, witnessBytes)
		if err != nil {
			return nil, err
		}
		next, err := exactPacketOutputPrefix(len(script), phone != nil)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(next, prefix) {
			return script, nil
		}
		prefix = next
	}
	return nil, fmt.Errorf("authorization script packet envelope did not converge")
}

func assembleTransitionScript(dest, prefix, phone []byte, witnessBytes int64) ([]byte, error) {
	b := txscript.NewScriptBuilder().
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
		AddInt64(TransitionSequence).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTNUMOUTPUTS).
		AddInt64(TransitionOutputCount).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(1).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(dest).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(program.DustSats).
		AddOp(txscript.OP_GREATERTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddInt64(P2AOutputIndex).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(1).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(p2aProgram).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(P2AOutputIndex).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(P2AValueSats).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(PacketOutputIndex).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(0).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(int64(arkade.PacketType)).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(txscript.OP_VERIFY).
		AddData(prefix).
		AddOp(txscript.OP_SWAP).
		AddOp(arkade.OP_CAT).
		AddOp(txscript.OP_SHA256).
		AddInt64(PacketOutputIndex).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(-1).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(txscript.OP_SUB).
		AddInt64(P2AOutputIndex).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(txscript.OP_SUB).
		AddOp(txscript.OP_DUP).
		AddInt64(0).
		AddOp(txscript.OP_GREATERTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DUP).
		AddInt64(program.AbsoluteFeeCeiling).
		AddOp(txscript.OP_LESSTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DUP).
		AddOp(arkade.OP_TXWEIGHT).
		AddInt64(witnessBytes).
		AddOp(txscript.OP_ADD).
		AddInt64(3).
		AddOp(txscript.OP_ADD).
		AddInt64(4).
		AddOp(txscript.OP_DIV).
		AddInt64(program.FeerateCeilingSatPerV).
		AddOp(txscript.OP_MUL).
		AddOp(txscript.OP_LESSTHANOREQUAL).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DROP)
	if len(phone) > 0 {
		key := append([]byte{DirectP256CSFSPrefix}, phone...)
		b.AddOp(txscript.OP_0).
			AddOp(arkade.OP_SIGHASH).
			AddData(key).
			AddOp(arkade.OP_CHECKSIGFROMSTACK)
	} else {
		b.AddInt64(1)
	}
	return b.Script()
}

func exactPacketOutputPrefix(authScriptLen int, phoneBound bool) ([]byte, error) {
	if authScriptLen <= 0 {
		return nil, fmt.Errorf("authorization script length required")
	}
	entry := arkade.EmulatorEntry{
		Vin:    0,
		Script: make([]byte, authScriptLen),
	}
	if phoneBound {
		entry.Witness = wire.TxWitness{make([]byte, 64)}
	} else {
		entry.Witness = wire.TxWitness{}
	}
	packet, err := arkade.NewPacket(entry)
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

func p2trProgram(script []byte) ([]byte, error) {
	if len(script) != 34 || script[0] != 0x51 || script[1] != 0x20 {
		return nil, fmt.Errorf("dest must be a 34-byte p2tr script")
	}
	return append([]byte(nil), script[2:]...), nil
}

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
