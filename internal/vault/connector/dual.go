package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const DualName = "savings-connector-dual-v2"
const DualTemplate = "phone-connector-recovery-savings-v2"

func IsTemplate(template string) bool { return template == Template || template == DualTemplate }
func (r Rules) SavingsIndex() int {
	if r.Version == 2 {
		return 2
	}
	return SavingsInput
}
func (r Rules) ReserveIndices() []int {
	if r.Version == 2 {
		return []int{0, 1}
	}
	return []int{ConnectorInput}
}
func (r Rules) ReserveValue() int64 {
	if r.Version == 2 {
		return 500
	}
	return ReserveSats
}
func (r Rules) PacketIndex(count int) int {
	if r.Version == 2 {
		return count - 1
	}
	return PacketOutput
}
func (r Rules) InputCount() int {
	if r.Version == 2 {
		return 3
	}
	return 2
}
func (r Rules) OutputCount() int {
	if r.Version == 2 {
		return 5
	}
	return 4
}

// expectedWitnessBytes includes the second reserve for v2 while preserving
// the v1 bound used by existing enrolled programs.
func expectedWitnessBytes(leaf, control []byte, kind Kind, version int) int64 {
	w := WitnessBytes(leaf, control, kind)
	if version == 2 {
		if kind == Taproot {
			return w + 68
		}
		return w + 45
	}
	return w
}

// arkTag returns SHA256(s) || SHA256(s), the tagged-hash prefix input.
func arkTag(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return append(h[:], h[:]...)
}

// compactSize encodes n in Bitcoin compact-size format.
func compactSize(n int) []byte {
	if n < 253 {
		return []byte{byte(n)}
	}
	return []byte{253, byte(n), byte(n >> 8)}
}

// approvalChunkSizes returns the expected packet witness item sizes for the
// corrected contract: two compact hardware signatures, the length-prefixed
// padded recipient, the compressed key for native SegWit only, then the
// executing program in chunks of at most 500 bytes.
func approvalChunkSizes(taproot bool, programLen int) []int {
	sizes := []int{64, 64, 35}
	if !taproot {
		sizes = append(sizes, 33)
	}
	for remaining := programLen; remaining > 0; remaining -= 500 {
		if remaining > 500 {
			sizes = append(sizes, 500)
		} else {
			sizes = append(sizes, remaining)
		}
	}
	return sizes
}

// ApprovalWitness builds the packet witness for the corrected contract.
// P2TR signatures arrive as 65-byte SINGLE (suffix stripped to compact64);
// P2WPKH signatures arrive DER-encoded with SINGLE suffix and are converted
// to compact64 low-S, matching the Emulator CSFS 0x10 compact expectation.
// The recipient is length-prefixed and zero-padded to 35 bytes.
func ApprovalWitness(program []byte, sigs [][]byte, recipient []byte, pubKey []byte) (wire.TxWitness, error) {
	taproot := pubKey == nil
	if len(sigs) != 2 {
		return nil, fmt.Errorf("dual approval requires two hardware signatures")
	}
	if len(recipient) == 0 || len(recipient) > 34 {
		return nil, fmt.Errorf("recipient length")
	}
	encoded := make([][]byte, 0, 4)
	for _, s := range sigs {
		if taproot {
			if len(s) != 65 || s[64] != byte(txscript.SigHashSingle) {
				return nil, fmt.Errorf("Taproot SINGLE signature required")
			}
			encoded = append(encoded, bytes.Clone(s[:64]))
		} else {
			compact, err := derToCompactLowS(s)
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, compact)
		}
	}
	padded := make([]byte, 35)
	padded[0] = byte(len(recipient))
	copy(padded[1:], recipient)
	encoded = append(encoded, padded)
	if !taproot {
		if len(pubKey) != 33 {
			return nil, fmt.Errorf("compressed connector key required")
		}
		encoded = append(encoded, bytes.Clone(pubKey))
	}
	for len(program) > 0 {
		n := 500
		if len(program) < n {
			n = len(program)
		}
		encoded = append(encoded, bytes.Clone(program[:n]))
		program = program[n:]
	}
	return wire.TxWitness(encoded), nil
}

// buildDualPolicy is the byte-identical port of the wallet buildDualPolicy:
// the two-reserve covenant, protected change, anchor, and fee ceiling. The
// packet-envelope binding now lives in the approval proof wrapper; the caller
// appends VERIFY as the extra separator before the final TRUE.
func buildDualPolicy(r Rules) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	num := func(n int64) { b.AddInt64(n) }
	op := func(ops ...byte) {
		for _, o := range ops {
			b.AddOp(o)
		}
	}
	equal := func(o byte, n int64) { op(o); num(n); op(txscript.OP_EQUALVERIFY) }
	withChange := func() { op(arkade.OP_INSPECTNUMOUTPUTS); num(6); op(txscript.OP_EQUAL, txscript.OP_IF) }
	position := func(full int64) {
		withChange()
		num(full + 1)
		op(txscript.OP_ELSE)
		num(full)
		op(txscript.OP_ENDIF)
	}
	scriptCheck := func(o byte, script []byte) {
		op(o)
		if script[0] == txscript.OP_1 {
			num(1)
		} else {
			num(0)
		}
		op(txscript.OP_EQUALVERIFY)
		b.AddData(script[2:])
		op(txscript.OP_EQUALVERIFY)
	}
	b.AddData([]byte(DualName))
	op(txscript.OP_DROP)
	equal(arkade.OP_INSPECTVERSION, 2)
	equal(arkade.OP_INSPECTLOCKTIME, 0)
	equal(arkade.OP_INSPECTNUMINPUTS, 3)
	op(arkade.OP_INSPECTNUMOUTPUTS, txscript.OP_DUP)
	num(5)
	op(txscript.OP_EQUAL, txscript.OP_SWAP)
	num(6)
	op(txscript.OP_EQUAL, txscript.OP_BOOLOR, txscript.OP_VERIFY)
	for i := int64(0); i < 3; i++ {
		num(i)
		equal(arkade.OP_INSPECTINPUTSEQUENCE, savings.TransitionSequence)
	}
	for i := int64(0); i < 2; i++ {
		num(i)
		op(arkade.OP_INSPECTINPUTSCRIPTPUBKEY)
		if r.ConnectorScript[0] == txscript.OP_1 {
			num(1)
		} else {
			num(0)
		}
		op(txscript.OP_EQUALVERIFY)
		b.AddData(r.ConnectorScript[2:])
		op(txscript.OP_EQUALVERIFY)
		num(i)
		equal(arkade.OP_INSPECTINPUTVALUE, 500)
		position(i + 1)
		scriptCheck(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, r.ConnectorScript)
		position(i + 1)
		equal(arkade.OP_INSPECTOUTPUTVALUE, 500)
	}
	position(3)
	scriptCheck(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, []byte{0x51, 0x02, 0x4e, 0x73})
	position(3)
	equal(arkade.OP_INSPECTOUTPUTVALUE, 240)
	position(4)
	equal(arkade.OP_INSPECTOUTPUTVALUE, 0)
	withChange()
	num(2)
	op(arkade.OP_INSPECTINPUTSCRIPTPUBKEY, txscript.OP_TOALTSTACK)
	num(1)
	op(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, txscript.OP_FROMALTSTACK, txscript.OP_EQUALVERIFY, txscript.OP_EQUALVERIFY)
	num(1)
	op(arkade.OP_INSPECTOUTPUTVALUE)
	num(330)
	op(txscript.OP_GREATERTHANOREQUAL, txscript.OP_VERIFY, txscript.OP_ENDIF)
	num(0)
	op(arkade.OP_INSPECTOUTPUTVALUE)
	num(294)
	op(txscript.OP_GREATERTHANOREQUAL, txscript.OP_VERIFY)
	num(2)
	op(arkade.OP_INSPECTINPUTVALUE)
	num(0)
	op(arkade.OP_INSPECTOUTPUTVALUE, txscript.OP_SUB)
	position(3)
	op(arkade.OP_INSPECTOUTPUTVALUE, txscript.OP_SUB)
	withChange()
	num(1)
	op(arkade.OP_INSPECTOUTPUTVALUE, txscript.OP_SUB, txscript.OP_ENDIF)
	op(txscript.OP_DUP)
	num(0)
	op(txscript.OP_GREATERTHANOREQUAL, txscript.OP_VERIFY, txscript.OP_DUP)
	num(r.AbsoluteFeeCapSats)
	op(txscript.OP_LESSTHANOREQUAL, txscript.OP_VERIFY, arkade.OP_TXWEIGHT)
	num(r.WitnessBytes)
	op(txscript.OP_ADD)
	num(3)
	op(txscript.OP_ADD)
	num(4)
	op(txscript.OP_DIV)
	num(r.FeerateCapSatPerV)
	op(txscript.OP_MUL, txscript.OP_LESSTHANOREQUAL)
	return b.Script()
}

// buildApprovalProof is the byte-identical port of the wallet
// buildConnectorApprovalProof: witness-shape checks, incremental SHA256
// reconstruction of the executing program verified with
// INSPECTINPUTARKADESCRIPTHASH, canonical extension-output reconstruction,
// and independent BIP341/BIP143 SINGLE digest reconstruction with
// CHECKSIGFROMSTACK so NONE signatures cannot authorize. Length converges to
// a fixpoint like the wallet (20 rounds from 1000).
func buildApprovalProof(hardware []byte, extra []byte) ([]byte, error) {
	taproot := len(hardware) == 34
	length := 1000
	for round := 0; round < 20; round++ {
		b := txscript.NewScriptBuilder()
		num := func(n int64) { b.AddInt64(n) }
		op := func(ops ...byte) {
			for _, o := range ops {
				b.AddOp(o)
			}
		}
		data := func(d []byte) { b.AddData(d) }
		copyItem := func(i int) {
			op(txscript.OP_DEPTH)
			num(int64(i + 1))
			op(txscript.OP_SUB, txscript.OP_PICK)
		}
		var chunks []int
		for remaining := length; remaining > 0; remaining -= 500 {
			if remaining > 500 {
				chunks = append(chunks, 500)
			} else {
				chunks = append(chunks, remaining)
			}
		}
		start := 3
		if !taproot {
			start = 4
		}
		sizes := approvalChunkSizes(taproot, length)
		// Witness shape: stack depth plus each item length.
		op(txscript.OP_DEPTH)
		num(int64(len(sizes)))
		op(txscript.OP_EQUALVERIFY)
		for i, s := range sizes {
			copyItem(i)
			op(txscript.OP_SIZE)
			num(int64(s))
			op(txscript.OP_EQUALVERIFY, txscript.OP_DROP)
		}
		// Commit the supplied script chunks to the actual executing program.
		data(arkTag("ArkScriptHash"))
		op(arkade.OP_SHA256INITIALIZE)
		for j := range chunks {
			copyItem(j + start)
			op(arkade.OP_SHA256UPDATE)
		}
		data([]byte{})
		op(arkade.OP_SHA256FINALIZE)
		num(2)
		op(arkade.OP_INSPECTINPUTARKADESCRIPTHASH, txscript.OP_EQUALVERIFY)
		// Independently reconstruct the entire canonical extension output,
		// streamed below 520 bytes.
		prefix, err := exactPacketPrefix(length, sizes)
		if err != nil {
			return nil, err
		}
		data(append(prefix, append([]byte{1, 2, 0}, compactSize(length)...)...))
		op(arkade.OP_SHA256INITIALIZE)
		for j := range chunks {
			copyItem(j + start)
			op(arkade.OP_SHA256UPDATE)
		}
		witnessLen := len(compactSize(len(sizes)))
		for _, s := range sizes {
			witnessLen += len(compactSize(s)) + s
		}
		data(append(compactSize(witnessLen), compactSize(len(sizes))...))
		op(arkade.OP_SHA256UPDATE)
		for i, s := range sizes {
			data(compactSize(s))
			op(arkade.OP_SHA256UPDATE)
			copyItem(i)
			op(arkade.OP_SHA256UPDATE)
		}
		data([]byte{})
		op(arkade.OP_SHA256FINALIZE, arkade.OP_INSPECTNUMOUTPUTS)
		num(1)
		op(txscript.OP_SUB, arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY)
		num(-1)
		op(txscript.OP_EQUALVERIFY, txscript.OP_EQUALVERIFY)
		if !taproot {
			copyItem(3)
			op(txscript.OP_HASH160)
			data(hardware[2:])
			op(txscript.OP_EQUALVERIFY)
		}
		if taproot {
			// BIP341 keypath SINGLE preimage: tag, epoch, hash type,
			// version, locktime.
			data(append(arkTag("TapSighash"), mustHex("00030200000000000000")...))
			for i := int64(0); i < 3; i++ {
				num(i)
				op(arkade.OP_INSPECTINPUTOUTPOINT)
				num(4)
				op(arkade.OP_NUM2BIN, arkade.OP_CAT)
				if i > 0 {
					op(arkade.OP_CAT)
				}
			}
			op(txscript.OP_SHA256, arkade.OP_CAT)
			data(mustHex("f401000000000000f401000000000000"))
			num(2)
			op(arkade.OP_INSPECTINPUTVALUE)
			num(8)
			op(arkade.OP_NUM2BIN, arkade.OP_CAT, txscript.OP_SHA256, arkade.OP_CAT)
			data(append(append(append([]byte{byte(len(hardware))}, hardware...), byte(len(hardware))), append(hardware, mustHex("225120")...)...))
			num(2)
			op(arkade.OP_INSPECTINPUTSCRIPTPUBKEY)
			num(1)
			op(txscript.OP_EQUALVERIFY, arkade.OP_CAT, txscript.OP_SHA256, arkade.OP_CAT)
			h := sha256.Sum256(mustHex("fdfffffffdfffffffdffffff"))
			data(h[:])
			op(arkade.OP_CAT)
		}
		for i := int64(0); i < 2; i++ {
			if taproot {
				op(txscript.OP_DUP)
				data([]byte{0, byte(i), 0, 0, 0})
				op(arkade.OP_CAT)
			} else {
				data(mustHex("02000000"))
				for j := int64(0); j < 3; j++ {
					num(j)
					op(arkade.OP_INSPECTINPUTOUTPOINT)
					num(4)
					op(arkade.OP_NUM2BIN, arkade.OP_CAT)
					if j > 0 {
						op(arkade.OP_CAT)
					}
				}
				op(txscript.OP_HASH256, arkade.OP_CAT)
				data(make([]byte, 32))
				op(arkade.OP_CAT)
				num(i)
				op(arkade.OP_INSPECTINPUTOUTPOINT)
				num(4)
				op(arkade.OP_NUM2BIN, arkade.OP_CAT, arkade.OP_CAT)
				data(append(append(mustHex("1976a914"), hardware[2:]...), mustHex("88acf401000000000000fdffffff")...))
				op(arkade.OP_CAT)
			}
			num(i)
			op(arkade.OP_INSPECTOUTPUTVALUE)
			num(8)
			op(arkade.OP_NUM2BIN)
			if i == 0 {
				copyItem(2)
				op(txscript.OP_DUP)
				num(1)
				op(txscript.OP_LEFT, arkade.OP_BIN2NUM)
				num(1)
				op(txscript.OP_SWAP, txscript.OP_SUBSTR, txscript.OP_DUP)
				num(0)
				op(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY, txscript.OP_DUP)
				num(-1)
				op(txscript.OP_EQUAL, txscript.OP_IF, txscript.OP_DROP, txscript.OP_SWAP, txscript.OP_SHA256, txscript.OP_EQUALVERIFY, txscript.OP_ELSE)
				op(txscript.OP_DUP)
				num(0)
				op(txscript.OP_EQUAL, txscript.OP_IF)
				num(1)
				op(arkade.OP_NUM2BIN, txscript.OP_ELSE)
				num(80)
				op(txscript.OP_ADD)
				num(1)
				op(arkade.OP_NUM2BIN, txscript.OP_ENDIF, txscript.OP_SWAP, txscript.OP_SIZE)
				num(1)
				op(arkade.OP_NUM2BIN, txscript.OP_SWAP, arkade.OP_CAT, arkade.OP_CAT, txscript.OP_EQUALVERIFY, txscript.OP_ENDIF)
				op(txscript.OP_SIZE)
				num(1)
				op(arkade.OP_NUM2BIN, txscript.OP_SWAP, arkade.OP_CAT)
			} else {
				// Second approved output is either protected Taproot
				// change or the native reserve.
				op(arkade.OP_INSPECTNUMOUTPUTS)
				num(6)
				op(txscript.OP_EQUAL, txscript.OP_IF)
				data(mustHex("225120"))
				num(1)
				op(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY)
				num(1)
				op(txscript.OP_EQUALVERIFY, arkade.OP_CAT, txscript.OP_ELSE)
				data(append([]byte{byte(len(hardware))}, hardware...))
				op(txscript.OP_ENDIF)
			}
			if taproot {
				op(arkade.OP_CAT, txscript.OP_SHA256, arkade.OP_CAT)
			} else {
				op(arkade.OP_CAT, txscript.OP_HASH256, arkade.OP_CAT)
			}
			if !taproot {
				data(mustHex("0000000003000000"))
				op(arkade.OP_CAT)
			}
			if taproot {
				op(txscript.OP_SHA256)
			} else {
				op(txscript.OP_HASH256)
			}
			copyItem(int(i))
			op(txscript.OP_SWAP)
			if taproot {
				data(hardware[2:])
			} else {
				num(16)
				copyItem(3)
				op(arkade.OP_CAT)
			}
			op(arkade.OP_CHECKSIGFROMSTACK, txscript.OP_VERIFY)
		}
		if taproot {
			op(txscript.OP_DROP)
		}
		for range sizes {
			op(txscript.OP_DROP)
		}
		for _, opcode := range extra {
			b.AddOp(opcode)
		}
		num(1)
		result, err := b.Script()
		if err != nil {
			return nil, err
		}
		if len(result) == length {
			return result, nil
		}
		length = len(result)
	}
	return nil, fmt.Errorf("length convergence")
}

// BuildDualProgram wraps the dual policy with the approval proof.
func BuildDualProgram(r Rules) ([]byte, error) {
	policy, err := buildDualPolicy(r)
	if err != nil {
		return nil, err
	}
	extra := append(policy, txscript.OP_VERIFY)
	return buildApprovalProof(r.ConnectorScript, extra)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// exactPacketPrefix mirrors the wallet exactPacketOutputPrefix for vin 2
// with the given witness item sizes: the canonical extension envelope minus
// its trailing packet content.
func exactPacketPrefix(scriptLen int, sizes []int) ([]byte, error) {
	witness := make(wire.TxWitness, len(sizes))
	for i, s := range sizes {
		witness[i] = make([]byte, s)
	}
	entry, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 2, Script: make([]byte, scriptLen), Witness: witness})
	if err != nil {
		return nil, err
	}
	content, err := entry.Serialize()
	if err != nil {
		return nil, err
	}
	output, err := (extension.Extension{entry}).Serialize()
	if err != nil {
		return nil, err
	}
	if len(output) <= len(content) || !bytes.HasSuffix(output, content) {
		return nil, fmt.Errorf("noncanonical packet envelope")
	}
	return bytes.Clone(output[:len(output)-len(content)]), nil
}

// derToCompactLowS converts a DER+SINGLE signature to compact64 low-S,
// matching the Emulator CSFS 0x10 compact expectation.
func derToCompactLowS(sig []byte) ([]byte, error) {
	if len(sig) < 9 || len(sig) > 73 || sig[len(sig)-1] != byte(txscript.SigHashSingle) {
		return nil, fmt.Errorf("native SegWit SINGLE signature required")
	}
	parsed, err := ecdsa.ParseDERSignature(sig[:len(sig)-1])
	if err != nil {
		return nil, fmt.Errorf("invalid DER signature")
	}
	// Serialize normalizes S and DER; reject any noncanonical/high-S input.
	if !bytes.Equal(parsed.Serialize(), sig[:len(sig)-1]) {
		return nil, fmt.Errorf("canonical low-S DER signature required")
	}
	r, scalarS := parsed.R(), parsed.S()
	rb, sb := r.Bytes(), scalarS.Bytes()
	return append(rb[:], sb[:]...), nil
}

// ParseApprovalPacket decodes a v2 packet output and verifies its canonical
// shape: vin 2, script equal to the expected program, witness of compact
// sigs, padded recipient, optional compressed key, and program chunks that
// reassemble to the script. It returns the two compact signatures and the
// recipient script. All length and canonical checks mirror the wallet.
func ParseApprovalPacket(packetScript, program []byte, taproot bool) (sigs [][]byte, recipient []byte, err error) {
	packet, err := decodePacketOutput(packetScript)
	if err != nil {
		return nil, nil, err
	}
	if packet.Vin != 2 {
		return nil, nil, fmt.Errorf("approval packet vin 2 required")
	}
	if !bytes.Equal(packet.Script, program) {
		return nil, nil, fmt.Errorf("approval program mismatch")
	}
	wantSizes := approvalChunkSizes(taproot, len(program))
	if len(packet.Witness) != len(wantSizes) {
		return nil, nil, fmt.Errorf("approval witness shape")
	}
	for i, want := range wantSizes {
		if len(packet.Witness[i]) != want {
			return nil, nil, fmt.Errorf("approval witness item %d size", i)
		}
	}
	sigs = [][]byte{bytes.Clone(packet.Witness[0]), bytes.Clone(packet.Witness[1])}
	padded := packet.Witness[2]
	n := int(padded[0])
	if n <= 0 || n > 34 || len(padded) != 35 {
		return nil, nil, fmt.Errorf("approval recipient length")
	}
	recipient = bytes.Clone(padded[1 : 1+n])
	for _, b := range padded[1+n:] {
		if b != 0 {
			return nil, nil, fmt.Errorf("approval recipient padding")
		}
	}
	offset := 3
	if !taproot {
		offset = 4
	}
	var reassembled []byte
	for _, chunk := range packet.Witness[offset:] {
		reassembled = append(reassembled, chunk...)
	}
	if !bytes.Equal(reassembled, program) {
		return nil, nil, fmt.Errorf("approval program chunks mismatch")
	}
	return sigs, recipient, nil
}

// VerifyApprovalSignatures independently reconstructs the BIP341 (P2TR) or
// BIP143 (P2WPKH) SINGLE digests for both reserves and verifies the compact
// signatures, so a NONE signature can never authorize. Digests commit to the
// exact candidate transaction; recipient binding is checked by the caller
// against output 0. For P2WPKH the packet pubkey must be supplied and is
// proven against the enrolled script hash.
func VerifyApprovalSignatures(r Rules, tx *wire.MsgTx, parents Parents, sigs [][]byte, pubKey []byte) error {
	if len(sigs) != 2 {
		return fmt.Errorf("dual approval requires two hardware signatures")
	}
	taproot := validP2TR(r.ConnectorScript)
	if taproot && pubKey != nil {
		return fmt.Errorf("unexpected packet key for Taproot")
	}
	if !taproot {
		if len(pubKey) != 33 || (pubKey[0] != 0x02 && pubKey[0] != 0x03) {
			return fmt.Errorf("compressed connector key required")
		}
		if !pubkeyMatchesScript(pubKey, r.ConnectorScript) {
			return fmt.Errorf("packet key does not match enrolled script")
		}
	}
	for i, ri := range r.ReserveIndices() {
		out := parents.FetchPrevOutput(tx.TxIn[ri].PreviousOutPoint)
		if out == nil {
			return fmt.Errorf("unverified reserve parent")
		}
		if taproot {
			digest, err := calcTaprootSingleDigest(tx, parents, ri)
			if err != nil {
				return err
			}
			if !verifySchnorrCompact(sigs[i], digest, r.ConnectorScript[2:]) {
				return fmt.Errorf("invalid hardware SINGLE signature")
			}
		} else {
			digest, err := calcSegwitSingleDigest(tx, ri, out.PkScript, out.Value, parents)
			if err != nil {
				return err
			}
			if !verifyECDSACompact(sigs[i], digest, pubKey) {
				return fmt.Errorf("invalid hardware SINGLE signature")
			}
		}
	}
	return nil
}

type decodedPacket struct {
	Vin     int
	Script  []byte
	Witness wire.TxWitness
}

// decodePacketOutput parses a v2 packet output into its emulator entry.
// The output must carry exactly one entry; extra entries are rejected.
func decodePacketOutput(script []byte) (*decodedPacket, error) {
	ext, err := extension.NewExtensionFromBytes(script)
	if err != nil {
		return nil, fmt.Errorf("extension envelope: %w", err)
	}
	raw := ext.GetPacketByType(1)
	if raw == nil {
		return nil, fmt.Errorf("emulator packet required")
	}
	rawBytes, err := raw.Serialize()
	if err != nil {
		return nil, fmt.Errorf("emulator packet: %w", err)
	}
	entry, err := arkade.DeserializeEmulatorPacket(rawBytes)
	if err != nil {
		return nil, fmt.Errorf("emulator packet: %w", err)
	}
	if len(entry) != 1 {
		return nil, fmt.Errorf("exactly one emulator entry required")
	}
	return &decodedPacket{
		Vin:     int(entry[0].Vin),
		Script:  bytes.Clone(entry[0].Script),
		Witness: append(wire.TxWitness(nil), entry[0].Witness...),
	}, nil
}

// calcTaprootSingleDigest reconstructs the BIP341 keypath SINGLE digest for
// one hardware input over the exact candidate transaction.
func calcTaprootSingleDigest(tx *wire.MsgTx, parents Parents, idx int) ([]byte, error) {
	digest, err := txscript.CalcTaprootSignatureHash(
		txscript.NewTxSigHashes(tx, parents),
		txscript.SigHashSingle, tx, idx, parents,
	)
	if err != nil {
		return nil, fmt.Errorf("taproot SINGLE digest: %w", err)
	}
	return digest, nil
}

// calcSegwitSingleDigest reconstructs the BIP143 SINGLE digest for one
// native SegWit hardware input.
func calcSegwitSingleDigest(tx *wire.MsgTx, idx int, pkScript []byte, value int64, parents Parents) ([]byte, error) {
	if len(pkScript) != 22 || pkScript[0] != 0 || pkScript[1] != 20 {
		return nil, fmt.Errorf("native SegWit script required")
	}
	scriptCode := append(append([]byte{0x76, 0xa9, 0x14}, pkScript[2:]...), 0x88, 0xac)
	digest, err := txscript.CalcWitnessSigHash(
		scriptCode, txscript.NewTxSigHashes(tx, parents),
		txscript.SigHashSingle, tx, idx, value,
	)
	if err != nil {
		return nil, fmt.Errorf("segwit SINGLE digest: %w", err)
	}
	return digest, nil
}

// verifySchnorrCompact verifies a 64-byte compact signature against a
// 32-byte digest and x-only key.
func verifySchnorrCompact(sig, digest, xOnly []byte) bool {
	if len(sig) != 64 || len(digest) != 32 || len(xOnly) != 32 {
		return false
	}
	pub, err := schnorr.ParsePubKey(xOnly)
	if err != nil {
		return false
	}
	var sigArr [64]byte
	copy(sigArr[:], sig)
	var msg [32]byte
	copy(msg[:], digest)
	parsed, err := schnorr.ParseSignature(sigArr[:])
	if err != nil {
		return false
	}
	return parsed.Verify(msg[:], pub)
}

// verifyECDSACompact verifies a 64-byte compact (r||s) low-S signature
// against a 32-byte digest with the given compressed pubkey.
func verifyECDSACompact(sig, digest []byte, pubKey []byte) bool {
	if len(sig) != 64 || len(digest) != 32 || len(pubKey) != 33 {
		return false
	}
	pub, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		return false
	}
	var rScalar, sScalar btcec.ModNScalar
	// SetBytes takes [32]byte; r,s within range for valid sigs.
	var rArr, sArr [32]byte
	copy(rArr[:], sig[:32])
	copy(sArr[:], sig[32:])
	if rScalar.SetBytes(&rArr) != 0 {
		return false
	}
	if sScalar.SetBytes(&sArr) != 0 {
		return false
	}
	if rScalar.IsZero() || sScalar.IsZero() || sScalar.IsOverHalfOrder() {
		return false
	}
	parsed := ecdsa.NewSignature(&rScalar, &sScalar)
	return parsed.Verify(digest, pub)
}

// pubkeyMatchesScript proves the compressed key hashes to the enrolled
// P2WPKH script.
func pubkeyMatchesScript(pubKey, script []byte) bool {
	if len(pubKey) != 33 || len(script) != 22 {
		return false
	}
	return bytes.Equal(btcutil.Hash160(pubKey), script[2:])
}
