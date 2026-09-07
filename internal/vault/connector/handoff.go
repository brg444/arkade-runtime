package connector

import (
	"bytes"
	"fmt"
	"math/bits"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// KeyOrigin is display/signing metadata. The public key must reproduce the
// enrolled connector script; a signer must independently derive the key.
type KeyOrigin struct {
	Type        Kind
	PublicKey   []byte // Compressed SEC key; parity matters for native SegWit.
	Fingerprint uint32 // Human-readable fingerprint interpreted as big-endian hex.
	Path        []uint32
}

// Request contains externally pinned contract data and independently resolved
// parents. No constructor here discovers coins, creates keys, or signs.
// SecondConnector carries the v2 second hardware reserve; it must be nil for
// v1 and non-nil for v2 (Rules.Version==2). HardwareSignatures carries the
// two hardware-first SINGLE approvals for v2 (P2TR 65-byte SINGLE, P2WPKH
// DER+SINGLE); HardwarePubKey carries the compressed key for P2WPKH only.
// v1 must leave all three nil/empty. Guardian production receives only the
// final candidate (sigs already in packet+inputs); these fields let tests
// build the same hardware-first final candidate.
type Request struct {
	Rules                             Rules
	Parents                           Parents
	Savings, Connector                wire.OutPoint
	SecondConnector                   *wire.OutPoint
	HardwareSignatures                [][]byte
	HardwarePubKey                    []byte
	SavingsScript, Leaf, Control      []byte
	DestinationScript                 []byte
	Phone, GuardianBase, EmulatorBase *btcec.PublicKey
	Origin                            KeyOrigin
	AmountSats, FeeSats               int64
}

// Draft retains a private snapshot. PSBT returns disposable copies so signer
// mutations cannot redefine the transaction that will eventually be accepted.
type Draft struct {
	rules         Rules
	parents       Parents
	packet        *psbt.Packet
	leaf, control []byte
}

func clonePacket(p *psbt.Packet) (*psbt.Packet, error) {
	var buf bytes.Buffer
	if err := p.Serialize(&buf); err != nil {
		return nil, err
	}
	return psbt.NewFromRawBytes(&buf, false)
}

// WitnessBytes is a lower bound so variable ECDSA lengths and explicit Taproot
// ALL signatures never weaken the fee-rate ceiling. The shortest DER signature
// plus ALL byte is nine bytes; a compressed public key is 33 bytes.
func WitnessBytes(leaf, control []byte, kind Kind) int64 {
	connector := 66
	if kind == NativeSegwit {
		connector = 45
	}
	return int64(2 + 1 + 3*65 + wire.VarIntSerializeSize(uint64(len(leaf))) + len(leaf) +
		wire.VarIntSerializeSize(uint64(len(control))) + len(control) + connector)
}

func Prepare(req Request) (*Draft, error) {
	if err := req.Rules.validate(); err != nil {
		return nil, err
	}
	dual := req.Rules.Version == 2
	if !dual && req.SecondConnector != nil {
		return nil, fmt.Errorf("second reserve requires dual contract")
	}
	if dual && req.SecondConnector == nil {
		return nil, fmt.Errorf("dual connector second reserve required")
	}
	if req.Savings == req.Connector || (dual && (*req.SecondConnector == req.Savings || *req.SecondConnector == req.Connector)) {
		return nil, fmt.Errorf("distinct outpoints required")
	}
	d := &Draft{rules: req.Rules, parents: Parents{}, leaf: bytes.Clone(req.Leaf), control: bytes.Clone(req.Control)}
	d.rules.ConnectorScript = bytes.Clone(req.Rules.ConnectorScript)
	outpoints := []wire.OutPoint{req.Savings, req.Connector}
	if dual {
		outpoints = []wire.OutPoint{req.Connector, *req.SecondConnector, req.Savings}
	}
	for _, op := range outpoints {
		if req.Parents.FetchPrevOutput(op) == nil {
			return nil, fmt.Errorf("verified parent required")
		}
		d.parents[op] = req.Parents[op].Copy()
	}
	s := d.parents.FetchPrevOutput(req.Savings)
	c := d.parents.FetchPrevOutput(req.Connector)
	reserveValue := req.Rules.ReserveValue()
	if !validP2TR(req.SavingsScript) || !bytes.Equal(s.PkScript, req.SavingsScript) ||
		!bytes.Equal(c.PkScript, d.rules.ConnectorScript) || c.Value != reserveValue {
		return nil, fmt.Errorf("enrolled input mismatch")
	}
	if dual {
		c2 := d.parents.FetchPrevOutput(*req.SecondConnector)
		if !bytes.Equal(c2.PkScript, d.rules.ConnectorScript) || c2.Value != reserveValue {
			return nil, fmt.Errorf("enrolled second reserve mismatch")
		}
		if !bytes.Equal(c.PkScript, c2.PkScript) {
			return nil, fmt.Errorf("dual reserves share one enrolled script")
		}
	}
	control, err := txscript.ParseControlBlock(d.control)
	if err != nil {
		return nil, err
	}
	if control.LeafVersion != txscript.BaseLeafVersion {
		return nil, fmt.Errorf("unexpected leaf version")
	}
	if err := txscript.VerifyTaprootLeafCommitment(control, req.SavingsScript[2:], d.leaf); err != nil {
		return nil, err
	}
	kind, err := req.Origin.Kind()
	if err != nil {
		return nil, err
	}
	wantWitness := expectedWitnessBytes(d.leaf, d.control, kind, d.rules.Version)
	if wantWitness != d.rules.WitnessBytes {
		return nil, fmt.Errorf("committed witness size mismatch")
	}
	key, err := btcec.ParsePubKey(req.Origin.PublicKey)
	if err != nil || len(req.Origin.PublicKey) != 33 {
		return nil, fmt.Errorf("compressed connector key required")
	}
	connectorScript, err := kind.Script(key)
	if err != nil || !bytes.Equal(connectorScript, c.PkScript) {
		return nil, fmt.Errorf("connector origin key mismatch")
	}
	path := req.Origin.Path
	// Check bounds before subtraction so hostile amounts cannot wrap.
	if s.Value <= 0 || s.Value > 21_000_000*100_000_000 || req.AmountSats < 294 || req.AmountSats > s.Value ||
		req.FeeSats < 0 || req.FeeSats > d.rules.AbsoluteFeeCapSats {
		return nil, fmt.Errorf("invalid Savings amount or fee")
	}
	change := s.Value - req.AmountSats - req.FeeSats - savings.P2AValueSats
	if change < 0 || (change > 0 && change < 330) {
		return nil, fmt.Errorf("Savings change must be absent or non-dust")
	}
	policy, err := BuildProgram(d.rules)
	if err != nil {
		return nil, err
	}
	if req.Phone == nil || req.GuardianBase == nil || req.EmulatorBase == nil {
		return nil, fmt.Errorf("pinned signing authorities required")
	}
	identities := []*btcec.PublicKey{req.Phone, key, req.GuardianBase, req.EmulatorBase}
	for i, pub := range identities {
		for _, other := range identities[:i] {
			if bytes.Equal(schnorr.SerializePubKey(pub), schnorr.SerializePubKey(other)) {
				return nil, fmt.Errorf("distinct enrolled identities required")
			}
		}
	}
	hash := arkade.ArkadeScriptHash(policy)
	g := arkade.ComputeArkadeScriptPublicKey(req.GuardianBase, hash)
	e := arkade.ComputeArkadeScriptPublicKey(req.EmulatorBase, hash)
	keys := []*btcec.PublicKey{req.Phone, g, e}
	for i, pub := range keys {
		for _, other := range keys[:i] {
			if bytes.Equal(schnorr.SerializePubKey(pub), schnorr.SerializePubKey(other)) {
				return nil, fmt.Errorf("distinct signing authorities required")
			}
		}
	}
	wantLeaf, err := savings.Checksig(keys...)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(d.leaf, wantLeaf) {
		return nil, fmt.Errorf("Savings leaf must bind phone and both connector programs")
	}
	packetOutput := []byte(nil)
	if !dual {
		packetOutput, err = packetScriptAt(policy, d.rules.SavingsIndex())
		if err != nil {
			return nil, err
		}
	} else {
		// Hardware-first: the two SINGLE approvals must be supplied so the
		// corrected packet witness can be filled before the candidate txid
		// freezes. P2TR sigs are 65-byte SINGLE; P2WPKH sigs DER+SINGLE.
		if len(req.HardwareSignatures) != 2 {
			return nil, fmt.Errorf("dual hardware approval required before Savings signatures")
		}
		var hwPub []byte
		if kind == Taproot {
			if len(req.HardwarePubKey) != 0 {
				return nil, fmt.Errorf("unexpected packet key for Taproot")
			}
		} else {
			if len(req.HardwarePubKey) != 33 {
				return nil, fmt.Errorf("compressed connector key required")
			}
			hwPub = bytes.Clone(req.HardwarePubKey)
		}
		witness, err := ApprovalWitness(policy, req.HardwareSignatures, req.DestinationScript, hwPub)
		if err != nil {
			return nil, err
		}
		packetOutput, err = PacketScriptWithWitness(policy, witness)
		if err != nil {
			return nil, err
		}
	}
	tx := wire.NewMsgTx(2)
	for _, op := range outpoints {
		op := op
		in := wire.NewTxIn(&op, nil, nil)
		in.Sequence = savings.TransitionSequence
		tx.AddTxIn(in)
	}
	if !dual {
		tx.AddTxOut(wire.NewTxOut(req.AmountSats, bytes.Clone(req.DestinationScript)))
		tx.AddTxOut(wire.NewTxOut(ReserveSats, bytes.Clone(c.PkScript)))
		tx.AddTxOut(wire.NewTxOut(savings.P2AValueSats, []byte{0x51, 0x02, 0x4e, 0x73}))
		tx.AddTxOut(wire.NewTxOut(0, packetOutput))
		if change > 0 {
			tx.AddTxOut(wire.NewTxOut(change, bytes.Clone(s.PkScript)))
		}
	} else {
		// Dual layout mirrors the wallet: recipient, optional Savings
		// change, both 500-sat reserves, anchor, packet. Savings is input 2
		// and the packet commits vin 2.
		tx.AddTxOut(wire.NewTxOut(req.AmountSats, bytes.Clone(req.DestinationScript)))
		if change > 0 {
			tx.AddTxOut(wire.NewTxOut(change, bytes.Clone(s.PkScript)))
		}
		tx.AddTxOut(wire.NewTxOut(reserveValue, bytes.Clone(c.PkScript)))
		tx.AddTxOut(wire.NewTxOut(reserveValue, bytes.Clone(c.PkScript)))
		tx.AddTxOut(wire.NewTxOut(savings.P2AValueSats, []byte{0x51, 0x02, 0x4e, 0x73}))
		tx.AddTxOut(wire.NewTxOut(0, packetOutput))
	}
	if err := Validate(d.rules, tx, d.parents); err != nil {
		return nil, err
	}
	d.packet, err = psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	for i, in := range tx.TxIn {
		parent := d.parents[in.PreviousOutPoint]
		d.packet.Inputs[i].NonWitnessUtxo = parent.Copy()
		out := d.parents.FetchPrevOutput(in.PreviousOutPoint)
		d.packet.Inputs[i].WitnessUtxo = wire.NewTxOut(out.Value, bytes.Clone(out.PkScript))
		if err := txutils.SetArkPsbtField(d.packet, i, arkade.PrevoutTxField, *parent); err != nil {
			return nil, err
		}
	}
	savingsInput := d.rules.SavingsIndex()
	d.packet.Inputs[savingsInput].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{ControlBlock: bytes.Clone(d.control), Script: bytes.Clone(d.leaf), LeafVersion: txscript.BaseLeafVersion}}
	d.packet.Inputs[savingsInput].TaprootInternalKey = schnorr.SerializePubKey(control.InternalKey)
	reserveIndices := d.rules.ReserveIndices()
	if kind == Taproot {
		internal := schnorr.SerializePubKey(key)
		for _, ri := range reserveIndices {
			d.packet.Inputs[ri].TaprootInternalKey = internal
			origin := &psbt.TaprootBip32Derivation{XOnlyPubKey: internal, MasterKeyFingerprint: bits.ReverseBytes32(req.Origin.Fingerprint), Bip32Path: append([]uint32(nil), path...)}
			d.packet.Inputs[ri].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{origin}
			if dual {
				d.packet.Inputs[ri].SighashType = txscript.SigHashSingle
			}
		}
		// Reserve change outputs mirror the enrolled script derivation.
		if !dual {
			d.packet.Outputs[ConnectorOutput].TaprootInternalKey = internal
			origin := &psbt.TaprootBip32Derivation{XOnlyPubKey: internal, MasterKeyFingerprint: bits.ReverseBytes32(req.Origin.Fingerprint), Bip32Path: append([]uint32(nil), path...)}
			d.packet.Outputs[ConnectorOutput].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{origin}
		} else {
			for _, oi := range reserveOutputIndices(len(tx.TxOut)) {
				origin := &psbt.TaprootBip32Derivation{XOnlyPubKey: internal, MasterKeyFingerprint: bits.ReverseBytes32(req.Origin.Fingerprint), Bip32Path: append([]uint32(nil), path...)}
				d.packet.Outputs[oi].TaprootInternalKey = internal
				d.packet.Outputs[oi].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{origin}
			}
		}
	} else {
		origin := &psbt.Bip32Derivation{PubKey: bytes.Clone(req.Origin.PublicKey), MasterKeyFingerprint: bits.ReverseBytes32(req.Origin.Fingerprint), Bip32Path: append([]uint32(nil), path...)}
		for _, ri := range reserveIndices {
			if dual {
				d.packet.Inputs[ri].SighashType = txscript.SigHashSingle
			} else if ri == ConnectorInput {
				d.packet.Inputs[ri].SighashType = txscript.SigHashAll
			}
			d.packet.Inputs[ri].Bip32Derivation = []*psbt.Bip32Derivation{origin}
		}
		if !dual {
			d.packet.Outputs[ConnectorOutput].Bip32Derivation = []*psbt.Bip32Derivation{origin}
		} else {
			for _, oi := range reserveOutputIndices(len(tx.TxOut)) {
				d.packet.Outputs[oi].Bip32Derivation = []*psbt.Bip32Derivation{origin}
			}
		}
	}
	if dual {
		// Retain the hardware-approved final candidate: reserve inputs
		// carry their SINGLE final witnesses (65-byte P2TR, DER+key
		// P2WPKH) exactly as the wallet persists before passkey.
		for j, ri := range reserveIndices {
			var final wire.TxWitness
			if kind == Taproot {
				final = wire.TxWitness{bytes.Clone(req.HardwareSignatures[j])}
			} else {
				final = wire.TxWitness{bytes.Clone(req.HardwareSignatures[j]), bytes.Clone(req.HardwarePubKey)}
			}
			var buf bytes.Buffer
			if err := psbt.WriteTxWitness(&buf, final); err != nil {
				return nil, err
			}
			d.packet.Inputs[ri].FinalScriptWitness = bytes.Clone(buf.Bytes())
			d.packet.Inputs[ri].FinalScriptSig = []byte{}
		}
	}
	return d, nil
}

// reserveOutputIndices returns the output positions carrying the enrolled
// hardware script for v2: indices 1/2 without change or 2/3 with change.
func reserveOutputIndices(outputCount int) []int {
	if outputCount == 6 {
		return []int{2, 3}
	}
	return []int{1, 2}
}

func (d *Draft) PSBT() (*psbt.Packet, error) { return clonePacket(d.packet) }

// HardwareRequest carries a verified, finalized Savings input so a device can
// validate the external input before signing its own. Actual device support
// and display behavior still require qualification.
type HardwareRequest struct {
	draft          *Draft
	savingsWitness wire.TxWitness
	packet         *psbt.Packet
}

func (d *Draft) ForHardware(witness wire.TxWitness) (*HardwareRequest, error) {
	if d.rules.Version == 2 {
		return nil, fmt.Errorf("v2 requires hardware approval before Savings signatures")
	}
	if len(witness) != 5 || !bytes.Equal(witness[3], d.leaf) || !bytes.Equal(witness[4], d.control) {
		return nil, fmt.Errorf("unexpected Savings witness")
	}
	for _, sig := range witness[:3] {
		if len(sig) != 64 {
			return nil, fmt.Errorf("Savings requires DEFAULT signatures")
		}
	}
	tx := d.packet.UnsignedTx.Copy()
	tx.TxIn[0].Witness = witness
	if err := verifyInput(tx, d.parents, 0); err != nil {
		return nil, fmt.Errorf("Savings signatures: %w", err)
	}
	p, err := d.PSBT()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := psbt.WriteTxWitness(&buf, witness); err != nil {
		return nil, err
	}
	// Clear obsolete signing metadata on the finalized foreign input.
	p.Inputs[0].TaprootLeafScript = nil
	p.Inputs[0].TaprootInternalKey = nil
	p.Inputs[0].FinalScriptWitness = bytes.Clone(buf.Bytes())
	// Explicitly encode the empty native-SegWit scriptSig. Electrum requires
	// both final fields to recognize a foreign witness input as complete.
	p.Inputs[0].FinalScriptSig = []byte{}
	w := make(wire.TxWitness, len(witness))
	for i := range witness {
		w[i] = bytes.Clone(witness[i])
	}
	return &HardwareRequest{draft: d, savingsWitness: w, packet: p}, nil
}

func (h *HardwareRequest) PSBT() (*psbt.Packet, error) { return clonePacket(h.packet) }

func verifyInput(tx *wire.MsgTx, parents Parents, index int) error {
	out := parents.FetchPrevOutput(tx.TxIn[index].PreviousOutPoint)
	engine, err := txscript.NewEngine(out.PkScript, tx, index, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, parents), out.Value, parents)
	if err != nil {
		return err
	}
	return engine.Execute()
}

// Accept imports only the connector's verified signature. Signer-supplied
// outputs, prevouts, foreign witnesses, and derivations never become authority.
// Both signatures and the transaction remain reusable for exact retransmission;
// confirmation/unspentness must be reconciled before choosing another outpoint.
func (h *HardwareRequest) Accept(response *psbt.Packet) (*wire.MsgTx, error) {
	if response == nil || response.UnsignedTx == nil || len(response.Inputs) != 2 || len(response.Outputs) != len(h.packet.Outputs) {
		return nil, fmt.Errorf("hardware response shape")
	}
	var want, got bytes.Buffer
	if err := h.packet.UnsignedTx.Serialize(&want); err != nil {
		return nil, err
	}
	if err := response.UnsignedTx.Serialize(&got); err != nil {
		return nil, err
	}
	if !bytes.Equal(want.Bytes(), got.Bytes()) {
		return nil, fmt.Errorf("hardware changed transaction")
	}
	for i, input := range response.Inputs {
		actual := h.packet.Inputs[i].WitnessUtxo
		if input.SighashType != txscript.SigHashDefault && (i != 1 || input.SighashType != txscript.SigHashAll) {
			return nil, fmt.Errorf("signature must commit all outputs")
		}
		if input.WitnessUtxo != nil && (input.WitnessUtxo.Value != actual.Value || !bytes.Equal(input.WitnessUtxo.PkScript, actual.PkScript)) {
			return nil, fmt.Errorf("hardware changed prevout")
		}
		if input.NonWitnessUtxo != nil && input.NonWitnessUtxo.TxHash() != h.packet.UnsignedTx.TxIn[i].PreviousOutPoint.Hash {
			return nil, fmt.Errorf("hardware changed parent")
		}
	}
	in := response.Inputs[1]
	if len(in.FinalScriptSig) != 0 || len(in.TaprootScriptSpendSig) != 0 {
		return nil, fmt.Errorf("unexpected connector signing path")
	}
	var witness wire.TxWitness
	if len(in.FinalScriptWitness) != 0 {
		reader := bytes.NewReader(in.FinalScriptWitness)
		count, err := wire.ReadVarInt(reader, 0)
		if err != nil || count < 1 || count > 2 {
			return nil, fmt.Errorf("unexpected connector witness")
		}
		for range count {
			item, err := wire.ReadVarBytes(reader, 0, 73, "connector witness")
			if err != nil {
				return nil, err
			}
			witness = append(witness, item)
		}
		if reader.Len() != 0 {
			return nil, fmt.Errorf("trailing connector witness data")
		}
	}
	if validP2TR(h.draft.rules.ConnectorScript) {
		if len(in.PartialSigs) != 0 {
			return nil, fmt.Errorf("unexpected ECDSA signature")
		}
		sig := in.TaprootKeySpendSig
		if witness != nil {
			if len(witness) != 1 {
				return nil, fmt.Errorf("Taproot key-path witness required")
			}
			if len(sig) != 0 && !bytes.Equal(sig, witness[0]) {
				return nil, fmt.Errorf("conflicting signatures")
			}
			sig = witness[0]
		}
		if len(sig) != 64 && (len(sig) != 65 || sig[64] != byte(txscript.SigHashAll)) {
			return nil, fmt.Errorf("Taproot DEFAULT or ALL signature required")
		}
		if in.SighashType == txscript.SigHashAll && len(sig) != 65 {
			return nil, fmt.Errorf("signature sighash mismatch")
		}
		witness = wire.TxWitness{bytes.Clone(sig)}
	} else {
		if len(in.TaprootKeySpendSig) != 0 || len(in.PartialSigs) > 1 {
			return nil, fmt.Errorf("unexpected connector signature")
		}
		if len(in.PartialSigs) == 1 {
			partial := in.PartialSigs[0]
			if witness != nil && (len(witness) != 2 || !bytes.Equal(witness[0], partial.Signature) || !bytes.Equal(witness[1], partial.PubKey)) {
				return nil, fmt.Errorf("conflicting signatures")
			}
			witness = wire.TxWitness{bytes.Clone(partial.Signature), bytes.Clone(partial.PubKey)}
		}
		if len(witness) != 2 || len(witness[0]) < 9 || len(witness[0]) > 73 || witness[0][len(witness[0])-1] != byte(txscript.SigHashAll) || len(witness[1]) != 33 {
			return nil, fmt.Errorf("native SegWit ALL signature required")
		}
	}
	tx := h.packet.UnsignedTx.Copy()
	tx.TxIn[0].Witness = make(wire.TxWitness, len(h.savingsWitness))
	for i, item := range h.savingsWitness {
		tx.TxIn[0].Witness[i] = bytes.Clone(item)
	}
	tx.TxIn[1].Witness = witness
	if err := verifyInput(tx, h.draft.parents, 1); err != nil {
		return nil, fmt.Errorf("hardware signature: %w", err)
	}
	return tx, nil
}

// AcceptTransaction supports wallets that return final transaction hex. The
// unsigned transaction must match exactly; only the connector witness is used.
func (h *HardwareRequest) AcceptTransaction(raw []byte) (*wire.MsgTx, error) {
	if len(raw) > 1_000_000 {
		return nil, fmt.Errorf("signer response too large")
	}
	reader := bytes.NewReader(raw)
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(reader); err != nil {
		return nil, err
	}
	if reader.Len() != 0 || len(tx.TxIn) != 2 {
		return nil, fmt.Errorf("invalid signer transaction")
	}
	var buf bytes.Buffer
	if err := psbt.WriteTxWitness(&buf, tx.TxIn[1].Witness); err != nil {
		return nil, err
	}
	for _, in := range tx.TxIn {
		if len(in.SignatureScript) != 0 {
			return nil, fmt.Errorf("unexpected scriptSig")
		}
		in.Witness = nil
	}
	p, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	p.Inputs[1].FinalScriptWitness = buf.Bytes()
	return h.Accept(p)
}
