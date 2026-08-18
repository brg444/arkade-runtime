package vault

import (
	"bytes"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// SpendParams describes one Operational routine spend.
type SpendParams struct {
	Vault           *Built
	PrevTx          *wire.MsgTx
	PrevOutPoint    wire.OutPoint
	RecipientScript []byte
	RecipientAmount int64
	Fee             int64
	Sequence        uint32
	Witness         wire.TxWitness // empty for challenge computation
}

// BuiltSpend is the unsigned routine PSBT plus derived digests.
type BuiltSpend struct {
	Packet       *psbt.Packet
	Challenge    []byte
	ChangeAmount int64
	HasChange    bool
	InputValue   int64
	Prevout      *wire.TxOut
}

// BuildRoutineSpend builds the exact one-input / recipient / mandatory
// recursive-change / packet template. A routine request can never fully drain
// or replace this descriptor because it must return non-dust change to the
// identical current vault script.
func BuildRoutineSpend(p SpendParams) (*BuiltSpend, error) {
	if p.Vault == nil || p.Vault.Leaves.Routine == nil {
		return nil, fmt.Errorf("operational routine leaf required")
	}
	if len(p.RecipientScript) == 0 {
		return nil, fmt.Errorf("recipient script required")
	}
	if !txscript.IsWitnessProgram(p.RecipientScript) {
		return nil, fmt.Errorf("routine recipient must be a native segwit output")
	}
	prev, err := checkedPrevout(p.Vault, p.PrevTx, p.PrevOutPoint)
	if err != nil {
		return nil, err
	}
	if p.Fee < 0 || p.RecipientAmount <= 0 {
		return nil, fmt.Errorf("invalid amount")
	}
	if p.RecipientAmount < p.Vault.Record.AuthorizationPolicy.RecipientDustSats {
		return nil, fmt.Errorf("recipient below dust")
	}

	change, err := remainingAfter(prev.Value, p.RecipientAmount, p.Fee)
	if err != nil {
		return nil, err
	}
	if change < p.Vault.Record.AuthorizationPolicy.RecipientDustSats {
		return nil, fmt.Errorf("routine spend requires non-dust recursive change")
	}

	tx := wire.NewMsgTx(2)
	seq := p.Sequence
	if seq == 0 {
		seq = wire.MaxTxInSequenceNum
	}
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: p.PrevOutPoint,
		Sequence:         seq,
	})
	tx.AddTxOut(&wire.TxOut{Value: p.RecipientAmount, PkScript: p.RecipientScript})
	tx.AddTxOut(&wire.TxOut{Value: change, PkScript: p.Vault.PkScript})

	entry := arkade.EmulatorEntry{
		Vin:     0,
		Script:  p.Vault.Record.AuthScript,
		Witness: p.Witness,
	}
	if err := attachPacket(tx, entry); err != nil {
		return nil, err
	}

	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	packet.Inputs[0].WitnessUtxo = &wire.TxOut{Value: prev.Value, PkScript: prev.PkScript}
	packet.Inputs[0].SighashType = txscript.SigHashDefault
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: p.Vault.Leaves.Routine.ControlBlock,
		Script:       p.Vault.Leaves.Routine.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	if err := txutils.SetArkPsbtField(packet, 0, arkade.PrevoutTxField, *p.PrevTx); err != nil {
		return nil, err
	}

	challenge, err := Challenge(packet, p.Vault)
	if err != nil {
		return nil, err
	}
	return &BuiltSpend{
		Packet:       packet,
		Challenge:    challenge,
		ChangeAmount: change,
		HasChange:    true,
		InputValue:   prev.Value,
		Prevout:      prev,
	}, nil
}

func attachPacket(tx *wire.MsgTx, entry arkade.EmulatorEntry) error {
	pkt, err := arkade.NewPacket(entry)
	if err != nil {
		return err
	}
	ext := extension.Extension{pkt}
	out, err := ext.TxOut()
	if err != nil {
		return err
	}
	if out.Value != 0 {
		return fmt.Errorf("emulator packet output must be zero value")
	}
	tx.AddTxOut(out)
	return nil
}

// Challenge is the witness-masked Arkade SIGHASH_DEFAULT digest.
func Challenge(ptx *psbt.Packet, vault *Built) ([]byte, error) {
	if len(ptx.UnsignedTx.TxIn) != 1 || len(ptx.Inputs) != 1 {
		return nil, fmt.Errorf("expected one input")
	}
	prev := ptx.Inputs[0].WitnessUtxo
	if prev == nil {
		return nil, fmt.Errorf("missing witness utxo")
	}
	fetcher := NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	if vault == nil || vault.Leaves.Routine == nil {
		return nil, fmt.Errorf("routine leaf required")
	}
	leaf := txscript.NewBaseTapLeaf(vault.Leaves.Routine.Script)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
	return arkade.CalcArkadeScriptSignatureHash(
		sigHashes, txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, leaf,
	)
}

// SetPacketWitness replaces the emulator packet witness and leaves the
// challenge unchanged (witness bytes are masked).
func SetPacketWitness(tx *wire.MsgTx, witness wire.TxWitness) error {
	entry, script, err := packetEntry(tx)
	if err != nil {
		return err
	}
	entry.Witness = witness
	// Rebuild the extension output in place.
	for i, out := range tx.TxOut {
		if !extension.IsExtension(out.PkScript) {
			continue
		}
		pkt, err := arkade.NewPacket(arkade.EmulatorEntry{
			Vin:     entry.Vin,
			Script:  script,
			Witness: witness,
		})
		if err != nil {
			return err
		}
		ext := extension.Extension{pkt}
		repl, err := ext.TxOut()
		if err != nil {
			return err
		}
		tx.TxOut[i] = repl
		return nil
	}
	return fmt.Errorf("emulator packet output not found")
}

func packetEntry(tx *wire.MsgTx) (arkade.EmulatorEntry, []byte, error) {
	packet, err := arkade.FindEmulatorPacket(tx)
	if err != nil {
		return arkade.EmulatorEntry{}, nil, err
	}
	if len(packet) != 1 {
		return arkade.EmulatorEntry{}, nil, fmt.Errorf("expected one emulator entry")
	}
	return packet[0], packet[0].Script, nil
}

// PrevFetcher implements arkade.ArkPrevOutFetcher for a single verified prevout.
type PrevFetcher struct {
	txscript.PrevOutputFetcher
	op  wire.OutPoint
	tx  *wire.MsgTx
	idx uint32
}

// NewPrevFetcher wraps one outpoint/output.
func NewPrevFetcher(op wire.OutPoint, out *wire.TxOut) *PrevFetcher {
	return &PrevFetcher{
		PrevOutputFetcher: txscript.NewCannedPrevOutputFetcher(out.PkScript, out.Value),
		op:                op,
		idx:               op.Index,
	}
}

// WithPrevTx attaches the verified previous transaction for FetchPrevOutArkTx.
func (f *PrevFetcher) WithPrevTx(tx *wire.MsgTx) *PrevFetcher {
	f.tx = tx
	return f
}

func (f *PrevFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if op != f.op {
		return nil
	}
	return f.tx
}

func (f *PrevFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if op != f.op || f.tx == nil {
		return nil
	}
	if int(f.idx) >= len(f.tx.TxOut) {
		return nil
	}
	return f.tx.TxOut[f.idx].PkScript
}

// SignLeaf produces a BIP342 SIGHASH_DEFAULT tapscript signature.
func SignLeaf(tx *wire.MsgTx, prev *wire.TxOut, leafScript []byte, priv *btcec.PrivateKey) ([]byte, error) {
	fetcher := txscript.NewCannedPrevOutputFetcher(prev.PkScript, prev.Value)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	leaf := txscript.NewBaseTapLeaf(leafScript)
	sig, err := txscript.RawTxInTapscriptSignature(
		tx, sigHashes, 0, prev.Value, prev.PkScript, leaf, txscript.SigHashDefault, priv,
	)
	if err != nil {
		return nil, err
	}
	if len(sig) == 65 {
		return sig[:64], nil
	}
	return sig, nil
}

// AddPartialSig appends a taproot script spend signature to the PSBT input.
func AddPartialSig(ptx *psbt.Packet, pub *btcec.PublicKey, leafHash, sig []byte) {
	ptx.Inputs[0].TaprootScriptSpendSig = append(ptx.Inputs[0].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(pub),
		LeafHash:    leafHash,
		Signature:   sig,
		SigHash:     txscript.SigHashDefault,
	})
}

// FinalizeRoutine builds the Bitcoin witness from the PhoneRoutineBIP340,
// private VaultCosigner, and public ArkadeCosigner partial signatures.
// It fail-closes on nil inputs, a preexisting final script, the wrong leaf,
// duplicate/extra keys, a non-default sighash, or an invalid signature.
func FinalizeRoutine(ptx *psbt.Packet, v *Built) error {
	if err := verifyRoutinePartials(ptx, v); err != nil {
		return err
	}
	return writeFinalWitness(ptx, v.Leaves.Routine)
}

func verifyRoutinePartials(ptx *psbt.Packet, v *Built) error {
	if ptx == nil || ptx.UnsignedTx == nil || v == nil || v.Leaves.Routine == nil || v.Record.PhoneRoutineBIP340 == nil || v.TweakedVaultCosigner == nil || v.TweakedArkadeCosigner == nil {
		return fmt.Errorf("routine finalize inputs")
	}
	if len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("exactly one input required")
	}
	in := &ptx.Inputs[0]
	if len(in.FinalScriptWitness) != 0 || len(in.FinalScriptSig) != 0 {
		return fmt.Errorf("preexisting final script")
	}
	if in.WitnessUtxo == nil {
		return fmt.Errorf("witness utxo required")
	}
	if len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return fmt.Errorf("exactly one taproot leaf required")
	}
	leaf := in.TaprootLeafScript[0]
	if !bytes.Equal(leaf.Script, v.Leaves.Routine.Script) || !bytes.Equal(leaf.ControlBlock, v.Leaves.Routine.ControlBlock) {
		return fmt.Errorf("leaf is not the routine path")
	}
	if leaf.LeafVersion != txscript.BaseLeafVersion {
		return fmt.Errorf("unsupported leaf version")
	}
	wantPhone := schnorr.SerializePubKey(v.Record.PhoneRoutineBIP340)
	wantVault := schnorr.SerializePubKey(v.TweakedVaultCosigner)
	wantArkade := schnorr.SerializePubKey(v.TweakedArkadeCosigner)
	wantLeaf := v.Leaves.Routine.Hash
	var phoneSig, vaultSig, arkadeSig *psbt.TaprootScriptSpendSig
	seen := make(map[string]struct{})
	for _, s := range in.TaprootScriptSpendSig {
		if s == nil {
			return fmt.Errorf("nil taproot signature")
		}
		key := string(s.XOnlyPubKey) + string(s.LeafHash)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate taproot signature")
		}
		seen[key] = struct{}{}
		if s.SigHash != txscript.SigHashDefault {
			return fmt.Errorf("unsupported sighash")
		}
		if !bytes.Equal(s.LeafHash, wantLeaf) {
			return fmt.Errorf("wrong leaf hash")
		}
		switch {
		case bytes.Equal(s.XOnlyPubKey, wantPhone):
			if phoneSig != nil {
				return fmt.Errorf("duplicate phone routine signature")
			}
			phoneSig = s
		case bytes.Equal(s.XOnlyPubKey, wantVault):
			if vaultSig != nil {
				return fmt.Errorf("duplicate vault cosigner signature")
			}
			vaultSig = s
		case bytes.Equal(s.XOnlyPubKey, wantArkade):
			if arkadeSig != nil {
				return fmt.Errorf("duplicate arkade emulator signature")
			}
			arkadeSig = s
		default:
			return fmt.Errorf("unexpected taproot key")
		}
	}
	if phoneSig == nil || vaultSig == nil || arkadeSig == nil || len(in.TaprootScriptSpendSig) != 3 {
		return fmt.Errorf("expected phone routine, tweaked vault cosigner, and tweaked arkade cosigner signatures")
	}
	if err := verifySchnorrTapSig(ptx, phoneSig, wantPhone, v.Leaves.Routine.Script); err != nil {
		return fmt.Errorf("phone routine signature: %w", err)
	}
	if err := verifySchnorrTapSig(ptx, vaultSig, wantVault, v.Leaves.Routine.Script); err != nil {
		return fmt.Errorf("vault cosigner signature: %w", err)
	}
	if err := verifySchnorrTapSig(ptx, arkadeSig, wantArkade, v.Leaves.Routine.Script); err != nil {
		return fmt.Errorf("arkade emulator signature: %w", err)
	}
	return nil
}

func verifySchnorrTapSig(ptx *psbt.Packet, s *psbt.TaprootScriptSpendSig, wantXOnly, leafScript []byte) error {
	if len(s.Signature) != 64 {
		return fmt.Errorf("signature length")
	}
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	digest, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher),
		txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, txscript.NewBaseTapLeaf(leafScript),
	)
	if err != nil {
		return err
	}
	sig, err := schnorr.ParseSignature(s.Signature)
	if err != nil {
		return err
	}
	pub, err := schnorr.ParsePubKey(wantXOnly)
	if err != nil {
		return err
	}
	if !sig.Verify(digest, pub) {
		return fmt.Errorf("invalid")
	}
	return nil
}

func writeFinalWitness(ptx *psbt.Packet, leaf *Leaf) error {
	if ptx == nil || leaf == nil || leaf.Closure == nil {
		return fmt.Errorf("missing leaf")
	}
	if len(ptx.Inputs) != 1 {
		return fmt.Errorf("exactly one input required")
	}
	sigs := map[string][]byte{}
	for _, s := range ptx.Inputs[0].TaprootScriptSpendSig {
		sigs[fmt.Sprintf("%x", s.XOnlyPubKey)] = s.Signature
	}
	wit, err := leaf.Closure.Witness(leaf.ControlBlock, sigs)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := psbt.WriteTxWitness(&buf, wit); err != nil {
		return err
	}
	ptx.Inputs[0].FinalScriptWitness = buf.Bytes()
	return nil
}

// ExecuteFinalizedRoutine runs the standard-script engine against the
// finalized routine input and the verified prevout. Callers must
// finalize a clone first.
func ExecuteFinalizedRoutine(ptx *psbt.Packet, v *Built) error {
	if ptx == nil || v == nil {
		return fmt.Errorf("execute inputs")
	}
	return executeFinalizedInput(ptx)
}

// ExecuteFinalizedAdmin runs the standard-script engine after exact
// ExternalOwnerWallet+RecoveryKey finalization. It is useful to file-only
// handoff tools as a final witness-order and control-block check.
func ExecuteFinalizedAdmin(ptx *psbt.Packet, v *Built) error {
	if ptx == nil || v == nil || v.Leaves.Admin == nil {
		return fmt.Errorf("execute admin inputs")
	}
	return executeFinalizedInput(ptx)
}

func executeFinalizedInput(ptx *psbt.Packet) error {
	tx, err := ExtractFinalizedTx(ptx)
	if err != nil {
		return err
	}
	prev := ptx.Inputs[0].WitnessUtxo
	if prev == nil {
		return fmt.Errorf("witness utxo required")
	}
	fetcher := NewPrevFetcher(tx.TxIn[0].PreviousOutPoint, prev)
	eng, err := txscript.NewEngine(
		prev.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), prev.Value, fetcher,
	)
	if err != nil {
		return err
	}
	return eng.Execute()
}

// FinalizeAdmin builds the Bitcoin witness from the PhoneRoutineBIP340 and
// ExternalOwnerWallet admin signatures.
func FinalizeAdmin(ptx *psbt.Packet, vault *Built) error {
	if vault == nil || vault.Leaves.Admin == nil || vault.Record.ExternalOwnerWallet == nil || vault.Record.PhoneRoutineBIP340 == nil {
		return fmt.Errorf("admin finalize inputs")
	}
	prevTx, err := RequireVerifiedPrevout(ptx)
	if err != nil {
		return fmt.Errorf("admin prevout: %w", err)
	}
	op := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
	if _, err := checkedPrevout(vault, prevTx, op); err != nil {
		return fmt.Errorf("admin prevout: %w", err)
	}
	if err := verifyExactLeafPartials(
		ptx, vault.Leaves.Admin,
		vault.Record.PhoneRoutineBIP340, vault.Record.ExternalOwnerWallet,
	); err != nil {
		return err
	}
	return writeFinalWitness(ptx, vault.Leaves.Admin)
}

func verifyExactLeafPartials(ptx *psbt.Packet, leaf *Leaf, expected ...*btcec.PublicKey) error {
	if ptx == nil || ptx.UnsignedTx == nil || leaf == nil {
		return fmt.Errorf("missing leaf")
	}
	if len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("exactly one input required")
	}
	in := &ptx.Inputs[0]
	if len(in.FinalScriptWitness) != 0 || len(in.FinalScriptSig) != 0 {
		return fmt.Errorf("preexisting final script")
	}
	if in.WitnessUtxo == nil {
		return fmt.Errorf("witness utxo required")
	}
	if len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return fmt.Errorf("exactly one taproot leaf required")
	}
	gotLeaf := in.TaprootLeafScript[0]
	if gotLeaf.LeafVersion != txscript.BaseLeafVersion ||
		!bytes.Equal(gotLeaf.Script, leaf.Script) ||
		!bytes.Equal(gotLeaf.ControlBlock, leaf.ControlBlock) {
		return fmt.Errorf("unexpected admin leaf")
	}
	if len(in.TaprootScriptSpendSig) != len(expected) {
		return fmt.Errorf("expected exactly %d admin signatures", len(expected))
	}
	want := make(map[string][]byte, len(expected))
	for _, pub := range expected {
		if pub == nil {
			return fmt.Errorf("admin signer key required")
		}
		xonly := schnorr.SerializePubKey(pub)
		want[string(xonly)] = xonly
	}
	seen := make(map[string]struct{}, len(expected))
	for _, sig := range in.TaprootScriptSpendSig {
		if sig == nil || sig.SigHash != txscript.SigHashDefault || !bytes.Equal(sig.LeafHash, leaf.Hash) {
			return fmt.Errorf("invalid admin signature metadata")
		}
		key := string(sig.XOnlyPubKey)
		wantKey, ok := want[key]
		if !ok {
			return fmt.Errorf("unexpected admin signer")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate admin signer")
		}
		seen[key] = struct{}{}
		if err := verifySchnorrTapSig(ptx, sig, wantKey, leaf.Script); err != nil {
			return fmt.Errorf("admin signature: %w", err)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("missing admin signer")
	}
	return nil
}

// ExtractFinalizedTx copies the unsigned transaction and attaches the
// finalized input witness. It does not re-sign.
func ExtractFinalizedTx(ptx *psbt.Packet) (*wire.MsgTx, error) {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 {
		return nil, fmt.Errorf("finalized psbt")
	}
	if len(ptx.Inputs[0].FinalScriptWitness) == 0 {
		return nil, fmt.Errorf("missing final script witness")
	}
	wit, err := txutils.ReadTxWitness(ptx.Inputs[0].FinalScriptWitness)
	if err != nil {
		return nil, err
	}
	tx := ptx.UnsignedTx.Copy()
	tx.TxIn[0].Witness = wit
	return tx, nil
}

// AdminSpend builds a PhoneRoutine+ExternalOwnerWallet full sweep or policy
// migration with no emulator packet. The optional recursive change is an
// explicit admin decision and is never exposed through routine HTTP routes.
func AdminSpend(v *Built, prevTx *wire.MsgTx, op wire.OutPoint, dest []byte, destAmt, fee int64, sequence uint32) (*psbt.Packet, error) {
	if v == nil || v.Leaves.Admin == nil {
		return nil, fmt.Errorf("admin leaf required")
	}
	if len(dest) == 0 {
		return nil, fmt.Errorf("destination script required")
	}
	prev, err := checkedPrevout(v, prevTx, op)
	if err != nil {
		return nil, err
	}
	if destAmt < fixture.DustSats || fee < 0 {
		return nil, fmt.Errorf("invalid amount")
	}
	change, err := remainingAfter(prev.Value, destAmt, fee)
	if err != nil {
		return nil, err
	}
	tx := wire.NewMsgTx(2)
	if sequence == 0 {
		sequence = wire.MaxTxInSequenceNum
	}
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Sequence: sequence})
	tx.AddTxOut(&wire.TxOut{Value: destAmt, PkScript: dest})
	switch {
	case change == 0:
		// fully consumed
	case change >= fixture.DustSats && !bytes.Equal(dest, v.PkScript):
		tx.AddTxOut(&wire.TxOut{Value: change, PkScript: v.PkScript})
	default:
		return nil, fmt.Errorf("owner spend does not balance")
	}
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: prev.Value, PkScript: prev.PkScript}
	ptx.Inputs[0].SighashType = txscript.SigHashDefault
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: v.Leaves.Admin.ControlBlock,
		Script:       v.Leaves.Admin.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	if err := txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, *prevTx); err != nil {
		return nil, err
	}
	return ptx, nil
}

// RecoverySpend builds a delayed single-key spend. v4 uses the hardware CSV
// leaf (lost device). A v3 Recovery leaf is still accepted if present.
func RecoverySpend(v *Built, prevTx *wire.MsgTx, op wire.OutPoint, dest []byte, destAmt, fee int64) (*psbt.Packet, error) {
	if v == nil {
		return nil, fmt.Errorf("recovery leaf required")
	}
	leaf := v.Leaves.HardwareCSV
	if leaf == nil {
		leaf = v.Leaves.Recovery
	}
	if leaf == nil {
		return nil, fmt.Errorf("recovery leaf required")
	}
	if len(dest) == 0 {
		return nil, fmt.Errorf("destination script required")
	}
	if destAmt < fixture.DustSats || fee < 0 {
		return nil, fmt.Errorf("invalid amount")
	}
	prev, err := checkedPrevout(v, prevTx, op)
	if err != nil {
		return nil, err
	}
	lock := v.Record.HardwareCSV
	if lock.Value == 0 {
		lock = v.Record.CSV
	}
	seq, err := arklib.BIP68Sequence(lock)
	if err != nil {
		return nil, err
	}
	left, err := remainingAfter(prev.Value, destAmt, fee)
	if err != nil {
		return nil, err
	}
	if left != 0 {
		return nil, fmt.Errorf("recovery spend must consume the input")
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Sequence: seq})
	tx.AddTxOut(&wire.TxOut{Value: destAmt, PkScript: dest})
	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, err
	}
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: prev.Value, PkScript: prev.PkScript}
	ptx.Inputs[0].SighashType = txscript.SigHashDefault
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: leaf.ControlBlock,
		Script:       leaf.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	return ptx, nil
}

func checkedPrevout(v *Built, prevTx *wire.MsgTx, op wire.OutPoint) (*wire.TxOut, error) {
	if v == nil {
		return nil, fmt.Errorf("vault required")
	}
	if prevTx == nil {
		return nil, fmt.Errorf("prevout transaction required")
	}
	if prevTx.TxHash() != op.Hash {
		return nil, fmt.Errorf("prevout tx hash mismatch")
	}
	if int(op.Index) >= len(prevTx.TxOut) {
		return nil, fmt.Errorf("prevout index out of range")
	}
	prev := prevTx.TxOut[op.Index]
	if prev == nil {
		return nil, fmt.Errorf("missing prevout")
	}
	if !bytes.Equal(prev.PkScript, v.PkScript) {
		return nil, fmt.Errorf("prevout script is not this vault")
	}
	if err := requireSats(prev.Value, "prevout"); err != nil {
		return nil, err
	}
	return prev, nil
}

func requireSats(v int64, name string) error {
	if v < 0 || v > btcutil.MaxSatoshi {
		return fmt.Errorf("%s outside bitcoin money range", name)
	}
	return nil
}

func subSats(lhs, rhs int64) (int64, error) {
	if rhs < 0 || lhs < rhs {
		return 0, fmt.Errorf("outputs exceed input")
	}
	return lhs - rhs, nil
}

func remainingAfter(input, amount, fee int64) (int64, error) {
	if err := requireSats(input, "input"); err != nil {
		return 0, err
	}
	if err := requireSats(amount, "amount"); err != nil {
		return 0, err
	}
	if err := requireSats(fee, "fee"); err != nil {
		return 0, err
	}
	afterAmount, err := subSats(input, amount)
	if err != nil {
		return 0, err
	}
	return subSats(afterAmount, fee)
}

// RequireVerifiedPrevout loads PrevoutTxField and checks hash, vout and WitnessUtxo.
func RequireVerifiedPrevout(ptx *psbt.Packet) (*wire.MsgTx, error) {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one input required")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return nil, fmt.Errorf("witness utxo required")
	}
	fields, err := txutils.GetArkPsbtFields(ptx, 0, arkade.PrevoutTxField)
	if err != nil {
		return nil, err
	}
	if len(fields) != 1 {
		return nil, fmt.Errorf("PrevoutTxField required")
	}
	prev := fields[0]
	op := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
	if prev.TxHash() != op.Hash {
		return nil, fmt.Errorf("prevout tx hash mismatch")
	}
	if int(op.Index) >= len(prev.TxOut) {
		return nil, fmt.Errorf("prevout vout out of range")
	}
	want := prev.TxOut[op.Index]
	got := ptx.Inputs[0].WitnessUtxo
	if want == nil || got.Value != want.Value || !bytes.Equal(got.PkScript, want.PkScript) {
		return nil, fmt.Errorf("witness utxo does not match prevout")
	}
	return &prev, nil
}

// HashFromStr is a thin helper for tests and the demo.
func HashFromStr(s string) (*chainhash.Hash, error) {
	return chainhash.NewHashFromStr(s)
}
