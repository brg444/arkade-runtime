package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/brg444/vaulted-guardian/internal/program"
)

const (
	vtxoPurposeSpend = "spend"

	vtxoStateReserved   = "reserved"
	vtxoStateSigned     = "signed"
	vtxoStateSubmitted  = "submitted"
	vtxoStateFinalized  = "finalized"
	vtxoStateAborted    = "aborted"
	vtxoStateUnresolved = "unresolved"

	VtxoPurposeSpend       = vtxoPurposeSpend
	VtxoFeePolicyDigestTag = "arkade-vault/arkade-intent-fee-policy/v1"
	MaxVtxoOperationInputs = 50

	VtxoStateReserved   = vtxoStateReserved
	VtxoStateSigned     = vtxoStateSigned
	VtxoStateSubmitted  = vtxoStateSubmitted
	VtxoStateFinalized  = vtxoStateFinalized
	VtxoStateAborted    = vtxoStateAborted
	VtxoStateUnresolved = vtxoStateUnresolved

	vtxoOperationCanonicalVer = 2
	vtxoOperationInputKind    = "input"
)

// VtxoOperation is one policy-spend row.
type VtxoOperation struct {
	OperationID            string
	VaultID                string
	Purpose                string
	BundleDigest           []byte
	State                  string
	AmountSats             int64
	FeeSats                int64
	FeePolicyDigest        []byte
	DestScript             []byte
	ChangeScript           []byte
	ChangeSats             int64
	ChangeVout             *uint32
	UnsignedPSBT           string
	AuthorizedPSBT         string
	PendingProofDigest     []byte
	AuthorizedPendingProof string
	CheckpointPSBTs        string
	CheckpointRequestPSBTs string
	CheckpointTapscript    []byte
	ArkTxid                string
	ExpiresAt              string
	CreatedAt              string
	LastDestScript         []byte
	IntegrityMAC           []byte
}

// VtxoOperationInput is one reserved outpoint for an operation.
type VtxoOperationInput struct {
	OperationID  string
	Txid         []byte
	Vout         int
	ValueSats    int64
	Script       []byte
	IntegrityMAC []byte
}

// VtxoBundleInput is one outpoint in the server-computed bundle digest.
type VtxoBundleInput struct {
	Txid      []byte
	Vout      uint32
	ValueSats uint64
}

// SealVtxoOperation authenticates every persisted operation field.
func SealVtxoOperation(rec *VtxoOperation, integrityKey []byte) error {
	if rec == nil {
		return fmt.Errorf("vtxo operation required")
	}
	mac, err := vtxoOperationMAC(*rec, integrityKey)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

// VerifyVtxoOperation rejects a missing, malformed, or modified row.
func VerifyVtxoOperation(rec *VtxoOperation, integrityKey []byte) error {
	if rec == nil || len(rec.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("vtxo operation integrity MAC missing or malformed")
	}
	want, err := vtxoOperationMAC(*rec, integrityKey)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(rec.IntegrityMAC, want) {
		return fmt.Errorf("vtxo operation integrity MAC mismatch")
	}
	return nil
}

// SealVtxoOperationInput authenticates one reserved outpoint row.
func SealVtxoOperationInput(rec *VtxoOperationInput, integrityKey []byte) error {
	if rec == nil {
		return fmt.Errorf("vtxo operation input required")
	}
	mac, err := vtxoOperationInputMAC(*rec, integrityKey)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

// VerifyVtxoOperationInput rejects a missing, malformed, or modified input.
func VerifyVtxoOperationInput(rec *VtxoOperationInput, integrityKey []byte) error {
	if rec == nil || len(rec.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("vtxo operation input integrity MAC missing or malformed")
	}
	want, err := vtxoOperationInputMAC(*rec, integrityKey)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(rec.IntegrityMAC, want) {
		return fmt.Errorf("vtxo operation input integrity MAC mismatch")
	}
	return nil
}

// CanonicalVtxoBundleInputs copies inputs, normalizes each txid, sorts by
// lowercase 64-hex then vout, and rejects duplicate outpoints. Digest and
// reserved set must share this order; callers cannot choose it.
func CanonicalVtxoBundleInputs(inputs []VtxoBundleInput) ([]VtxoBundleInput, error) {
	if len(inputs) > 0xffff {
		return nil, fmt.Errorf("too many vtxo inputs")
	}
	type keyed struct {
		in  VtxoBundleInput
		hex string
	}
	ordered := make([]keyed, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for i, in := range inputs {
		canon, raw, err := canonicalVtxoTxid(in.Txid)
		if err != nil {
			return nil, err
		}
		key := canon + ":" + fmt.Sprintf("%d", in.Vout)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("duplicate vtxo outpoint")
		}
		seen[key] = struct{}{}
		ordered[i] = keyed{
			in:  VtxoBundleInput{Txid: raw, Vout: in.Vout, ValueSats: in.ValueSats},
			hex: canon,
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].hex != ordered[j].hex {
			return ordered[i].hex < ordered[j].hex
		}
		return ordered[i].in.Vout < ordered[j].in.Vout
	})
	out := make([]VtxoBundleInput, len(ordered))
	for i := range ordered {
		out[i] = ordered[i].in
	}
	return out, nil
}

func canonicalVtxoTxid(txid []byte) (string, []byte, error) {
	var raw []byte
	switch len(txid) {
	case 32:
		raw = bytes.Clone(txid)
	case 64:
		decoded, err := hex.DecodeString(strings.ToLower(string(txid)))
		if err != nil || len(decoded) != 32 {
			return "", nil, fmt.Errorf("vtxo input txid must be 32 bytes or 64 hex chars")
		}
		raw = decoded
	default:
		return "", nil, fmt.Errorf("vtxo input txid must be 32 bytes or 64 hex chars")
	}
	return hex.EncodeToString(raw), raw, nil
}

// ComputeVtxoBundleDigest binds purpose and length-prefixes variable fields so
// dest/change scripts cannot be split at an embedded 0x00. Inputs are sorted
// internally; caller order is not trusted.
func ComputeVtxoBundleDigest(purpose, vaultID string, destScript, changeScript []byte, amountSats, feeSats, changeSats uint64, changeVout *uint32, feePolicyDigest []byte, inputs []VtxoBundleInput, createdAt string) ([]byte, error) {
	if purpose != vtxoPurposeSpend {
		return nil, fmt.Errorf("vtxo purpose must be spend")
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	if len(feePolicyDigest) != sha256.Size {
		return nil, fmt.Errorf("fee policy digest must be 32 bytes")
	}
	if changeSats == 0 {
		if changeVout != nil || len(changeScript) != 0 {
			return nil, fmt.Errorf("invalid no-change shape")
		}
	} else if changeSats < uint64(program.DustSats) || changeVout == nil || *changeVout != 1 || len(changeScript) == 0 {
		return nil, fmt.Errorf("invalid change shape")
	}
	ordered, err := CanonicalVtxoBundleInputs(inputs)
	if err != nil {
		return nil, err
	}
	if len(ordered) == 0 || len(ordered) > MaxVtxoOperationInputs {
		return nil, fmt.Errorf("vtxo input count must be 1..%d", MaxVtxoOperationInputs)
	}
	payload := make([]byte, 0, 256)
	payload, err = appendCredentialField(payload, []byte(purpose))
	if err != nil {
		return nil, err
	}
	payload, err = appendCredentialField(payload, []byte(vaultID))
	if err != nil {
		zeroBytes(payload)
		return nil, err
	}
	payload, err = appendCredentialField(payload, destScript)
	if err != nil {
		zeroBytes(payload)
		return nil, err
	}
	payload = binary.LittleEndian.AppendUint64(payload, amountSats)
	payload, err = appendCredentialField(payload, changeScript)
	if err != nil {
		zeroBytes(payload)
		return nil, err
	}
	payload = binary.LittleEndian.AppendUint64(payload, feeSats)
	payload = binary.LittleEndian.AppendUint64(payload, changeSats)
	if changeVout == nil {
		payload = append(payload, 0)
	} else {
		payload = append(payload, 1)
		payload = binary.LittleEndian.AppendUint32(payload, *changeVout)
	}
	payload, err = appendCredentialField(payload, feePolicyDigest)
	if err != nil {
		zeroBytes(payload)
		return nil, err
	}
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(ordered)))
	for _, in := range ordered {
		payload = append(payload, in.Txid...)
		payload = binary.LittleEndian.AppendUint32(payload, in.Vout)
		payload = binary.LittleEndian.AppendUint64(payload, in.ValueSats)
	}
	payload, err = appendCredentialField(payload, []byte(createdAt))
	if err != nil {
		zeroBytes(payload)
		return nil, err
	}
	sum := taggedSHA256(vtxoBundleDigestTag, payload)
	zeroBytes(payload)
	return sum, nil
}

// ComputeIntentFeePolicyDigest is shared with the wallet. It binds all four
// CEL strings, including explicitly empty programs, in the frozen field order.
func ComputeIntentFeePolicyDigest(offchainInput, offchainOutput, onchainInput, onchainOutput string) []byte {
	payload := make([]byte, 0, len(offchainInput)+len(offchainOutput)+len(onchainInput)+len(onchainOutput)+16)
	for _, program := range []string{offchainInput, offchainOutput, onchainInput, onchainOutput} {
		payload = binary.LittleEndian.AppendUint32(payload, uint32(len(program)))
		payload = append(payload, program...)
	}
	digest := taggedSHA256(VtxoFeePolicyDigestTag, payload)
	zeroBytes(payload)
	return digest
}

// ComputeVtxoReserveDigest authenticates the mutation that creates a durable
// reservation. The phone signs this before the server selects or locks any
// outpoint; operationID is the caller's already-persisted idempotency key.
func ComputeVtxoReserveDigest(operationID, vaultID, purpose string, destScript []byte, amountSats uint64) ([]byte, error) {
	operationRaw, err := hex.DecodeString(operationID)
	if err != nil || len(operationRaw) != 16 || operationID != strings.ToLower(operationID) {
		return nil, fmt.Errorf("operation id must be 16 bytes encoded as lowercase hex")
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	if purpose != vtxoPurposeSpend {
		return nil, fmt.Errorf("vtxo purpose must be spend")
	}
	if len(destScript) == 0 {
		return nil, fmt.Errorf("destination script required")
	}
	if amountSats == 0 {
		return nil, fmt.Errorf("amount required")
	}
	payload := make([]byte, 0, 128)
	payload = binary.LittleEndian.AppendUint32(payload, 1)
	for _, field := range [][]byte{operationRaw, []byte(vaultID), []byte(purpose), destScript} {
		payload, err = appendCredentialField(payload, field)
		if err != nil {
			zeroBytes(payload)
			return nil, err
		}
	}
	payload = binary.LittleEndian.AppendUint64(payload, amountSats)
	digest := taggedSHA256(vtxoReserveDigestTag, payload)
	zeroBytes(payload)
	return digest, nil
}

// ComputeVtxoAbortDigest authenticates the mutation that releases a
// pre-signature reservation. Signed and submitted operations have no digest
// because they are not abortable.
func ComputeVtxoAbortDigest(operationID, vaultID, purpose string) ([]byte, error) {
	operationRaw, err := hex.DecodeString(operationID)
	if err != nil || len(operationRaw) != 16 || operationID != strings.ToLower(operationID) {
		return nil, fmt.Errorf("operation id must be 16 bytes encoded as lowercase hex")
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	if purpose != vtxoPurposeSpend {
		return nil, fmt.Errorf("vtxo purpose must be spend")
	}
	payload := make([]byte, 0, 128)
	payload = binary.LittleEndian.AppendUint32(payload, 1)
	for _, field := range [][]byte{operationRaw, []byte(vaultID), []byte(purpose)} {
		payload, err = appendCredentialField(payload, field)
		if err != nil {
			zeroBytes(payload)
			return nil, err
		}
	}
	digest := taggedSHA256(vtxoAbortDigestTag, payload)
	zeroBytes(payload)
	return digest, nil
}

func taggedSHA256(tag string, msg []byte) []byte {
	th := sha256.Sum256([]byte(tag))
	h := sha256.New()
	_, _ = h.Write(th[:])
	_, _ = h.Write(th[:])
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func vtxoOperationMAC(rec VtxoOperation, integrityKey []byte) ([]byte, error) {
	if len(integrityKey) != sha256.Size {
		return nil, fmt.Errorf("vtxo operation integrity key must be 32 bytes")
	}
	payload, err := canonicalVtxoOperation(rec)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(payload)
	mac := hmac.New(sha256.New, integrityKey)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func vtxoOperationInputMAC(rec VtxoOperationInput, integrityKey []byte) ([]byte, error) {
	if len(integrityKey) != sha256.Size {
		return nil, fmt.Errorf("vtxo operation integrity key must be 32 bytes")
	}
	payload, err := canonicalVtxoOperationInput(rec)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(payload)
	mac := hmac.New(sha256.New, integrityKey)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func canonicalVtxoOperation(rec VtxoOperation) ([]byte, error) {
	if rec.OperationID == "" || rec.VaultID == "" {
		return nil, fmt.Errorf("vtxo operation identity required")
	}
	if rec.Purpose != vtxoPurposeSpend {
		return nil, fmt.Errorf("vtxo purpose must be spend")
	}
	if err := requireVtxoState(rec.State); err != nil {
		return nil, err
	}
	if len(rec.BundleDigest) != 32 {
		return nil, fmt.Errorf("bundle digest must be 32 bytes")
	}
	if rec.AmountSats < 0 || rec.FeeSats < 0 || rec.ChangeSats < 0 {
		return nil, fmt.Errorf("negative vtxo outflow")
	}
	if len(rec.FeePolicyDigest) != sha256.Size {
		return nil, fmt.Errorf("fee policy digest must be 32 bytes")
	}
	if (len(rec.PendingProofDigest) == 0) != (rec.AuthorizedPendingProof == "") {
		return nil, fmt.Errorf("pending proof persistence must be all-or-nothing")
	}
	if len(rec.PendingProofDigest) != 0 && len(rec.PendingProofDigest) != sha256.Size {
		return nil, fmt.Errorf("pending proof digest must be 32 bytes")
	}
	if rec.ChangeSats == 0 {
		if rec.ChangeVout != nil || len(rec.ChangeScript) != 0 {
			return nil, fmt.Errorf("invalid no-change shape")
		}
	} else if rec.ChangeSats < program.DustSats || rec.ChangeVout == nil || *rec.ChangeVout != 1 || len(rec.ChangeScript) == 0 {
		return nil, fmt.Errorf("invalid change shape")
	}
	out := make([]byte, 0, 512)
	var err error
	out, err = appendCredentialField(out, []byte(vtxoOperationMACDomain))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, vtxoOperationCanonicalVer)
	for _, field := range [][]byte{
		[]byte(rec.OperationID), []byte(rec.VaultID), []byte(rec.Purpose),
		rec.BundleDigest, []byte(rec.State), rec.FeePolicyDigest, rec.DestScript, rec.ChangeScript,
		[]byte(rec.UnsignedPSBT), []byte(rec.AuthorizedPSBT),
		rec.PendingProofDigest, []byte(rec.AuthorizedPendingProof),
		[]byte(rec.CheckpointPSBTs), []byte(rec.CheckpointRequestPSBTs), rec.CheckpointTapscript,
		[]byte(rec.ArkTxid), []byte(rec.ExpiresAt), []byte(rec.CreatedAt), rec.LastDestScript,
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.AmountSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.FeeSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.ChangeSats))
	if rec.ChangeVout == nil {
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = binary.LittleEndian.AppendUint32(out, *rec.ChangeVout)
	}
	return out, nil
}

func canonicalVtxoOperationInput(rec VtxoOperationInput) ([]byte, error) {
	if rec.OperationID == "" {
		return nil, fmt.Errorf("vtxo operation id required")
	}
	if len(rec.Txid) != 32 {
		return nil, fmt.Errorf("vtxo input txid must be 32 bytes")
	}
	if rec.Vout < 0 {
		return nil, fmt.Errorf("vtxo input vout")
	}
	if rec.ValueSats < 0 {
		return nil, fmt.Errorf("negative vtxo input value")
	}
	out := make([]byte, 0, 128)
	var err error
	out, err = appendCredentialField(out, []byte(vtxoOperationMACDomain))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, vtxoOperationCanonicalVer)
	out, err = appendCredentialField(out, []byte(vtxoOperationInputKind))
	if err != nil {
		zeroBytes(out)
		return nil, err
	}
	out, err = appendCredentialField(out, []byte(rec.OperationID))
	if err != nil {
		zeroBytes(out)
		return nil, err
	}
	out, err = appendCredentialField(out, rec.Txid)
	if err != nil {
		zeroBytes(out)
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, uint32(rec.Vout))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.ValueSats))
	out, err = appendCredentialField(out, rec.Script)
	if err != nil {
		zeroBytes(out)
		return nil, err
	}
	return out, nil
}

func requireVtxoState(state string) error {
	switch state {
	case vtxoStateReserved, vtxoStateSigned, vtxoStateSubmitted,
		vtxoStateFinalized, vtxoStateAborted, vtxoStateUnresolved:
		return nil
	default:
		return fmt.Errorf("unknown vtxo operation state")
	}
}

func vtxoStateCountsTowardAllowance(state string) bool {
	switch state {
	case vtxoStateReserved, vtxoStateSigned, vtxoStateSubmitted,
		vtxoStateFinalized, vtxoStateUnresolved:
		return true
	default:
		return false
	}
}

func vtxoStateAwaitingSettlement(state string) bool {
	return state == vtxoStateSigned || state == vtxoStateSubmitted
}

func vtxoStateBlocksNewOperation(state string) bool {
	switch state {
	case vtxoStateReserved, vtxoStateSigned, vtxoStateSubmitted, vtxoStateUnresolved:
		return true
	default:
		return false
	}
}

// vtxoStateLocksInputs is deliberately narrower than allowance accounting.
// Unresolved means the indexer proved that a different transaction already
// spent a reserved outpoint: the debit remains, but that dead reservation no
// longer needs to block overlap checks.
func vtxoStateLocksInputs(state string) bool {
	switch state {
	case vtxoStateReserved, vtxoStateSigned, vtxoStateSubmitted, vtxoStateFinalized:
		return true
	default:
		return false
	}
}
