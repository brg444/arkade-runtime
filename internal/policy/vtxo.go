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
)

const (
	vtxoPurposeSpend = "spend"
	vtxoPurposeBoard = "board"

	vtxoStateReserved   = "reserved"
	vtxoStateSigned     = "signed"
	vtxoStateSubmitted  = "submitted"
	vtxoStateFinalized  = "finalized"
	vtxoStateAborted    = "aborted"
	vtxoStateUnresolved = "unresolved"

	VtxoPurposeSpend = vtxoPurposeSpend
	// VtxoPurposeBoard remains a digest/MAC token for schema 9 rows. HTTP
	// spend routes must not accept it.
	VtxoPurposeBoard = vtxoPurposeBoard

	VtxoStateReserved   = vtxoStateReserved
	VtxoStateSigned     = vtxoStateSigned
	VtxoStateSubmitted  = vtxoStateSubmitted
	VtxoStateFinalized  = vtxoStateFinalized
	VtxoStateAborted    = vtxoStateAborted
	VtxoStateUnresolved = vtxoStateUnresolved

	vtxoOperationCanonicalVer = 1
	vtxoOperationInputKind    = "input"
)

// VtxoOperation is one boarding or policy-spend row. It is a separate
// ledger from issuance; the MAC domain is not issuance-record/v3.
type VtxoOperation struct {
	OperationID         string
	VaultID             string
	Purpose             string
	BundleDigest        []byte
	State               string
	AmountSats          int64
	FeeSats             int64
	DestScript          []byte
	ChangeScript        []byte
	UnsignedPSBT        string
	AuthorizedPSBT      string
	CheckpointPSBTs     string
	CommitmentPSBT      string
	CheckpointTapscript []byte
	ArkTxid             string
	ExpiresAt           string
	CreatedAt           string
	LastDestScript      []byte
	IntegrityMAC        []byte
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
func ComputeVtxoBundleDigest(purpose, vaultID string, destScript, changeScript []byte, amountSats, feeSats uint64, inputs []VtxoBundleInput, createdAt string) ([]byte, error) {
	if purpose != vtxoPurposeSpend && purpose != vtxoPurposeBoard {
		return nil, fmt.Errorf("vtxo purpose must be spend or board")
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	ordered, err := CanonicalVtxoBundleInputs(inputs)
	if err != nil {
		return nil, err
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
	if rec.Purpose != vtxoPurposeSpend && rec.Purpose != vtxoPurposeBoard {
		return nil, fmt.Errorf("vtxo purpose must be spend or board")
	}
	if err := requireVtxoState(rec.State); err != nil {
		return nil, err
	}
	if len(rec.BundleDigest) != 32 {
		return nil, fmt.Errorf("bundle digest must be 32 bytes")
	}
	if rec.AmountSats < 0 || rec.FeeSats < 0 {
		return nil, fmt.Errorf("negative vtxo outflow")
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
		rec.BundleDigest, []byte(rec.State), rec.DestScript, rec.ChangeScript,
		[]byte(rec.UnsignedPSBT), []byte(rec.AuthorizedPSBT),
		[]byte(rec.CheckpointPSBTs), []byte(rec.CommitmentPSBT), rec.CheckpointTapscript,
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
