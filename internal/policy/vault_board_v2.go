package policy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/brg444/arkade-vault-server/internal/program"
)

const (
	VaultBoardV2PhaseRegister = "register"
	VaultBoardV2PhaseDelete   = "delete"
	VaultBoardV2PhaseFinalize = "finalize"

	VaultBoardV2AuthSubmitted = "submitted"
	VaultBoardV2AuthReleased  = "released"
	VaultBoardV2AuthRejected  = "rejected"

	vaultBoardV2EnrollmentMACDomain = "arkade-vault/vault-board-v2-enrollment/v1"
	vaultBoardV2OperationMACDomain  = "arkade-vault/vault-board-v2-operation/v1"
	vaultBoardV2AuthorizationDomain = "arkade-vault/vault-board-v2-authorization/v1"
	vaultBoardV2DispatchMACDomain   = "arkade-vault/vault-board-v2-dispatch/v1"
	vaultBoardV2SubmissionMACDomain = "arkade-vault/vault-board-v2-submission/v1"
	vaultBoardV2OperationIDDomain   = "arkade-vault/vault-board-v2-operation-id/v1"
	vaultBoardV2CanonicalVersion    = uint32(1)
	MaxVaultBoardV2OperatorRefBytes = 256
)

// VaultBoardV2Enrollment is the immutable per-vault commitment to the v2
// boarding key, VaultBoardCosigner, Operator and exact onchain script. It lives in a
// separate row so existing vault enrollment bytes and MACs remain untouched.
type VaultBoardV2Enrollment struct {
	VaultID       string
	Program       string
	BoardingPub   []byte
	CosignerPub   []byte
	OperatorPub   []byte
	ExitDelay     uint32
	ExitDelayUnit string
	PkScript      []byte
	Address       string
	IntegrityMAC  []byte
}

// VaultBoardV2Operation binds one immutable confirmed boarding outpoint to
// exactly one vault-policy-v1 receiver. Attempts rotate only the finite-lived
// Operator intent; they never rebind these economic facts.
type VaultBoardV2Operation struct {
	OperationID    string
	VaultID        string
	Txid           []byte
	Vout           uint32
	ValueSats      int64
	BoardingScript []byte
	ReceiverScript []byte
	// SequenceAnchorMTP is the median-time-past of the block immediately
	// preceding the confirmation block. BIP68 time locks are measured from
	// this value, not from the funding block header time or wall clock.
	SequenceAnchorMTP int64
	CreatedAt         string
	IntegrityMAC      []byte
}

// VaultBoardV2ChainState is authoritative chain time supplied by the pinned
// indexer boundary. TipMTP is the median-time-past against which a transaction
// in the next block would be evaluated under BIP68.
type VaultBoardV2ChainState struct {
	TipMTP int64
}

// VaultBoardV2Authorization is one replay-safe phase decision. Signed proofs
// and PSBTs are never persisted or returned: only their digest and the result
// of direct submission to the stock Operator are durable.
type VaultBoardV2Authorization struct {
	OperationID    string
	Attempt        uint32
	Phase          string
	RequestDigest  []byte
	TreeSessionPub []byte
	ReceiverSats   int64
	FeeSats        int64
	ExpireAt       int64
	// Finalize authorization persists the independently verified expected
	// commitment and receiver outpoints before any network dispatch. This is
	// the minimum durable evidence needed to reconcile a lost final response.
	CommitmentTxid string
	ReceiverTxid   string
	ReceiverVout   uint32
	CreatedAt      string
	IntegrityMAC   []byte
}

// VaultBoardV2Submission is the append-only authoritative result of sending a
// previously authorized phase directly to the stock Operator.
type VaultBoardV2Submission struct {
	OperationID    string
	Attempt        uint32
	Phase          string
	RequestDigest  []byte
	Outcome        string
	OperatorRef    string
	CommitmentTxid string
	ReceiverTxid   string
	ReceiverVout   uint32
	CreatedAt      string
	IntegrityMAC   []byte
}

// VaultBoardV2Dispatch is written immediately before a previously authorized
// artifact leaves the process. Its absence makes an exact authorization safe
// to retry; its presence without a result is deliberately ambiguous.
type VaultBoardV2Dispatch struct {
	OperationID   string
	Attempt       uint32
	Phase         string
	RequestDigest []byte
	CreatedAt     string
	IntegrityMAC  []byte
}

// VaultBoardV2RegisterRequest contains only per-attempt register evidence.
// The store derives the operation id and allocates the attempt atomically;
// neither value is accepted from an endpoint caller.
type VaultBoardV2RegisterRequest struct {
	RequestDigest  []byte
	TreeSessionPub []byte
	ReceiverSats   int64
	FeeSats        int64
	ExpireAt       int64
}

// VaultBoardV2AttemptSnapshot is the MAC-verified durable state for the latest
// server-allocated attempt. It contains no signing artifact.
type VaultBoardV2AttemptSnapshot struct {
	Operation           VaultBoardV2Operation
	Register            VaultBoardV2Authorization
	RegisterDispatch    *VaultBoardV2Dispatch
	RegisterSubmission  *VaultBoardV2Submission
	DeleteAuthorization *VaultBoardV2Authorization
	DeleteDispatch      *VaultBoardV2Dispatch
	DeleteSubmission    *VaultBoardV2Submission
	FinalAuthorization  *VaultBoardV2Authorization
	FinalDispatch       *VaultBoardV2Dispatch
	FinalSubmission     *VaultBoardV2Submission
}

func SealVaultBoardV2Enrollment(rec *VaultBoardV2Enrollment, key []byte) error {
	mac, err := vaultBoardV2MAC(canonicalVaultBoardV2Enrollment, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardV2Enrollment(rec *VaultBoardV2Enrollment, key []byte) error {
	return verifyVaultBoardV2MAC(canonicalVaultBoardV2Enrollment, rec, rec.IntegrityMAC, key, "enrollment")
}

func SealVaultBoardV2Operation(rec *VaultBoardV2Operation, key []byte) error {
	mac, err := vaultBoardV2MAC(canonicalVaultBoardV2Operation, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardV2Operation(rec *VaultBoardV2Operation, key []byte) error {
	return verifyVaultBoardV2MAC(canonicalVaultBoardV2Operation, rec, rec.IntegrityMAC, key, "operation")
}

func SealVaultBoardV2Authorization(rec *VaultBoardV2Authorization, key []byte) error {
	mac, err := vaultBoardV2MAC(canonicalVaultBoardV2Authorization, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardV2Authorization(rec *VaultBoardV2Authorization, key []byte) error {
	return verifyVaultBoardV2MAC(canonicalVaultBoardV2Authorization, rec, rec.IntegrityMAC, key, "authorization")
}

func SealVaultBoardV2Dispatch(rec *VaultBoardV2Dispatch, key []byte) error {
	mac, err := vaultBoardV2MAC(canonicalVaultBoardV2Dispatch, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardV2Dispatch(rec *VaultBoardV2Dispatch, key []byte) error {
	return verifyVaultBoardV2MAC(canonicalVaultBoardV2Dispatch, rec, rec.IntegrityMAC, key, "dispatch")
}

func SealVaultBoardV2Submission(rec *VaultBoardV2Submission, key []byte) error {
	mac, err := vaultBoardV2MAC(canonicalVaultBoardV2Submission, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardV2Submission(rec *VaultBoardV2Submission, key []byte) error {
	return verifyVaultBoardV2MAC(canonicalVaultBoardV2Submission, rec, rec.IntegrityMAC, key, "submission")
}

type boardV2Canonicalizer[T any] func(*T) ([]byte, error)

func vaultBoardV2MAC[T any](canonical boardV2Canonicalizer[T], rec *T, key []byte) ([]byte, error) {
	if rec == nil || len(key) != sha256.Size {
		return nil, fmt.Errorf("vault-board-v2 integrity key")
	}
	payload, err := canonical(rec)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func verifyVaultBoardV2MAC[T any](canonical boardV2Canonicalizer[T], rec *T, got, key []byte, kind string) error {
	if len(got) != sha256.Size {
		return fmt.Errorf("vault-board-v2 %s integrity MAC missing or malformed", kind)
	}
	want, err := vaultBoardV2MAC(canonical, rec, key)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(got, want) {
		return fmt.Errorf("vault-board-v2 %s integrity MAC mismatch", kind)
	}
	return nil
}

func boardV2Canonical(domain string, fields ...[]byte) ([]byte, error) {
	out := make([]byte, 0, 384)
	var err error
	out, err = appendCredentialField(out, []byte(domain))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, vaultBoardV2CanonicalVersion)
	for _, field := range fields {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	return out, nil
}

func canonicalVaultBoardV2Enrollment(rec *VaultBoardV2Enrollment) ([]byte, error) {
	if rec == nil || rec.VaultID == "" || rec.Program != "vault-board-v2" || len(rec.BoardingPub) != 33 || len(rec.CosignerPub) != 33 || len(rec.OperatorPub) != 33 || len(rec.PkScript) != 34 || rec.Address == "" || rec.ExitDelay == 0 || rec.ExitDelayUnit == "" {
		return nil, fmt.Errorf("invalid vault-board-v2 enrollment")
	}
	out, err := boardV2Canonical(vaultBoardV2EnrollmentMACDomain, []byte(rec.VaultID), []byte(rec.Program), rec.BoardingPub, rec.CosignerPub, rec.OperatorPub, []byte(rec.ExitDelayUnit), rec.PkScript, []byte(rec.Address))
	if err != nil {
		return nil, err
	}
	return binary.LittleEndian.AppendUint32(out, rec.ExitDelay), nil
}

func canonicalVaultBoardV2Operation(rec *VaultBoardV2Operation) ([]byte, error) {
	if rec == nil || rec.OperationID == "" || rec.VaultID == "" || len(rec.Txid) != 32 || rec.ValueSats <= 0 || len(rec.BoardingScript) != 34 || len(rec.ReceiverScript) == 0 || rec.SequenceAnchorMTP <= 0 || rec.CreatedAt == "" {
		return nil, fmt.Errorf("invalid vault-board-v2 operation")
	}
	wantID, err := ComputeVaultBoardV2OperationID(rec.VaultID, rec.Txid, rec.Vout)
	if err != nil || rec.OperationID != wantID {
		return nil, fmt.Errorf("vault-board-v2 operation id mismatch")
	}
	out, err := boardV2Canonical(vaultBoardV2OperationMACDomain, []byte(rec.OperationID), []byte(rec.VaultID), rec.Txid, rec.BoardingScript, rec.ReceiverScript, []byte(rec.CreatedAt))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, rec.Vout)
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.ValueSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.SequenceAnchorMTP))
	return out, nil
}

// ComputeVaultBoardV2OperationID makes the runtime—not the client—the sole
// owner of one stable operation identity per enrolled boarding outpoint.
func ComputeVaultBoardV2OperationID(vaultID string, txid []byte, vout uint32) (string, error) {
	if vaultID == "" || len(txid) != 32 {
		return "", fmt.Errorf("vault-board-v2 outpoint required")
	}
	payload, err := boardV2Canonical(vaultBoardV2OperationIDDomain, []byte(vaultID), txid)
	if err != nil {
		return "", err
	}
	payload = binary.LittleEndian.AppendUint32(payload, vout)
	sum := taggedSHA256(vaultBoardV2OperationIDDomain, payload)
	zeroBytes(payload)
	return hex.EncodeToString(sum), nil
}

func canonicalVaultBoardV2Authorization(rec *VaultBoardV2Authorization) ([]byte, error) {
	if rec == nil || rec.OperationID == "" || len(rec.RequestDigest) != sha256.Size || rec.CreatedAt == "" {
		return nil, fmt.Errorf("invalid vault-board-v2 authorization")
	}
	switch rec.Phase {
	case VaultBoardV2PhaseRegister:
		if rec.ExpireAt <= 0 || len(rec.TreeSessionPub) != 33 || rec.ReceiverSats <= 0 || rec.FeeSats < 0 || rec.ReceiverSats > (1<<63-1)-rec.FeeSats ||
			rec.CommitmentTxid != "" || rec.ReceiverTxid != "" || rec.ReceiverVout != 0 {
			return nil, fmt.Errorf("vault-board-v2 register attempt fields required")
		}
	case VaultBoardV2PhaseFinalize:
		canonicalCommitment, rawCommitment, commitmentErr := canonicalVtxoTxid([]byte(rec.CommitmentTxid))
		zeroBytes(rawCommitment)
		canonicalReceiver, rawReceiver, receiverErr := canonicalVtxoTxid([]byte(rec.ReceiverTxid))
		zeroBytes(rawReceiver)
		if rec.ExpireAt != 0 || len(rec.TreeSessionPub) != 0 || rec.ReceiverSats != 0 || rec.FeeSats != 0 ||
			commitmentErr != nil || receiverErr != nil || rec.CommitmentTxid != canonicalCommitment || rec.ReceiverTxid != canonicalReceiver {
			return nil, fmt.Errorf("vault-board-v2 finalize fields")
		}
	case VaultBoardV2PhaseDelete:
		if rec.ExpireAt <= 0 || len(rec.TreeSessionPub) != 0 || rec.ReceiverSats != 0 || rec.FeeSats != 0 ||
			rec.CommitmentTxid != "" || rec.ReceiverTxid != "" || rec.ReceiverVout != 0 {
			return nil, fmt.Errorf("vault-board-v2 delete fields")
		}
	default:
		return nil, fmt.Errorf("invalid vault-board-v2 phase")
	}
	out, err := boardV2Canonical(vaultBoardV2AuthorizationDomain, []byte(rec.OperationID), []byte(rec.Phase), rec.RequestDigest, rec.TreeSessionPub, []byte(rec.CommitmentTxid), []byte(rec.ReceiverTxid), []byte(rec.CreatedAt))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, rec.Attempt)
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.ReceiverSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.FeeSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.ExpireAt))
	return binary.LittleEndian.AppendUint32(out, rec.ReceiverVout), nil
}

func canonicalVaultBoardV2Submission(rec *VaultBoardV2Submission) ([]byte, error) {
	if rec == nil || rec.OperationID == "" || len(rec.RequestDigest) != sha256.Size || rec.CreatedAt == "" || len(rec.OperatorRef) > MaxVaultBoardV2OperatorRefBytes {
		return nil, fmt.Errorf("invalid vault-board-v2 submission")
	}
	switch rec.Phase {
	case VaultBoardV2PhaseRegister:
		validSubmitted := rec.Outcome == VaultBoardV2AuthSubmitted && rec.OperatorRef != ""
		validRejected := rec.Outcome == VaultBoardV2AuthRejected && rec.OperatorRef == ""
		if (!validSubmitted && !validRejected) || rec.CommitmentTxid != "" || rec.ReceiverTxid != "" || rec.ReceiverVout != 0 {
			return nil, fmt.Errorf("vault-board-v2 intent id required")
		}
	case VaultBoardV2PhaseDelete:
		if rec.Outcome != VaultBoardV2AuthReleased || rec.OperatorRef != "" || rec.CommitmentTxid != "" || rec.ReceiverTxid != "" || rec.ReceiverVout != 0 {
			return nil, fmt.Errorf("vault-board-v2 delete result")
		}
	case VaultBoardV2PhaseFinalize:
		canonicalCommitment, rawCommitment, commitmentErr := canonicalVtxoTxid([]byte(rec.CommitmentTxid))
		zeroBytes(rawCommitment)
		canonicalReceiver, rawReceiver, receiverErr := canonicalVtxoTxid([]byte(rec.ReceiverTxid))
		zeroBytes(rawReceiver)
		if rec.Outcome != VaultBoardV2AuthSubmitted || rec.OperatorRef != "" || commitmentErr != nil || receiverErr != nil ||
			rec.CommitmentTxid != canonicalCommitment || rec.ReceiverTxid != canonicalReceiver {
			return nil, fmt.Errorf("vault-board-v2 finalize result")
		}
	default:
		return nil, fmt.Errorf("invalid vault-board-v2 phase")
	}
	out, err := boardV2Canonical(vaultBoardV2SubmissionMACDomain, []byte(rec.OperationID), []byte(rec.Phase), rec.RequestDigest, []byte(rec.Outcome), []byte(rec.OperatorRef), []byte(rec.CommitmentTxid), []byte(rec.ReceiverTxid), []byte(rec.CreatedAt))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, rec.Attempt)
	return binary.LittleEndian.AppendUint32(out, rec.ReceiverVout), nil
}

func canonicalVaultBoardV2Dispatch(rec *VaultBoardV2Dispatch) ([]byte, error) {
	if rec == nil || rec.OperationID == "" || len(rec.RequestDigest) != sha256.Size || rec.CreatedAt == "" {
		return nil, fmt.Errorf("invalid vault-board-v2 dispatch")
	}
	switch rec.Phase {
	case VaultBoardV2PhaseRegister, VaultBoardV2PhaseDelete, VaultBoardV2PhaseFinalize:
	default:
		return nil, fmt.Errorf("invalid vault-board-v2 phase")
	}
	out, err := boardV2Canonical(vaultBoardV2DispatchMACDomain, []byte(rec.OperationID), []byte(rec.Phase), rec.RequestDigest, []byte(rec.CreatedAt))
	if err != nil {
		return nil, err
	}
	return binary.LittleEndian.AppendUint32(out, rec.Attempt), nil
}

// PutVaultBoardV2EnrollmentTx adds the immutable v2 binding in the caller's
// enrollment transaction.
func PutVaultBoardV2EnrollmentTx(tx *sql.Tx, rec VaultBoardV2Enrollment) error {
	if tx == nil {
		return fmt.Errorf("vault-board-v2 enrollment transaction required")
	}
	_, err := tx.Exec(`INSERT INTO vault_board_v2_enrollment (vault_id, program, boarding_pub, cosigner_pub, operator_pub, exit_delay, exit_delay_unit, pk_script, address, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, rec.VaultID, rec.Program, rec.BoardingPub, rec.CosignerPub, rec.OperatorPub, rec.ExitDelay, rec.ExitDelayUnit, rec.PkScript, rec.Address, rec.IntegrityMAC)
	return err
}

func (l *Ledger) GetVaultBoardV2Enrollment(vaultID string) (*VaultBoardV2Enrollment, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	var rec VaultBoardV2Enrollment
	err = l.db.QueryRow(`SELECT vault_id, program, boarding_pub, cosigner_pub, operator_pub, exit_delay, exit_delay_unit, pk_script, address, integrity_mac FROM vault_board_v2_enrollment WHERE vault_id = ?`, vaultID).Scan(&rec.VaultID, &rec.Program, &rec.BoardingPub, &rec.CosignerPub, &rec.OperatorPub, &rec.ExitDelay, &rec.ExitDelayUnit, &rec.PkScript, &rec.Address, &rec.IntegrityMAC)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyVaultBoardV2Enrollment(&rec, key); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (l *Ledger) GetCurrentVaultBoardV2Attempt(ctx context.Context, operationID string) (*VaultBoardV2AttemptSnapshot, error) {
	if operationID == "" {
		return nil, fmt.Errorf("vault-board-v2 operation id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	operation, err := loadVaultBoardV2Operation(ctx, l.db, operationID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyVaultBoardV2Operation(&operation, key); err != nil {
		return nil, err
	}
	register, err := loadLatestVaultBoardV2Register(ctx, l.db, operationID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("vault-board-v2 operation has no register attempt")
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyVaultBoardV2Authorization(&register, key); err != nil {
		return nil, err
	}
	snapshot := &VaultBoardV2AttemptSnapshot{Operation: operation, Register: register}
	if err := loadOptionalVerifiedVaultBoardV2Dispatch(ctx, l.db, key, operationID, register.Attempt, VaultBoardV2PhaseRegister, &snapshot.RegisterDispatch); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardV2Submission(ctx, l.db, key, operationID, register.Attempt, VaultBoardV2PhaseRegister, &snapshot.RegisterSubmission); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardV2Authorization(ctx, l.db, key, operationID, register.Attempt, VaultBoardV2PhaseDelete, &snapshot.DeleteAuthorization); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardV2Dispatch(ctx, l.db, key, operationID, register.Attempt, VaultBoardV2PhaseDelete, &snapshot.DeleteDispatch); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardV2Submission(ctx, l.db, key, operationID, register.Attempt, VaultBoardV2PhaseDelete, &snapshot.DeleteSubmission); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardV2Authorization(ctx, l.db, key, operationID, register.Attempt, VaultBoardV2PhaseFinalize, &snapshot.FinalAuthorization); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardV2Dispatch(ctx, l.db, key, operationID, register.Attempt, VaultBoardV2PhaseFinalize, &snapshot.FinalDispatch); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardV2Submission(ctx, l.db, key, operationID, register.Attempt, VaultBoardV2PhaseFinalize, &snapshot.FinalSubmission); err != nil {
		return nil, err
	}
	if snapshot.RegisterSubmission != nil && !bytes.Equal(snapshot.RegisterSubmission.RequestDigest, register.RequestDigest) {
		return nil, fmt.Errorf("vault-board-v2 register result digest mismatch")
	}
	if snapshot.DeleteSubmission != nil && (snapshot.DeleteAuthorization == nil || !bytes.Equal(snapshot.DeleteSubmission.RequestDigest, snapshot.DeleteAuthorization.RequestDigest)) {
		return nil, fmt.Errorf("vault-board-v2 delete result digest mismatch")
	}
	if snapshot.FinalSubmission != nil && (snapshot.FinalAuthorization == nil || !bytes.Equal(snapshot.FinalSubmission.RequestDigest, snapshot.FinalAuthorization.RequestDigest)) {
		return nil, fmt.Errorf("vault-board-v2 final result digest mismatch")
	}
	for phase, pair := range map[string]struct {
		dispatch *VaultBoardV2Dispatch
		auth     *VaultBoardV2Authorization
	}{
		VaultBoardV2PhaseRegister: {dispatch: snapshot.RegisterDispatch, auth: &snapshot.Register},
		VaultBoardV2PhaseDelete:   {dispatch: snapshot.DeleteDispatch, auth: snapshot.DeleteAuthorization},
		VaultBoardV2PhaseFinalize: {dispatch: snapshot.FinalDispatch, auth: snapshot.FinalAuthorization},
	} {
		if pair.dispatch != nil && (pair.auth == nil || !bytes.Equal(pair.dispatch.RequestDigest, pair.auth.RequestDigest)) {
			return nil, fmt.Errorf("vault-board-v2 %s dispatch digest mismatch", phase)
		}
	}
	return snapshot, nil
}

// BeginVaultBoardV2Attempt binds the stable outpoint operation and allocates
// its next register attempt under the same BEGIN IMMEDIATE transaction.
func (l *Ledger) BeginVaultBoardV2Attempt(ctx context.Context, operation VaultBoardV2Operation, request VaultBoardV2RegisterRequest, chain VaultBoardV2ChainState) (*VaultBoardV2Operation, *VaultBoardV2Authorization, bool, error) {
	operationID, err := ComputeVaultBoardV2OperationID(operation.VaultID, operation.Txid, operation.Vout)
	if err != nil {
		return nil, nil, false, err
	}
	if operation.OperationID != "" && operation.OperationID != operationID {
		return nil, nil, false, fmt.Errorf("vault-board-v2 operation id is server-derived")
	}
	if len(request.RequestDigest) != sha256.Size || len(request.TreeSessionPub) != 33 || request.ReceiverSats <= 0 || request.FeeSats < 0 ||
		request.ReceiverSats > (1<<63-1)-request.FeeSats || request.ReceiverSats+request.FeeSats != operation.ValueSats || request.ExpireAt <= l.NowUTC().Unix() {
		return nil, nil, false, fmt.Errorf("vault-board-v2 finite register request required")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return nil, nil, false, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, nil, false, err
	}
	defer zeroBytes(key)

	now := l.NowUTC()
	operation.OperationID = operationID
	stored, err := loadVaultBoardV2Operation(ctx, conn, operationID)
	switch err {
	case nil:
		if err := VerifyVaultBoardV2Operation(&stored, key); err != nil {
			return nil, nil, false, err
		}
		if !sameVaultBoardV2OperationFacts(stored, operation) {
			return nil, nil, false, fmt.Errorf("vault-board-v2 outpoint is bound to different economic facts")
		}
	case sql.ErrNoRows:
		operation.CreatedAt = now.Format(time.RFC3339Nano)
		if err := SealVaultBoardV2Operation(&operation, key); err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_v2_operation (operation_id, vault_id, txid, vout, value_sats, boarding_script, receiver_script, sequence_anchor_mtp, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, operation.OperationID, operation.VaultID, operation.Txid, operation.Vout, operation.ValueSats, operation.BoardingScript, operation.ReceiverScript, operation.SequenceAnchorMTP, operation.CreatedAt, operation.IntegrityMAC); err != nil {
			return nil, nil, false, err
		}
		stored = operation
	default:
		return nil, nil, false, err
	}
	if err := requireVaultBoardV2CooperativeWindow(stored, chain); err != nil {
		return nil, nil, false, err
	}

	registers, err := loadVerifiedVaultBoardV2Registers(ctx, conn, key, operationID)
	if err != nil {
		return nil, nil, false, err
	}
	for i := range registers {
		prior := registers[i]
		if bytes.Equal(prior.RequestDigest, request.RequestDigest) || bytes.Equal(prior.TreeSessionPub, request.TreeSessionPub) {
			isLatest := i == len(registers)-1
			if isLatest && bytes.Equal(prior.RequestDigest, request.RequestDigest) && bytes.Equal(prior.TreeSessionPub, request.TreeSessionPub) &&
				prior.ReceiverSats == request.ReceiverSats && prior.FeeSats == request.FeeSats && prior.ExpireAt == request.ExpireAt {
				if err := requireVaultBoardV2AttemptCurrent(ctx, conn, key, operationID, prior.Attempt); err != nil {
					return nil, nil, false, err
				}
				if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
					return nil, nil, false, err
				}
				committed = true
				return &stored, &prior, false, nil
			}
			return nil, nil, false, fmt.Errorf("vault-board-v2 attempt must rotate register digest and tree session key")
		}
	}

	attempt := uint32(0)
	if len(registers) > 0 {
		last := registers[len(registers)-1]
		if last.Attempt == ^uint32(0) {
			return nil, nil, false, fmt.Errorf("vault-board-v2 attempt overflow")
		}
		if err := requireVaultBoardV2AttemptCanRotate(ctx, conn, key, operationID, last.Attempt); err != nil {
			return nil, nil, false, err
		}
		attempt = last.Attempt + 1
	}
	auth := VaultBoardV2Authorization{
		OperationID: operationID, Attempt: attempt, Phase: VaultBoardV2PhaseRegister,
		RequestDigest: append([]byte(nil), request.RequestDigest...), TreeSessionPub: append([]byte(nil), request.TreeSessionPub...),
		ReceiverSats: request.ReceiverSats, FeeSats: request.FeeSats,
		ExpireAt: request.ExpireAt, CreatedAt: now.Format(time.RFC3339Nano),
	}
	if err := SealVaultBoardV2Authorization(&auth, key); err != nil {
		return nil, nil, false, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_v2_authorization (operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, auth.OperationID, auth.Attempt, auth.Phase, auth.RequestDigest, nullableVaultBoardV2Bytes(auth.TreeSessionPub), auth.ReceiverSats, auth.FeeSats, auth.ExpireAt, auth.CommitmentTxid, auth.ReceiverTxid, auth.ReceiverVout, auth.CreatedAt, auth.IntegrityMAC); err != nil {
		return nil, nil, false, err
	}
	if err := l.observeEconomicOutflowsLocked(conn); err != nil {
		return nil, nil, false, fmt.Errorf("policy sequence: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return nil, nil, false, err
	}
	committed = true
	return &stored, &auth, true, nil
}

// AppendVaultBoardV2AuthorizationAndDispatch closes the delete/final crash
// gap: once a fully signed artifact exists in memory, the exact semantic
// authorization and its outbound boundary become durable in one SQLite
// transaction. No signed artifact is persisted.
func (l *Ledger) AppendVaultBoardV2AuthorizationAndDispatch(ctx context.Context, auth VaultBoardV2Authorization, chain VaultBoardV2ChainState) (*VaultBoardV2Authorization, *VaultBoardV2Dispatch, bool, error) {
	if auth.Phase != VaultBoardV2PhaseDelete && auth.Phase != VaultBoardV2PhaseFinalize {
		return nil, nil, false, fmt.Errorf("vault-board-v2 atomic dispatch is delete/final only")
	}
	if auth.OperationID == "" {
		return nil, nil, false, fmt.Errorf("vault-board-v2 operation required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return nil, nil, false, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, nil, false, err
	}
	defer zeroBytes(key)
	operation, err := loadVaultBoardV2Operation(ctx, conn, auth.OperationID)
	if err != nil {
		return nil, nil, false, err
	}
	if err := VerifyVaultBoardV2Operation(&operation, key); err != nil {
		return nil, nil, false, err
	}
	if err := requireVaultBoardV2CooperativeWindow(operation, chain); err != nil {
		return nil, nil, false, err
	}
	latest, err := loadLatestVaultBoardV2Register(ctx, conn, auth.OperationID)
	if err != nil {
		return nil, nil, false, err
	}
	if err := VerifyVaultBoardV2Authorization(&latest, key); err != nil {
		return nil, nil, false, err
	}
	if latest.Attempt != auth.Attempt {
		return nil, nil, false, fmt.Errorf("vault-board-v2 attempt is no longer current")
	}
	storedAuth, authErr := loadVaultBoardV2Authorization(ctx, conn, auth.OperationID, auth.Attempt, auth.Phase)
	if authErr == nil {
		if err := VerifyVaultBoardV2Authorization(&storedAuth, key); err != nil {
			return nil, nil, false, err
		}
		if !sameVaultBoardV2AuthorizationRequest(storedAuth, auth) {
			return nil, nil, false, fmt.Errorf("vault-board-v2 phase is bound to a different exact request")
		}
		auth = storedAuth
	} else if authErr != sql.ErrNoRows {
		return nil, nil, false, authErr
	} else {
		if err := validateVaultBoardV2PhaseOrder(ctx, conn, key, auth); err != nil {
			return nil, nil, false, err
		}
		auth.CreatedAt = l.NowUTC().Format(time.RFC3339Nano)
		if err := SealVaultBoardV2Authorization(&auth, key); err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_v2_authorization (operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, auth.OperationID, auth.Attempt, auth.Phase, auth.RequestDigest, nullableVaultBoardV2Bytes(auth.TreeSessionPub), auth.ReceiverSats, auth.FeeSats, auth.ExpireAt, auth.CommitmentTxid, auth.ReceiverTxid, auth.ReceiverVout, auth.CreatedAt, auth.IntegrityMAC); err != nil {
			return nil, nil, false, err
		}
	}
	if existing, err := loadVaultBoardV2Dispatch(ctx, conn, auth.OperationID, auth.Attempt, auth.Phase); err == nil {
		if err := VerifyVaultBoardV2Dispatch(&existing, key); err != nil {
			return nil, nil, false, err
		}
		if !bytes.Equal(existing.RequestDigest, auth.RequestDigest) {
			return nil, nil, false, fmt.Errorf("vault-board-v2 dispatch request changed")
		}
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return nil, nil, false, err
		}
		committed = true
		return &auth, &existing, false, nil
	} else if err != sql.ErrNoRows {
		return nil, nil, false, err
	}
	if _, err := loadVaultBoardV2Submission(ctx, conn, auth.OperationID, auth.Attempt, auth.Phase); err == nil {
		return nil, nil, false, fmt.Errorf("vault-board-v2 result already recorded")
	} else if err != sql.ErrNoRows {
		return nil, nil, false, err
	}
	dispatch := VaultBoardV2Dispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: bytes.Clone(auth.RequestDigest), CreatedAt: l.NowUTC().Format(time.RFC3339Nano),
	}
	if err := SealVaultBoardV2Dispatch(&dispatch, key); err != nil {
		return nil, nil, false, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_v2_dispatch (operation_id, attempt, phase, request_digest, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?)`, dispatch.OperationID, dispatch.Attempt, dispatch.Phase, dispatch.RequestDigest, dispatch.CreatedAt, dispatch.IntegrityMAC); err != nil {
		return nil, nil, false, err
	}
	if err := l.observeEconomicOutflowsLocked(conn); err != nil {
		return nil, nil, false, fmt.Errorf("policy sequence: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return nil, nil, false, err
	}
	committed = true
	return &auth, &dispatch, true, nil
}

func sameVaultBoardV2OperationFacts(stored, proposed VaultBoardV2Operation) bool {
	return stored.OperationID == proposed.OperationID && stored.VaultID == proposed.VaultID &&
		bytes.Equal(stored.Txid, proposed.Txid) && stored.Vout == proposed.Vout &&
		stored.ValueSats == proposed.ValueSats && bytes.Equal(stored.BoardingScript, proposed.BoardingScript) &&
		bytes.Equal(stored.ReceiverScript, proposed.ReceiverScript) && stored.SequenceAnchorMTP == proposed.SequenceAnchorMTP
}

func sameVaultBoardV2AuthorizationRequest(stored, proposed VaultBoardV2Authorization) bool {
	return stored.OperationID == proposed.OperationID && stored.Attempt == proposed.Attempt && stored.Phase == proposed.Phase &&
		bytes.Equal(stored.RequestDigest, proposed.RequestDigest) && bytes.Equal(stored.TreeSessionPub, proposed.TreeSessionPub) &&
		stored.ReceiverSats == proposed.ReceiverSats && stored.FeeSats == proposed.FeeSats && stored.ExpireAt == proposed.ExpireAt &&
		stored.CommitmentTxid == proposed.CommitmentTxid && stored.ReceiverTxid == proposed.ReceiverTxid && stored.ReceiverVout == proposed.ReceiverVout
}

func requireVaultBoardV2CooperativeWindow(operation VaultBoardV2Operation, chain VaultBoardV2ChainState) error {
	if operation.SequenceAnchorMTP <= 0 || chain.TipMTP <= 0 {
		return fmt.Errorf("authoritative vault-board-v2 chain MTP required")
	}
	if operation.SequenceAnchorMTP > (1<<63-1)-int64(program.VaultBoardV2ExitDelay) ||
		chain.TipMTP >= operation.SequenceAnchorMTP+int64(program.VaultBoardV2ExitDelay) {
		return fmt.Errorf("vault-board-v2 cooperative path has matured")
	}
	return nil
}

func loadVerifiedVaultBoardV2Registers(ctx context.Context, q queryContext, key []byte, operationID string) ([]VaultBoardV2Authorization, error) {
	rows, err := q.QueryContext(ctx, `SELECT operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac FROM vault_board_v2_authorization WHERE operation_id = ? AND phase = 'register' ORDER BY attempt`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultBoardV2Authorization
	for rows.Next() {
		var rec VaultBoardV2Authorization
		if err := rows.Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.TreeSessionPub, &rec.ReceiverSats, &rec.FeeSats, &rec.ExpireAt, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC); err != nil {
			return nil, err
		}
		if err := VerifyVaultBoardV2Authorization(&rec, key); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func requireVaultBoardV2AttemptCanRotate(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32) error {
	if finalAuth, err := loadVaultBoardV2Authorization(ctx, q, operationID, attempt, VaultBoardV2PhaseFinalize); err == nil {
		if err := VerifyVaultBoardV2Authorization(&finalAuth, key); err != nil {
			return err
		}
		return fmt.Errorf("finalized vault-board-v2 attempt cannot rotate")
	} else if err != sql.ErrNoRows {
		return err
	}
	deleteAuth, err := loadVaultBoardV2Authorization(ctx, q, operationID, attempt, VaultBoardV2PhaseDelete)
	if err == sql.ErrNoRows {
		// A register authorization that never crossed the durable dispatch
		// boundary cannot have reached the Operator. Rotating it is safe and
		// gives a restarted SDK a fresh TreeSignerSession without storing the
		// old session secret.
		if _, dispatchErr := loadVaultBoardV2Dispatch(ctx, q, operationID, attempt, VaultBoardV2PhaseRegister); dispatchErr == sql.ErrNoRows {
			return nil
		} else if dispatchErr != nil {
			return dispatchErr
		}
		registerResult, resultErr := loadVaultBoardV2Submission(ctx, q, operationID, attempt, VaultBoardV2PhaseRegister)
		if resultErr == nil {
			if err := VerifyVaultBoardV2Submission(&registerResult, key); err != nil {
				return err
			}
			if registerResult.Outcome == VaultBoardV2AuthRejected {
				return nil
			}
		} else if resultErr != sql.ErrNoRows {
			return resultErr
		}
		return fmt.Errorf("previous vault-board-v2 attempt not authoritatively released")
	}
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardV2Authorization(&deleteAuth, key); err != nil {
		return err
	}
	deleteResult, err := loadVaultBoardV2Submission(ctx, q, operationID, attempt, VaultBoardV2PhaseDelete)
	if err != nil {
		return fmt.Errorf("previous vault-board-v2 attempt not authoritatively released")
	}
	if err := VerifyVaultBoardV2Submission(&deleteResult, key); err != nil {
		return err
	}
	if deleteResult.Outcome != VaultBoardV2AuthReleased || !bytes.Equal(deleteResult.RequestDigest, deleteAuth.RequestDigest) {
		return fmt.Errorf("previous vault-board-v2 attempt not authoritatively released")
	}
	return nil
}

func requireVaultBoardV2AttemptCurrent(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32) error {
	if registerResult, err := loadVaultBoardV2Submission(ctx, q, operationID, attempt, VaultBoardV2PhaseRegister); err == nil {
		if err := VerifyVaultBoardV2Submission(&registerResult, key); err != nil {
			return err
		}
		if registerResult.Outcome == VaultBoardV2AuthRejected {
			return fmt.Errorf("vault-board-v2 register request was definitely rejected")
		}
	} else if err != sql.ErrNoRows {
		return err
	}
	if finalAuth, err := loadVaultBoardV2Authorization(ctx, q, operationID, attempt, VaultBoardV2PhaseFinalize); err == nil {
		if err := VerifyVaultBoardV2Authorization(&finalAuth, key); err != nil {
			return err
		}
		return fmt.Errorf("vault-board-v2 attempt has final authorization")
	} else if err != sql.ErrNoRows {
		return err
	}
	if deleteAuth, err := loadVaultBoardV2Authorization(ctx, q, operationID, attempt, VaultBoardV2PhaseDelete); err == nil {
		if err := VerifyVaultBoardV2Authorization(&deleteAuth, key); err != nil {
			return err
		}
		return fmt.Errorf("vault-board-v2 attempt has delete authorization")
	} else if err != sql.ErrNoRows {
		return err
	}
	if deleteResult, err := loadVaultBoardV2Submission(ctx, q, operationID, attempt, VaultBoardV2PhaseDelete); err == nil {
		if err := VerifyVaultBoardV2Submission(&deleteResult, key); err != nil {
			return err
		}
		return fmt.Errorf("vault-board-v2 attempt was authoritatively released")
	} else if err != sql.ErrNoRows {
		return err
	}
	return nil
}

func loadLatestVaultBoardV2Register(ctx context.Context, q queryContext, operationID string) (VaultBoardV2Authorization, error) {
	var rec VaultBoardV2Authorization
	err := q.QueryRowContext(ctx, `SELECT operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac FROM vault_board_v2_authorization WHERE operation_id = ? AND phase = 'register' ORDER BY attempt DESC LIMIT 1`, operationID).Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.TreeSessionPub, &rec.ReceiverSats, &rec.FeeSats, &rec.ExpireAt, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}

func loadOptionalVerifiedVaultBoardV2Authorization(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32, phase string, out **VaultBoardV2Authorization) error {
	rec, err := loadVaultBoardV2Authorization(ctx, q, operationID, attempt, phase)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardV2Authorization(&rec, key); err != nil {
		return err
	}
	*out = &rec
	return nil
}

func loadOptionalVerifiedVaultBoardV2Submission(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32, phase string, out **VaultBoardV2Submission) error {
	rec, err := loadVaultBoardV2Submission(ctx, q, operationID, attempt, phase)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardV2Submission(&rec, key); err != nil {
		return err
	}
	*out = &rec
	return nil
}

func loadOptionalVerifiedVaultBoardV2Dispatch(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32, phase string, out **VaultBoardV2Dispatch) error {
	rec, err := loadVaultBoardV2Dispatch(ctx, q, operationID, attempt, phase)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardV2Dispatch(&rec, key); err != nil {
		return err
	}
	*out = &rec
	return nil
}

// AppendVaultBoardV2Dispatch durably records that an exact authorized request
// is about to cross the network boundary. No network call may happen first.
func (l *Ledger) AppendVaultBoardV2Dispatch(ctx context.Context, rec VaultBoardV2Dispatch, chain VaultBoardV2ChainState) (*VaultBoardV2Dispatch, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return nil, false, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, false, err
	}
	defer zeroBytes(key)
	operation, err := loadVaultBoardV2Operation(ctx, conn, rec.OperationID)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyVaultBoardV2Operation(&operation, key); err != nil {
		return nil, false, err
	}
	if err := requireVaultBoardV2CooperativeWindow(operation, chain); err != nil {
		return nil, false, err
	}
	if existing, err := loadVaultBoardV2Dispatch(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase); err == nil {
		if err := VerifyVaultBoardV2Dispatch(&existing, key); err != nil {
			return nil, false, err
		}
		if !bytes.Equal(existing.RequestDigest, rec.RequestDigest) {
			return nil, false, fmt.Errorf("vault-board-v2 dispatch request changed")
		}
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return nil, false, err
		}
		committed = true
		return &existing, false, nil
	} else if err != sql.ErrNoRows {
		return nil, false, err
	}
	auth, err := loadVaultBoardV2Authorization(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyVaultBoardV2Authorization(&auth, key); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(auth.RequestDigest, rec.RequestDigest) {
		return nil, false, fmt.Errorf("vault-board-v2 dispatch request changed")
	}
	latest, err := loadLatestVaultBoardV2Register(ctx, conn, rec.OperationID)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyVaultBoardV2Authorization(&latest, key); err != nil {
		return nil, false, err
	}
	if latest.Attempt != rec.Attempt {
		return nil, false, fmt.Errorf("vault-board-v2 attempt is no longer current")
	}
	if _, err := loadVaultBoardV2Submission(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase); err == nil {
		return nil, false, fmt.Errorf("vault-board-v2 result already recorded")
	} else if err != sql.ErrNoRows {
		return nil, false, err
	}
	rec.CreatedAt = l.NowUTC().Format(time.RFC3339Nano)
	if err := SealVaultBoardV2Dispatch(&rec, key); err != nil {
		return nil, false, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_v2_dispatch (operation_id, attempt, phase, request_digest, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?)`, rec.OperationID, rec.Attempt, rec.Phase, rec.RequestDigest, rec.CreatedAt, rec.IntegrityMAC); err != nil {
		return nil, false, err
	}
	if err := l.observeEconomicOutflowsLocked(conn); err != nil {
		return nil, false, fmt.Errorf("policy sequence: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return nil, false, err
	}
	committed = true
	return &rec, true, nil
}

func nullableVaultBoardV2Bytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

// AppendVaultBoardV2Submission records only authoritative success returned by
// the stock Operator. No signed proof or PSBT is durable.
func (l *Ledger) AppendVaultBoardV2Submission(ctx context.Context, rec VaultBoardV2Submission) (*VaultBoardV2Submission, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return nil, false, err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, false, err
	}
	defer zeroBytes(key)
	if current, err := loadVaultBoardV2Submission(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase); err == nil {
		if err := VerifyVaultBoardV2Submission(&current, key); err != nil {
			return nil, false, err
		}
		if !bytes.Equal(current.RequestDigest, rec.RequestDigest) || current.Outcome != rec.Outcome || current.OperatorRef != rec.OperatorRef ||
			current.CommitmentTxid != rec.CommitmentTxid || current.ReceiverTxid != rec.ReceiverTxid || current.ReceiverVout != rec.ReceiverVout {
			return nil, false, fmt.Errorf("vault-board-v2 Operator result changed")
		}
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return nil, false, err
		}
		commit = true
		return &current, false, nil
	} else if err != sql.ErrNoRows {
		return nil, false, err
	}
	auth, err := loadVaultBoardV2Authorization(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyVaultBoardV2Authorization(&auth, key); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(auth.RequestDigest, rec.RequestDigest) {
		return nil, false, fmt.Errorf("vault-board-v2 request changed")
	}
	dispatch, err := loadVaultBoardV2Dispatch(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase)
	if err != nil {
		return nil, false, fmt.Errorf("vault-board-v2 dispatch required")
	}
	if err := VerifyVaultBoardV2Dispatch(&dispatch, key); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(dispatch.RequestDigest, rec.RequestDigest) {
		return nil, false, fmt.Errorf("vault-board-v2 dispatch request changed")
	}
	rec.CreatedAt = l.NowUTC().Format(time.RFC3339Nano)
	if err := SealVaultBoardV2Submission(&rec, key); err != nil {
		return nil, false, err
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO vault_board_v2_submission (operation_id, attempt, phase, request_digest, outcome, operator_ref, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, rec.OperationID, rec.Attempt, rec.Phase, rec.RequestDigest, rec.Outcome, rec.OperatorRef, rec.CommitmentTxid, rec.ReceiverTxid, rec.ReceiverVout, rec.CreatedAt, rec.IntegrityMAC)
	if err != nil {
		return nil, false, err
	}
	if err := l.observeEconomicOutflowsLocked(conn); err != nil {
		return nil, false, fmt.Errorf("policy sequence: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return nil, false, err
	}
	commit = true
	return &rec, true, nil
}

func validateVaultBoardV2PhaseOrder(ctx context.Context, q queryContext, key []byte, auth VaultBoardV2Authorization) error {
	latest, latestErr := loadLatestVaultBoardV2Register(ctx, q, auth.OperationID)
	if latestErr != nil {
		return latestErr
	}
	if err := VerifyVaultBoardV2Authorization(&latest, key); err != nil {
		return err
	}
	if latest.Attempt != auth.Attempt {
		return fmt.Errorf("vault-board-v2 attempt is no longer current")
	}
	register, regErr := loadVaultBoardV2Authorization(ctx, q, auth.OperationID, auth.Attempt, VaultBoardV2PhaseRegister)
	if regErr == nil {
		if err := VerifyVaultBoardV2Authorization(&register, key); err != nil {
			return err
		}
	}
	switch auth.Phase {
	case VaultBoardV2PhaseDelete, VaultBoardV2PhaseFinalize:
		if regErr != nil {
			return fmt.Errorf("vault-board-v2 register authorization required")
		}
		registerSubmission, err := loadVaultBoardV2Submission(ctx, q, auth.OperationID, auth.Attempt, VaultBoardV2PhaseRegister)
		if err != nil {
			return fmt.Errorf("vault-board-v2 register submission required")
		}
		if err := VerifyVaultBoardV2Submission(&registerSubmission, key); err != nil {
			return err
		}
		if registerSubmission.Outcome != VaultBoardV2AuthSubmitted {
			return fmt.Errorf("vault-board-v2 register was not accepted")
		}
		opposite := VaultBoardV2PhaseFinalize
		if auth.Phase == VaultBoardV2PhaseFinalize {
			opposite = VaultBoardV2PhaseDelete
		}
		if oppositeAuth, err := loadVaultBoardV2Authorization(ctx, q, auth.OperationID, auth.Attempt, opposite); err == nil {
			if err := VerifyVaultBoardV2Authorization(&oppositeAuth, key); err != nil {
				return err
			}
			return fmt.Errorf("vault-board-v2 delete and finalize are mutually exclusive")
		} else if err != sql.ErrNoRows {
			return err
		}
		return nil
	default:
		return fmt.Errorf("invalid vault-board-v2 phase")
	}
}

func loadVaultBoardV2Operation(ctx context.Context, q queryContext, id string) (VaultBoardV2Operation, error) {
	var rec VaultBoardV2Operation
	err := q.QueryRowContext(ctx, `SELECT operation_id, vault_id, txid, vout, value_sats, boarding_script, receiver_script, sequence_anchor_mtp, created_at, integrity_mac FROM vault_board_v2_operation WHERE operation_id = ?`, id).Scan(&rec.OperationID, &rec.VaultID, &rec.Txid, &rec.Vout, &rec.ValueSats, &rec.BoardingScript, &rec.ReceiverScript, &rec.SequenceAnchorMTP, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}

func loadVaultBoardV2Authorization(ctx context.Context, q queryContext, id string, attempt uint32, phase string) (VaultBoardV2Authorization, error) {
	var rec VaultBoardV2Authorization
	err := q.QueryRowContext(ctx, `SELECT operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac FROM vault_board_v2_authorization WHERE operation_id = ? AND attempt = ? AND phase = ?`, id, attempt, phase).Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.TreeSessionPub, &rec.ReceiverSats, &rec.FeeSats, &rec.ExpireAt, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}

func loadVaultBoardV2Submission(ctx context.Context, q queryContext, id string, attempt uint32, phase string) (VaultBoardV2Submission, error) {
	var rec VaultBoardV2Submission
	err := q.QueryRowContext(ctx, `SELECT operation_id, attempt, phase, request_digest, outcome, operator_ref, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac FROM vault_board_v2_submission WHERE operation_id = ? AND attempt = ? AND phase = ?`, id, attempt, phase).Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.Outcome, &rec.OperatorRef, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}

func loadVaultBoardV2Dispatch(ctx context.Context, q queryContext, id string, attempt uint32, phase string) (VaultBoardV2Dispatch, error) {
	var rec VaultBoardV2Dispatch
	err := q.QueryRowContext(ctx, `SELECT operation_id, attempt, phase, request_digest, created_at, integrity_mac FROM vault_board_v2_dispatch WHERE operation_id = ? AND attempt = ? AND phase = ?`, id, attempt, phase).Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}
