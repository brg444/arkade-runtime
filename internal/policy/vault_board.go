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

	"github.com/brg444/arkade-runtime/internal/program"
)

const (
	VaultBoardPhaseRegister = "register"
	VaultBoardPhaseDelete   = "delete"
	VaultBoardPhaseFinalize = "finalize"

	VaultBoardAuthSubmitted = "submitted"
	VaultBoardAuthReleased  = "released"
	VaultBoardAuthRejected  = "rejected"

	vaultBoardEnrollmentMACDomain = "arkade-vault/vault-board-v1-enrollment/v1"
	vaultBoardOperationMACDomain  = "arkade-vault/vault-board-v1-operation/v1"
	vaultBoardAuthorizationDomain = "arkade-vault/vault-board-v1-authorization/v1"
	vaultBoardDispatchMACDomain   = "arkade-vault/vault-board-v1-dispatch/v1"
	vaultBoardSubmissionMACDomain = "arkade-vault/vault-board-v1-submission/v1"
	vaultBoardOperationIDDomain   = "arkade-vault/vault-board-v1-operation-id/v1"
	vaultBoardCanonicalVersion    = uint32(1)
	MaxVaultBoardOperatorRefBytes = 256
	vaultBoardRegisterQuarantine  = 30 * time.Second
)

// VaultBoardRegisterCanSupersede reports whether a finite-lived register
// proof is old enough to replace. This is only a liveness gate: callers must
// still prove the boarding outpoint is unspent and atomically reject any prior
// final authorization before allocating the next attempt.
func VaultBoardRegisterCanSupersede(expireAt int64, now time.Time) bool {
	quarantineSeconds := int64(vaultBoardRegisterQuarantine / time.Second)
	nowUnix := now.UTC().Unix()
	return expireAt > 0 && nowUnix >= quarantineSeconds && expireAt <= nowUnix-quarantineSeconds
}

// VaultBoardEnrollment is the immutable per-vault commitment to the boarding
// key, VaultBoardCosigner, Operator, and exact onchain script.
type VaultBoardEnrollment struct {
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

// VaultBoardOperation binds one immutable confirmed boarding outpoint to
// exactly one vault-policy-v1 receiver. Attempts rotate only after a definite
// rejection or proven release; they never rebind these economic facts.
type VaultBoardOperation struct {
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

// VaultBoardChainState is authoritative chain time supplied by the pinned
// indexer boundary. TipMTP is the median-time-past against which a transaction
// in the next block would be evaluated under BIP68.
type VaultBoardChainState struct {
	TipMTP int64
}

// VaultBoardAuthorization is one replay-safe phase decision. Signed proofs
// and PSBTs are never persisted or returned: only their digest and the result
// of direct submission to the stock Operator are durable.
type VaultBoardAuthorization struct {
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

// VaultBoardSubmission is the append-only authoritative result of sending a
// previously authorized phase directly to the stock Operator.
type VaultBoardSubmission struct {
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

// VaultBoardDispatch is written immediately before a previously authorized
// artifact leaves the process. Its absence makes an exact authorization safe
// to retry; its presence without a result is deliberately ambiguous.
type VaultBoardDispatch struct {
	OperationID   string
	Attempt       uint32
	Phase         string
	RequestDigest []byte
	CreatedAt     string
	IntegrityMAC  []byte
}

// VaultBoardRegisterRequest contains only per-attempt register evidence.
// The store derives the operation id and allocates the attempt atomically;
// neither value is accepted from an endpoint caller.
type VaultBoardRegisterRequest struct {
	RequestDigest  []byte
	TreeSessionPub []byte
	ReceiverSats   int64
	FeeSats        int64
	ExpireAt       int64
}

// VaultBoardAttemptSnapshot is the MAC-verified durable state for the latest
// server-allocated attempt. It contains no signing artifact.
type VaultBoardAttemptSnapshot struct {
	Operation           VaultBoardOperation
	Register            VaultBoardAuthorization
	RegisterDispatch    *VaultBoardDispatch
	RegisterSubmission  *VaultBoardSubmission
	DeleteAuthorization *VaultBoardAuthorization
	DeleteDispatch      *VaultBoardDispatch
	DeleteSubmission    *VaultBoardSubmission
	FinalAuthorization  *VaultBoardAuthorization
	FinalDispatch       *VaultBoardDispatch
	FinalSubmission     *VaultBoardSubmission
}

func SealVaultBoardEnrollment(rec *VaultBoardEnrollment, key []byte) error {
	mac, err := vaultBoardMAC(canonicalVaultBoardEnrollment, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardEnrollment(rec *VaultBoardEnrollment, key []byte) error {
	return verifyVaultBoardMAC(canonicalVaultBoardEnrollment, rec, rec.IntegrityMAC, key, "enrollment")
}

func SealVaultBoardOperation(rec *VaultBoardOperation, key []byte) error {
	mac, err := vaultBoardMAC(canonicalVaultBoardOperation, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardOperation(rec *VaultBoardOperation, key []byte) error {
	return verifyVaultBoardMAC(canonicalVaultBoardOperation, rec, rec.IntegrityMAC, key, "operation")
}

func SealVaultBoardAuthorization(rec *VaultBoardAuthorization, key []byte) error {
	mac, err := vaultBoardMAC(canonicalVaultBoardAuthorization, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardAuthorization(rec *VaultBoardAuthorization, key []byte) error {
	return verifyVaultBoardMAC(canonicalVaultBoardAuthorization, rec, rec.IntegrityMAC, key, "authorization")
}

func SealVaultBoardDispatch(rec *VaultBoardDispatch, key []byte) error {
	mac, err := vaultBoardMAC(canonicalVaultBoardDispatch, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardDispatch(rec *VaultBoardDispatch, key []byte) error {
	return verifyVaultBoardMAC(canonicalVaultBoardDispatch, rec, rec.IntegrityMAC, key, "dispatch")
}

func SealVaultBoardSubmission(rec *VaultBoardSubmission, key []byte) error {
	mac, err := vaultBoardMAC(canonicalVaultBoardSubmission, rec, key)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

func VerifyVaultBoardSubmission(rec *VaultBoardSubmission, key []byte) error {
	return verifyVaultBoardMAC(canonicalVaultBoardSubmission, rec, rec.IntegrityMAC, key, "submission")
}

type boardCanonicalizer[T any] func(*T) ([]byte, error)

func vaultBoardMAC[T any](canonical boardCanonicalizer[T], rec *T, key []byte) ([]byte, error) {
	if rec == nil || len(key) != sha256.Size {
		return nil, fmt.Errorf("vault-board-v1 integrity key")
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

func verifyVaultBoardMAC[T any](canonical boardCanonicalizer[T], rec *T, got, key []byte, kind string) error {
	if len(got) != sha256.Size {
		return fmt.Errorf("vault-board-v1 %s integrity MAC missing or malformed", kind)
	}
	want, err := vaultBoardMAC(canonical, rec, key)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(got, want) {
		return fmt.Errorf("vault-board-v1 %s integrity MAC mismatch", kind)
	}
	return nil
}

func boardCanonical(domain string, fields ...[]byte) ([]byte, error) {
	out := make([]byte, 0, 384)
	var err error
	out, err = appendCredentialField(out, []byte(domain))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, vaultBoardCanonicalVersion)
	for _, field := range fields {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	return out, nil
}

func canonicalVaultBoardEnrollment(rec *VaultBoardEnrollment) ([]byte, error) {
	if rec == nil || rec.VaultID == "" || rec.Program != "vault-board-v1" || len(rec.BoardingPub) != 33 || len(rec.CosignerPub) != 33 || len(rec.OperatorPub) != 33 || len(rec.PkScript) != 34 || rec.Address == "" || rec.ExitDelay == 0 || rec.ExitDelayUnit == "" {
		return nil, fmt.Errorf("invalid vault-board-v1 enrollment")
	}
	out, err := boardCanonical(vaultBoardEnrollmentMACDomain, []byte(rec.VaultID), []byte(rec.Program), rec.BoardingPub, rec.CosignerPub, rec.OperatorPub, []byte(rec.ExitDelayUnit), rec.PkScript, []byte(rec.Address))
	if err != nil {
		return nil, err
	}
	return binary.LittleEndian.AppendUint32(out, rec.ExitDelay), nil
}

func canonicalVaultBoardOperation(rec *VaultBoardOperation) ([]byte, error) {
	if rec == nil || rec.OperationID == "" || rec.VaultID == "" || len(rec.Txid) != 32 || rec.ValueSats <= 0 || len(rec.BoardingScript) != 34 || len(rec.ReceiverScript) == 0 || rec.SequenceAnchorMTP <= 0 || rec.CreatedAt == "" {
		return nil, fmt.Errorf("invalid vault-board-v1 operation")
	}
	wantID, err := ComputeVaultBoardOperationID(rec.VaultID, rec.Txid, rec.Vout)
	if err != nil || rec.OperationID != wantID {
		return nil, fmt.Errorf("vault-board-v1 operation id mismatch")
	}
	out, err := boardCanonical(vaultBoardOperationMACDomain, []byte(rec.OperationID), []byte(rec.VaultID), rec.Txid, rec.BoardingScript, rec.ReceiverScript, []byte(rec.CreatedAt))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, rec.Vout)
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.ValueSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.SequenceAnchorMTP))
	return out, nil
}

// ComputeVaultBoardOperationID makes the runtime—not the client—the sole
// owner of one stable operation identity per enrolled boarding outpoint.
func ComputeVaultBoardOperationID(vaultID string, txid []byte, vout uint32) (string, error) {
	if vaultID == "" || len(txid) != 32 {
		return "", fmt.Errorf("vault-board-v1 outpoint required")
	}
	payload, err := boardCanonical(vaultBoardOperationIDDomain, []byte(vaultID), txid)
	if err != nil {
		return "", err
	}
	payload = binary.LittleEndian.AppendUint32(payload, vout)
	sum := taggedSHA256(vaultBoardOperationIDDomain, payload)
	zeroBytes(payload)
	return hex.EncodeToString(sum), nil
}

func canonicalVaultBoardAuthorization(rec *VaultBoardAuthorization) ([]byte, error) {
	if rec == nil || rec.OperationID == "" || len(rec.RequestDigest) != sha256.Size || rec.CreatedAt == "" {
		return nil, fmt.Errorf("invalid vault-board-v1 authorization")
	}
	switch rec.Phase {
	case VaultBoardPhaseRegister:
		if rec.ExpireAt <= 0 || len(rec.TreeSessionPub) != 33 || rec.ReceiverSats <= 0 || rec.FeeSats < 0 || rec.ReceiverSats > (1<<63-1)-rec.FeeSats ||
			rec.CommitmentTxid != "" || rec.ReceiverTxid != "" || rec.ReceiverVout != 0 {
			return nil, fmt.Errorf("vault-board-v1 register attempt fields required")
		}
	case VaultBoardPhaseFinalize:
		canonicalCommitment, rawCommitment, commitmentErr := canonicalVtxoTxid([]byte(rec.CommitmentTxid))
		zeroBytes(rawCommitment)
		canonicalReceiver, rawReceiver, receiverErr := canonicalVtxoTxid([]byte(rec.ReceiverTxid))
		zeroBytes(rawReceiver)
		if rec.ExpireAt != 0 || len(rec.TreeSessionPub) != 0 || rec.ReceiverSats != 0 || rec.FeeSats != 0 ||
			commitmentErr != nil || receiverErr != nil || rec.CommitmentTxid != canonicalCommitment || rec.ReceiverTxid != canonicalReceiver {
			return nil, fmt.Errorf("vault-board-v1 finalize fields")
		}
	case VaultBoardPhaseDelete:
		if rec.ExpireAt <= 0 || len(rec.TreeSessionPub) != 0 || rec.ReceiverSats != 0 || rec.FeeSats != 0 ||
			rec.CommitmentTxid != "" || rec.ReceiverTxid != "" || rec.ReceiverVout != 0 {
			return nil, fmt.Errorf("vault-board-v1 delete fields")
		}
	default:
		return nil, fmt.Errorf("invalid vault-board-v1 phase")
	}
	out, err := boardCanonical(vaultBoardAuthorizationDomain, []byte(rec.OperationID), []byte(rec.Phase), rec.RequestDigest, rec.TreeSessionPub, []byte(rec.CommitmentTxid), []byte(rec.ReceiverTxid), []byte(rec.CreatedAt))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, rec.Attempt)
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.ReceiverSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.FeeSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.ExpireAt))
	return binary.LittleEndian.AppendUint32(out, rec.ReceiverVout), nil
}

func canonicalVaultBoardSubmission(rec *VaultBoardSubmission) ([]byte, error) {
	if rec == nil || rec.OperationID == "" || len(rec.RequestDigest) != sha256.Size || rec.CreatedAt == "" || len(rec.OperatorRef) > MaxVaultBoardOperatorRefBytes {
		return nil, fmt.Errorf("invalid vault-board-v1 submission")
	}
	switch rec.Phase {
	case VaultBoardPhaseRegister:
		validSubmitted := rec.Outcome == VaultBoardAuthSubmitted && rec.OperatorRef != ""
		validRejected := rec.Outcome == VaultBoardAuthRejected && rec.OperatorRef == ""
		if (!validSubmitted && !validRejected) || rec.CommitmentTxid != "" || rec.ReceiverTxid != "" || rec.ReceiverVout != 0 {
			return nil, fmt.Errorf("vault-board-v1 intent id required")
		}
	case VaultBoardPhaseDelete:
		if rec.Outcome != VaultBoardAuthReleased || rec.OperatorRef != "" || rec.CommitmentTxid != "" || rec.ReceiverTxid != "" || rec.ReceiverVout != 0 {
			return nil, fmt.Errorf("vault-board-v1 delete result")
		}
	case VaultBoardPhaseFinalize:
		canonicalCommitment, rawCommitment, commitmentErr := canonicalVtxoTxid([]byte(rec.CommitmentTxid))
		zeroBytes(rawCommitment)
		canonicalReceiver, rawReceiver, receiverErr := canonicalVtxoTxid([]byte(rec.ReceiverTxid))
		zeroBytes(rawReceiver)
		if rec.Outcome != VaultBoardAuthSubmitted || rec.OperatorRef != "" || commitmentErr != nil || receiverErr != nil ||
			rec.CommitmentTxid != canonicalCommitment || rec.ReceiverTxid != canonicalReceiver {
			return nil, fmt.Errorf("vault-board-v1 finalize result")
		}
	default:
		return nil, fmt.Errorf("invalid vault-board-v1 phase")
	}
	out, err := boardCanonical(vaultBoardSubmissionMACDomain, []byte(rec.OperationID), []byte(rec.Phase), rec.RequestDigest, []byte(rec.Outcome), []byte(rec.OperatorRef), []byte(rec.CommitmentTxid), []byte(rec.ReceiverTxid), []byte(rec.CreatedAt))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, rec.Attempt)
	return binary.LittleEndian.AppendUint32(out, rec.ReceiverVout), nil
}

func canonicalVaultBoardDispatch(rec *VaultBoardDispatch) ([]byte, error) {
	if rec == nil || rec.OperationID == "" || len(rec.RequestDigest) != sha256.Size || rec.CreatedAt == "" {
		return nil, fmt.Errorf("invalid vault-board-v1 dispatch")
	}
	switch rec.Phase {
	case VaultBoardPhaseRegister, VaultBoardPhaseDelete, VaultBoardPhaseFinalize:
	default:
		return nil, fmt.Errorf("invalid vault-board-v1 phase")
	}
	out, err := boardCanonical(vaultBoardDispatchMACDomain, []byte(rec.OperationID), []byte(rec.Phase), rec.RequestDigest, []byte(rec.CreatedAt))
	if err != nil {
		return nil, err
	}
	return binary.LittleEndian.AppendUint32(out, rec.Attempt), nil
}

// PutVaultBoardEnrollmentTx adds the immutable boarding binding in the caller's
// enrollment transaction.
func PutVaultBoardEnrollmentTx(tx *sql.Tx, rec VaultBoardEnrollment) error {
	if tx == nil {
		return fmt.Errorf("vault-board-v1 enrollment transaction required")
	}
	_, err := tx.Exec(`INSERT INTO vault_board_enrollment (vault_id, program, boarding_pub, cosigner_pub, operator_pub, exit_delay, exit_delay_unit, pk_script, address, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, rec.VaultID, rec.Program, rec.BoardingPub, rec.CosignerPub, rec.OperatorPub, rec.ExitDelay, rec.ExitDelayUnit, rec.PkScript, rec.Address, rec.IntegrityMAC)
	return err
}

func (l *Ledger) GetVaultBoardEnrollment(vaultID string) (*VaultBoardEnrollment, error) {
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
	var rec VaultBoardEnrollment
	err = l.db.QueryRow(`SELECT vault_id, program, boarding_pub, cosigner_pub, operator_pub, exit_delay, exit_delay_unit, pk_script, address, integrity_mac FROM vault_board_enrollment WHERE vault_id = ?`, vaultID).Scan(&rec.VaultID, &rec.Program, &rec.BoardingPub, &rec.CosignerPub, &rec.OperatorPub, &rec.ExitDelay, &rec.ExitDelayUnit, &rec.PkScript, &rec.Address, &rec.IntegrityMAC)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyVaultBoardEnrollment(&rec, key); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (l *Ledger) GetCurrentVaultBoardAttempt(ctx context.Context, operationID string) (*VaultBoardAttemptSnapshot, error) {
	if operationID == "" {
		return nil, fmt.Errorf("vault-board-v1 operation id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	operation, err := loadVaultBoardOperation(ctx, l.db, operationID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyVaultBoardOperation(&operation, key); err != nil {
		return nil, err
	}
	register, err := loadLatestVaultBoardRegister(ctx, l.db, operationID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("vault-board-v1 operation has no register attempt")
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyVaultBoardAuthorization(&register, key); err != nil {
		return nil, err
	}
	snapshot := &VaultBoardAttemptSnapshot{Operation: operation, Register: register}
	if err := loadOptionalVerifiedVaultBoardDispatch(ctx, l.db, key, operationID, register.Attempt, VaultBoardPhaseRegister, &snapshot.RegisterDispatch); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardSubmission(ctx, l.db, key, operationID, register.Attempt, VaultBoardPhaseRegister, &snapshot.RegisterSubmission); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardAuthorization(ctx, l.db, key, operationID, register.Attempt, VaultBoardPhaseDelete, &snapshot.DeleteAuthorization); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardDispatch(ctx, l.db, key, operationID, register.Attempt, VaultBoardPhaseDelete, &snapshot.DeleteDispatch); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardSubmission(ctx, l.db, key, operationID, register.Attempt, VaultBoardPhaseDelete, &snapshot.DeleteSubmission); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardAuthorization(ctx, l.db, key, operationID, register.Attempt, VaultBoardPhaseFinalize, &snapshot.FinalAuthorization); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardDispatch(ctx, l.db, key, operationID, register.Attempt, VaultBoardPhaseFinalize, &snapshot.FinalDispatch); err != nil {
		return nil, err
	}
	if err := loadOptionalVerifiedVaultBoardSubmission(ctx, l.db, key, operationID, register.Attempt, VaultBoardPhaseFinalize, &snapshot.FinalSubmission); err != nil {
		return nil, err
	}
	if snapshot.RegisterSubmission != nil && !bytes.Equal(snapshot.RegisterSubmission.RequestDigest, register.RequestDigest) {
		return nil, fmt.Errorf("vault-board-v1 register result digest mismatch")
	}
	if snapshot.DeleteSubmission != nil && (snapshot.DeleteAuthorization == nil || !bytes.Equal(snapshot.DeleteSubmission.RequestDigest, snapshot.DeleteAuthorization.RequestDigest)) {
		return nil, fmt.Errorf("vault-board-v1 delete result digest mismatch")
	}
	if snapshot.FinalSubmission != nil && (snapshot.FinalAuthorization == nil || !bytes.Equal(snapshot.FinalSubmission.RequestDigest, snapshot.FinalAuthorization.RequestDigest)) {
		return nil, fmt.Errorf("vault-board-v1 final result digest mismatch")
	}
	for phase, pair := range map[string]struct {
		dispatch *VaultBoardDispatch
		auth     *VaultBoardAuthorization
	}{
		VaultBoardPhaseRegister: {dispatch: snapshot.RegisterDispatch, auth: &snapshot.Register},
		VaultBoardPhaseDelete:   {dispatch: snapshot.DeleteDispatch, auth: snapshot.DeleteAuthorization},
		VaultBoardPhaseFinalize: {dispatch: snapshot.FinalDispatch, auth: snapshot.FinalAuthorization},
	} {
		if pair.dispatch != nil && (pair.auth == nil || !bytes.Equal(pair.dispatch.RequestDigest, pair.auth.RequestDigest)) {
			return nil, fmt.Errorf("vault-board-v1 %s dispatch digest mismatch", phase)
		}
	}
	return snapshot, nil
}

// BeginVaultBoardAttempt binds the stable outpoint operation and allocates
// its next register attempt under the same BEGIN IMMEDIATE transaction.
func (l *Ledger) BeginVaultBoardAttempt(ctx context.Context, operation VaultBoardOperation, request VaultBoardRegisterRequest, chain VaultBoardChainState) (*VaultBoardOperation, *VaultBoardAuthorization, bool, error) {
	operationID, err := ComputeVaultBoardOperationID(operation.VaultID, operation.Txid, operation.Vout)
	if err != nil {
		return nil, nil, false, err
	}
	if operation.OperationID != "" && operation.OperationID != operationID {
		return nil, nil, false, fmt.Errorf("vault-board-v1 operation id is server-derived")
	}
	if len(request.RequestDigest) != sha256.Size || len(request.TreeSessionPub) != 33 || request.ReceiverSats <= 0 || request.FeeSats < 0 ||
		request.ReceiverSats > (1<<63-1)-request.FeeSats || request.ReceiverSats+request.FeeSats != operation.ValueSats || request.ExpireAt <= l.NowUTC().Unix() {
		return nil, nil, false, fmt.Errorf("vault-board-v1 finite register request required")
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
	stored, err := loadVaultBoardOperation(ctx, conn, operationID)
	switch err {
	case nil:
		if err := VerifyVaultBoardOperation(&stored, key); err != nil {
			return nil, nil, false, err
		}
		if !sameVaultBoardOperationFacts(stored, operation) {
			return nil, nil, false, fmt.Errorf("vault-board-v1 outpoint is bound to different economic facts")
		}
	case sql.ErrNoRows:
		operation.CreatedAt = now.Format(time.RFC3339Nano)
		if err := SealVaultBoardOperation(&operation, key); err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_operation (operation_id, vault_id, txid, vout, value_sats, boarding_script, receiver_script, sequence_anchor_mtp, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, operation.OperationID, operation.VaultID, operation.Txid, operation.Vout, operation.ValueSats, operation.BoardingScript, operation.ReceiverScript, operation.SequenceAnchorMTP, operation.CreatedAt, operation.IntegrityMAC); err != nil {
			return nil, nil, false, err
		}
		stored = operation
	default:
		return nil, nil, false, err
	}
	if err := requireVaultBoardCooperativeWindow(stored, chain); err != nil {
		return nil, nil, false, err
	}

	registers, err := loadVerifiedVaultBoardRegisters(ctx, conn, key, operationID)
	if err != nil {
		return nil, nil, false, err
	}
	for i := range registers {
		prior := registers[i]
		if bytes.Equal(prior.RequestDigest, request.RequestDigest) || bytes.Equal(prior.TreeSessionPub, request.TreeSessionPub) {
			isLatest := i == len(registers)-1
			if isLatest && bytes.Equal(prior.RequestDigest, request.RequestDigest) && bytes.Equal(prior.TreeSessionPub, request.TreeSessionPub) &&
				prior.ReceiverSats == request.ReceiverSats && prior.FeeSats == request.FeeSats && prior.ExpireAt == request.ExpireAt {
				if err := requireVaultBoardAttemptCurrent(ctx, conn, key, operationID, prior.Attempt); err != nil {
					return nil, nil, false, err
				}
				if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
					return nil, nil, false, err
				}
				committed = true
				return &stored, &prior, false, nil
			}
			return nil, nil, false, fmt.Errorf("vault-board-v1 attempt must rotate register digest and tree session key")
		}
	}

	attempt := uint32(0)
	if len(registers) > 0 {
		last := registers[len(registers)-1]
		if last.Attempt == ^uint32(0) {
			return nil, nil, false, fmt.Errorf("vault-board-v1 attempt overflow")
		}
		if err := requireVaultBoardAttemptCanRotate(ctx, conn, key, operationID, last.Attempt, now); err != nil {
			return nil, nil, false, err
		}
		attempt = last.Attempt + 1
	}
	auth := VaultBoardAuthorization{
		OperationID: operationID, Attempt: attempt, Phase: VaultBoardPhaseRegister,
		RequestDigest: append([]byte(nil), request.RequestDigest...), TreeSessionPub: append([]byte(nil), request.TreeSessionPub...),
		ReceiverSats: request.ReceiverSats, FeeSats: request.FeeSats,
		ExpireAt: request.ExpireAt, CreatedAt: now.Format(time.RFC3339Nano),
	}
	if err := SealVaultBoardAuthorization(&auth, key); err != nil {
		return nil, nil, false, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_authorization (operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, auth.OperationID, auth.Attempt, auth.Phase, auth.RequestDigest, nullableVaultBoardBytes(auth.TreeSessionPub), auth.ReceiverSats, auth.FeeSats, auth.ExpireAt, auth.CommitmentTxid, auth.ReceiverTxid, auth.ReceiverVout, auth.CreatedAt, auth.IntegrityMAC); err != nil {
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

// AppendVaultBoardAuthorizationAndDispatch closes the delete/final crash
// gap: once a fully signed artifact exists in memory, the exact semantic
// authorization and its outbound boundary become durable in one SQLite
// transaction. No signed artifact is persisted.
func (l *Ledger) AppendVaultBoardAuthorizationAndDispatch(ctx context.Context, auth VaultBoardAuthorization, chain VaultBoardChainState) (*VaultBoardAuthorization, *VaultBoardDispatch, bool, error) {
	if auth.Phase != VaultBoardPhaseDelete && auth.Phase != VaultBoardPhaseFinalize {
		return nil, nil, false, fmt.Errorf("vault-board-v1 atomic dispatch is delete/final only")
	}
	if auth.OperationID == "" {
		return nil, nil, false, fmt.Errorf("vault-board-v1 operation required")
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
	operation, err := loadVaultBoardOperation(ctx, conn, auth.OperationID)
	if err != nil {
		return nil, nil, false, err
	}
	if err := VerifyVaultBoardOperation(&operation, key); err != nil {
		return nil, nil, false, err
	}
	if err := requireVaultBoardCooperativeWindow(operation, chain); err != nil {
		return nil, nil, false, err
	}
	latest, err := loadLatestVaultBoardRegister(ctx, conn, auth.OperationID)
	if err != nil {
		return nil, nil, false, err
	}
	if err := VerifyVaultBoardAuthorization(&latest, key); err != nil {
		return nil, nil, false, err
	}
	if latest.Attempt != auth.Attempt {
		return nil, nil, false, fmt.Errorf("vault-board-v1 attempt is no longer current")
	}
	storedAuth, authErr := loadVaultBoardAuthorization(ctx, conn, auth.OperationID, auth.Attempt, auth.Phase)
	if authErr == nil {
		if err := VerifyVaultBoardAuthorization(&storedAuth, key); err != nil {
			return nil, nil, false, err
		}
		if !sameVaultBoardAuthorizationRequest(storedAuth, auth) {
			return nil, nil, false, fmt.Errorf("vault-board-v1 phase is bound to a different exact request")
		}
		auth = storedAuth
	} else if authErr != sql.ErrNoRows {
		return nil, nil, false, authErr
	} else {
		if err := validateVaultBoardPhaseOrder(ctx, conn, key, auth); err != nil {
			return nil, nil, false, err
		}
		auth.CreatedAt = l.NowUTC().Format(time.RFC3339Nano)
		if err := SealVaultBoardAuthorization(&auth, key); err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_authorization (operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, auth.OperationID, auth.Attempt, auth.Phase, auth.RequestDigest, nullableVaultBoardBytes(auth.TreeSessionPub), auth.ReceiverSats, auth.FeeSats, auth.ExpireAt, auth.CommitmentTxid, auth.ReceiverTxid, auth.ReceiverVout, auth.CreatedAt, auth.IntegrityMAC); err != nil {
			return nil, nil, false, err
		}
	}
	if existing, err := loadVaultBoardDispatch(ctx, conn, auth.OperationID, auth.Attempt, auth.Phase); err == nil {
		if err := VerifyVaultBoardDispatch(&existing, key); err != nil {
			return nil, nil, false, err
		}
		if !bytes.Equal(existing.RequestDigest, auth.RequestDigest) {
			return nil, nil, false, fmt.Errorf("vault-board-v1 dispatch request changed")
		}
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return nil, nil, false, err
		}
		committed = true
		return &auth, &existing, false, nil
	} else if err != sql.ErrNoRows {
		return nil, nil, false, err
	}
	if _, err := loadVaultBoardSubmission(ctx, conn, auth.OperationID, auth.Attempt, auth.Phase); err == nil {
		return nil, nil, false, fmt.Errorf("vault-board-v1 result already recorded")
	} else if err != sql.ErrNoRows {
		return nil, nil, false, err
	}
	dispatch := VaultBoardDispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: bytes.Clone(auth.RequestDigest), CreatedAt: l.NowUTC().Format(time.RFC3339Nano),
	}
	if err := SealVaultBoardDispatch(&dispatch, key); err != nil {
		return nil, nil, false, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_dispatch (operation_id, attempt, phase, request_digest, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?)`, dispatch.OperationID, dispatch.Attempt, dispatch.Phase, dispatch.RequestDigest, dispatch.CreatedAt, dispatch.IntegrityMAC); err != nil {
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

func sameVaultBoardOperationFacts(stored, proposed VaultBoardOperation) bool {
	return stored.OperationID == proposed.OperationID && stored.VaultID == proposed.VaultID &&
		bytes.Equal(stored.Txid, proposed.Txid) && stored.Vout == proposed.Vout &&
		stored.ValueSats == proposed.ValueSats && bytes.Equal(stored.BoardingScript, proposed.BoardingScript) &&
		bytes.Equal(stored.ReceiverScript, proposed.ReceiverScript) && stored.SequenceAnchorMTP == proposed.SequenceAnchorMTP
}

func sameVaultBoardAuthorizationRequest(stored, proposed VaultBoardAuthorization) bool {
	return stored.OperationID == proposed.OperationID && stored.Attempt == proposed.Attempt && stored.Phase == proposed.Phase &&
		bytes.Equal(stored.RequestDigest, proposed.RequestDigest) && bytes.Equal(stored.TreeSessionPub, proposed.TreeSessionPub) &&
		stored.ReceiverSats == proposed.ReceiverSats && stored.FeeSats == proposed.FeeSats && stored.ExpireAt == proposed.ExpireAt &&
		stored.CommitmentTxid == proposed.CommitmentTxid && stored.ReceiverTxid == proposed.ReceiverTxid && stored.ReceiverVout == proposed.ReceiverVout
}

func requireVaultBoardCooperativeWindow(operation VaultBoardOperation, chain VaultBoardChainState) error {
	if operation.SequenceAnchorMTP <= 0 || chain.TipMTP <= 0 {
		return fmt.Errorf("authoritative vault-board-v1 chain MTP required")
	}
	if operation.SequenceAnchorMTP > (1<<63-1)-int64(program.VaultBoardV1ExitDelay) ||
		chain.TipMTP >= operation.SequenceAnchorMTP+int64(program.VaultBoardV1ExitDelay) {
		return fmt.Errorf("vault-board-v1 cooperative path has matured")
	}
	return nil
}

func loadVerifiedVaultBoardRegisters(ctx context.Context, q queryContext, key []byte, operationID string) ([]VaultBoardAuthorization, error) {
	rows, err := q.QueryContext(ctx, `SELECT operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac FROM vault_board_authorization WHERE operation_id = ? AND phase = 'register' ORDER BY attempt`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultBoardAuthorization
	for rows.Next() {
		var rec VaultBoardAuthorization
		if err := rows.Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.TreeSessionPub, &rec.ReceiverSats, &rec.FeeSats, &rec.ExpireAt, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC); err != nil {
			return nil, err
		}
		if err := VerifyVaultBoardAuthorization(&rec, key); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func requireVaultBoardAttemptCanRotate(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32, now time.Time) error {
	if finalAuth, err := loadVaultBoardAuthorization(ctx, q, operationID, attempt, VaultBoardPhaseFinalize); err == nil {
		if err := VerifyVaultBoardAuthorization(&finalAuth, key); err != nil {
			return err
		}
		return fmt.Errorf("finalized vault-board-v1 attempt cannot rotate")
	} else if err != sql.ErrNoRows {
		return err
	}
	register, err := loadVaultBoardAuthorization(ctx, q, operationID, attempt, VaultBoardPhaseRegister)
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardAuthorization(&register, key); err != nil {
		return err
	}
	registerDispatch, err := loadVaultBoardDispatch(ctx, q, operationID, attempt, VaultBoardPhaseRegister)
	if err == sql.ErrNoRows {
		// A register authorization that never crossed the durable dispatch
		// boundary cannot have reached the Operator.
		return nil
	}
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardDispatch(&registerDispatch, key); err != nil {
		return err
	}
	registerResult, resultErr := loadVaultBoardSubmission(ctx, q, operationID, attempt, VaultBoardPhaseRegister)
	if resultErr == nil {
		if err := VerifyVaultBoardSubmission(&registerResult, key); err != nil {
			return err
		}
		if registerResult.Outcome == VaultBoardAuthRejected {
			return nil
		}
	} else if resultErr == sql.ErrNoRows {
		// Dispatch crossed the Operator boundary without a definite outcome.
		return fmt.Errorf("previous vault-board-v1 register is still active")
	} else {
		return resultErr
	}

	deleteAuth, deleteErr := loadVaultBoardAuthorization(ctx, q, operationID, attempt, VaultBoardPhaseDelete)
	if deleteErr == nil {
		if err := VerifyVaultBoardAuthorization(&deleteAuth, key); err != nil {
			return err
		}
		if deleteDispatch, dispatchErr := loadVaultBoardDispatch(ctx, q, operationID, attempt, VaultBoardPhaseDelete); dispatchErr == nil {
			if err := VerifyVaultBoardDispatch(&deleteDispatch, key); err != nil {
				return err
			}
			if deleteResult, resultErr := loadVaultBoardSubmission(ctx, q, operationID, attempt, VaultBoardPhaseDelete); resultErr == nil {
				if err := VerifyVaultBoardSubmission(&deleteResult, key); err != nil {
					return err
				}
				if deleteResult.Outcome == VaultBoardAuthReleased && bytes.Equal(deleteResult.RequestDigest, deleteAuth.RequestDigest) {
					return nil
				}
			} else if resultErr != sql.ErrNoRows {
				return resultErr
			}
			return fmt.Errorf("previous vault-board-v1 register is still active")
		} else if dispatchErr != sql.ErrNoRows {
			return dispatchErr
		}
	} else if deleteErr != sql.ErrNoRows {
		return deleteErr
	}

	if registerResult.Outcome == VaultBoardAuthSubmitted && VaultBoardRegisterCanSupersede(register.ExpireAt, now) {
		return nil
	}
	return fmt.Errorf("previous vault-board-v1 register is still active")
}

func requireVaultBoardAttemptCurrent(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32) error {
	if registerResult, err := loadVaultBoardSubmission(ctx, q, operationID, attempt, VaultBoardPhaseRegister); err == nil {
		if err := VerifyVaultBoardSubmission(&registerResult, key); err != nil {
			return err
		}
		if registerResult.Outcome == VaultBoardAuthRejected {
			return fmt.Errorf("vault-board-v1 register request was definitely rejected")
		}
	} else if err != sql.ErrNoRows {
		return err
	}
	if finalAuth, err := loadVaultBoardAuthorization(ctx, q, operationID, attempt, VaultBoardPhaseFinalize); err == nil {
		if err := VerifyVaultBoardAuthorization(&finalAuth, key); err != nil {
			return err
		}
		return fmt.Errorf("vault-board-v1 attempt has final authorization")
	} else if err != sql.ErrNoRows {
		return err
	}
	if deleteAuth, err := loadVaultBoardAuthorization(ctx, q, operationID, attempt, VaultBoardPhaseDelete); err == nil {
		if err := VerifyVaultBoardAuthorization(&deleteAuth, key); err != nil {
			return err
		}
		return fmt.Errorf("vault-board-v1 attempt has delete authorization")
	} else if err != sql.ErrNoRows {
		return err
	}
	if deleteResult, err := loadVaultBoardSubmission(ctx, q, operationID, attempt, VaultBoardPhaseDelete); err == nil {
		if err := VerifyVaultBoardSubmission(&deleteResult, key); err != nil {
			return err
		}
		return fmt.Errorf("vault-board-v1 attempt was authoritatively released")
	} else if err != sql.ErrNoRows {
		return err
	}
	return nil
}

func loadLatestVaultBoardRegister(ctx context.Context, q queryContext, operationID string) (VaultBoardAuthorization, error) {
	var rec VaultBoardAuthorization
	err := q.QueryRowContext(ctx, `SELECT operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac FROM vault_board_authorization WHERE operation_id = ? AND phase = 'register' ORDER BY attempt DESC LIMIT 1`, operationID).Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.TreeSessionPub, &rec.ReceiverSats, &rec.FeeSats, &rec.ExpireAt, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}

func loadOptionalVerifiedVaultBoardAuthorization(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32, phase string, out **VaultBoardAuthorization) error {
	rec, err := loadVaultBoardAuthorization(ctx, q, operationID, attempt, phase)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardAuthorization(&rec, key); err != nil {
		return err
	}
	*out = &rec
	return nil
}

func loadOptionalVerifiedVaultBoardSubmission(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32, phase string, out **VaultBoardSubmission) error {
	rec, err := loadVaultBoardSubmission(ctx, q, operationID, attempt, phase)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardSubmission(&rec, key); err != nil {
		return err
	}
	*out = &rec
	return nil
}

func loadOptionalVerifiedVaultBoardDispatch(ctx context.Context, q queryContext, key []byte, operationID string, attempt uint32, phase string, out **VaultBoardDispatch) error {
	rec, err := loadVaultBoardDispatch(ctx, q, operationID, attempt, phase)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardDispatch(&rec, key); err != nil {
		return err
	}
	*out = &rec
	return nil
}

// AppendVaultBoardDispatch durably records that an exact authorized request
// is about to cross the network boundary. No network call may happen first.
func (l *Ledger) AppendVaultBoardDispatch(ctx context.Context, rec VaultBoardDispatch, chain VaultBoardChainState) (*VaultBoardDispatch, bool, error) {
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
	operation, err := loadVaultBoardOperation(ctx, conn, rec.OperationID)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyVaultBoardOperation(&operation, key); err != nil {
		return nil, false, err
	}
	if err := requireVaultBoardCooperativeWindow(operation, chain); err != nil {
		return nil, false, err
	}
	if existing, err := loadVaultBoardDispatch(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase); err == nil {
		if err := VerifyVaultBoardDispatch(&existing, key); err != nil {
			return nil, false, err
		}
		if !bytes.Equal(existing.RequestDigest, rec.RequestDigest) {
			return nil, false, fmt.Errorf("vault-board-v1 dispatch request changed")
		}
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return nil, false, err
		}
		committed = true
		return &existing, false, nil
	} else if err != sql.ErrNoRows {
		return nil, false, err
	}
	auth, err := loadVaultBoardAuthorization(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyVaultBoardAuthorization(&auth, key); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(auth.RequestDigest, rec.RequestDigest) {
		return nil, false, fmt.Errorf("vault-board-v1 dispatch request changed")
	}
	latest, err := loadLatestVaultBoardRegister(ctx, conn, rec.OperationID)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyVaultBoardAuthorization(&latest, key); err != nil {
		return nil, false, err
	}
	if latest.Attempt != rec.Attempt {
		return nil, false, fmt.Errorf("vault-board-v1 attempt is no longer current")
	}
	if _, err := loadVaultBoardSubmission(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase); err == nil {
		return nil, false, fmt.Errorf("vault-board-v1 result already recorded")
	} else if err != sql.ErrNoRows {
		return nil, false, err
	}
	rec.CreatedAt = l.NowUTC().Format(time.RFC3339Nano)
	if err := SealVaultBoardDispatch(&rec, key); err != nil {
		return nil, false, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_dispatch (operation_id, attempt, phase, request_digest, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?)`, rec.OperationID, rec.Attempt, rec.Phase, rec.RequestDigest, rec.CreatedAt, rec.IntegrityMAC); err != nil {
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

func nullableVaultBoardBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

// AppendVaultBoardSubmission records only authoritative success returned by
// the stock Operator. No signed proof or PSBT is durable.
func (l *Ledger) AppendVaultBoardSubmission(ctx context.Context, rec VaultBoardSubmission) (*VaultBoardSubmission, bool, error) {
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
	if current, err := loadVaultBoardSubmission(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase); err == nil {
		if err := VerifyVaultBoardSubmission(&current, key); err != nil {
			return nil, false, err
		}
		if !bytes.Equal(current.RequestDigest, rec.RequestDigest) || current.Outcome != rec.Outcome || current.OperatorRef != rec.OperatorRef ||
			current.CommitmentTxid != rec.CommitmentTxid || current.ReceiverTxid != rec.ReceiverTxid || current.ReceiverVout != rec.ReceiverVout {
			return nil, false, fmt.Errorf("vault-board-v1 Operator result changed")
		}
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return nil, false, err
		}
		commit = true
		return &current, false, nil
	} else if err != sql.ErrNoRows {
		return nil, false, err
	}
	auth, err := loadVaultBoardAuthorization(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyVaultBoardAuthorization(&auth, key); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(auth.RequestDigest, rec.RequestDigest) {
		return nil, false, fmt.Errorf("vault-board-v1 request changed")
	}
	dispatch, err := loadVaultBoardDispatch(ctx, conn, rec.OperationID, rec.Attempt, rec.Phase)
	if err != nil {
		return nil, false, fmt.Errorf("vault-board-v1 dispatch required")
	}
	if err := VerifyVaultBoardDispatch(&dispatch, key); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(dispatch.RequestDigest, rec.RequestDigest) {
		return nil, false, fmt.Errorf("vault-board-v1 dispatch request changed")
	}
	rec.CreatedAt = l.NowUTC().Format(time.RFC3339Nano)
	if err := SealVaultBoardSubmission(&rec, key); err != nil {
		return nil, false, err
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO vault_board_submission (operation_id, attempt, phase, request_digest, outcome, operator_ref, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, rec.OperationID, rec.Attempt, rec.Phase, rec.RequestDigest, rec.Outcome, rec.OperatorRef, rec.CommitmentTxid, rec.ReceiverTxid, rec.ReceiverVout, rec.CreatedAt, rec.IntegrityMAC)
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

func validateVaultBoardPhaseOrder(ctx context.Context, q queryContext, key []byte, auth VaultBoardAuthorization) error {
	latest, latestErr := loadLatestVaultBoardRegister(ctx, q, auth.OperationID)
	if latestErr != nil {
		return latestErr
	}
	if err := VerifyVaultBoardAuthorization(&latest, key); err != nil {
		return err
	}
	if latest.Attempt != auth.Attempt {
		return fmt.Errorf("vault-board-v1 attempt is no longer current")
	}
	register, regErr := loadVaultBoardAuthorization(ctx, q, auth.OperationID, auth.Attempt, VaultBoardPhaseRegister)
	if regErr == nil {
		if err := VerifyVaultBoardAuthorization(&register, key); err != nil {
			return err
		}
	}
	switch auth.Phase {
	case VaultBoardPhaseDelete, VaultBoardPhaseFinalize:
		if regErr != nil {
			return fmt.Errorf("vault-board-v1 register authorization required")
		}
		registerSubmission, err := loadVaultBoardSubmission(ctx, q, auth.OperationID, auth.Attempt, VaultBoardPhaseRegister)
		if err != nil {
			return fmt.Errorf("vault-board-v1 register submission required")
		}
		if err := VerifyVaultBoardSubmission(&registerSubmission, key); err != nil {
			return err
		}
		if registerSubmission.Outcome != VaultBoardAuthSubmitted {
			return fmt.Errorf("vault-board-v1 register was not accepted")
		}
		opposite := VaultBoardPhaseFinalize
		if auth.Phase == VaultBoardPhaseFinalize {
			opposite = VaultBoardPhaseDelete
		}
		if oppositeAuth, err := loadVaultBoardAuthorization(ctx, q, auth.OperationID, auth.Attempt, opposite); err == nil {
			if err := VerifyVaultBoardAuthorization(&oppositeAuth, key); err != nil {
				return err
			}
			return fmt.Errorf("vault-board-v1 delete and finalize are mutually exclusive")
		} else if err != sql.ErrNoRows {
			return err
		}
		return nil
	default:
		return fmt.Errorf("invalid vault-board-v1 phase")
	}
}

func loadVaultBoardOperation(ctx context.Context, q queryContext, id string) (VaultBoardOperation, error) {
	var rec VaultBoardOperation
	err := q.QueryRowContext(ctx, `SELECT operation_id, vault_id, txid, vout, value_sats, boarding_script, receiver_script, sequence_anchor_mtp, created_at, integrity_mac FROM vault_board_operation WHERE operation_id = ?`, id).Scan(&rec.OperationID, &rec.VaultID, &rec.Txid, &rec.Vout, &rec.ValueSats, &rec.BoardingScript, &rec.ReceiverScript, &rec.SequenceAnchorMTP, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}

func loadVaultBoardAuthorization(ctx context.Context, q queryContext, id string, attempt uint32, phase string) (VaultBoardAuthorization, error) {
	var rec VaultBoardAuthorization
	err := q.QueryRowContext(ctx, `SELECT operation_id, attempt, phase, request_digest, tree_session_pub, receiver_sats, fee_sats, expire_at, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac FROM vault_board_authorization WHERE operation_id = ? AND attempt = ? AND phase = ?`, id, attempt, phase).Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.TreeSessionPub, &rec.ReceiverSats, &rec.FeeSats, &rec.ExpireAt, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}

func loadVaultBoardSubmission(ctx context.Context, q queryContext, id string, attempt uint32, phase string) (VaultBoardSubmission, error) {
	var rec VaultBoardSubmission
	err := q.QueryRowContext(ctx, `SELECT operation_id, attempt, phase, request_digest, outcome, operator_ref, commitment_txid, receiver_txid, receiver_vout, created_at, integrity_mac FROM vault_board_submission WHERE operation_id = ? AND attempt = ? AND phase = ?`, id, attempt, phase).Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.Outcome, &rec.OperatorRef, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}

func loadVaultBoardDispatch(ctx context.Context, q queryContext, id string, attempt uint32, phase string) (VaultBoardDispatch, error) {
	var rec VaultBoardDispatch
	err := q.QueryRowContext(ctx, `SELECT operation_id, attempt, phase, request_digest, created_at, integrity_mac FROM vault_board_dispatch WHERE operation_id = ? AND attempt = ? AND phase = ?`, id, attempt, phase).Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.CreatedAt, &rec.IntegrityMAC)
	return rec, err
}
