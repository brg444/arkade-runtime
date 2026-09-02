package application

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/brg444/arkade-vault-server/internal/apperr"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/ports"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

const vtxoReserveAuthorizeTimeout = 2 * time.Minute

// VtxoReserveRequest is POST /v1/vtxo/reserve. Spend only.
type VtxoReserveRequest struct {
	OperationID    string `json:"operationId"`
	VaultID        string `json:"vaultId"`
	Purpose        string `json:"purpose"`
	DestAddress    string `json:"destAddress"`
	AmountSats     uint64 `json:"amountSats"`
	PhoneSignature string `json:"phoneSignature"`
}

// VtxoInputView is one reserved outpoint in a reserve response.
type VtxoInputView struct {
	Txid      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	ValueSats uint64 `json:"valueSats"`
	ScriptHex string `json:"scriptHex"`
}

// VtxoReserveResponse is the server-computed reservation. No unsigned PSBT.
type VtxoReserveResponse struct {
	OperationID         string          `json:"operationId"`
	BundleDigest        string          `json:"bundleDigest"`
	ReservationExpires  string          `json:"reservationExpires"`
	Inputs              []VtxoInputView `json:"inputs"`
	ChangeAddress       string          `json:"changeAddress"`
	ChangeScript        string          `json:"changeScript"`
	DestScript          string          `json:"destScript"`
	FeeSats             uint64          `json:"feeSats"`
	FeePolicyDigest     string          `json:"feePolicyDigest"`
	ChangeSats          uint64          `json:"changeSats"`
	ChangeVout          *uint32         `json:"changeVout,omitempty"`
	CheckpointTapscript string          `json:"checkpointTapscript,omitempty"`
}

// VtxoAuthorizeRequest is POST /v1/vtxo/authorize (spend).
type VtxoAuthorizeRequest struct {
	VaultID                 string   `json:"vaultId"`
	OperationID             string   `json:"operationId"`
	BundleDigest            string   `json:"bundleDigest"`
	UnsignedArkPsbt         string   `json:"unsignedArkPsbt"`
	UnsignedCheckpointPsbts []string `json:"unsignedCheckpointPsbts"`
	PendingProof            string   `json:"pendingProof"`
	CredentialID            string   `json:"credentialId"`
	ClientDataJSON          string   `json:"clientDataJSON"`
	AuthenticatorData       string   `json:"authenticatorData"`
	Signature               string   `json:"signature"`
	DirectSig               string   `json:"directSig"`
}

// VtxoAuthorizeResponse returns the VaultCosigner-authorized Ark PSBT and the
// dual-signed proof that can recover an ambiguous Operator SubmitTx result. The
// Operator-returned checkpoints use the separate post-submit endpoint.
type VtxoAuthorizeResponse struct {
	OperationID            string `json:"operationId"`
	BundleDigest           string `json:"bundleDigest"`
	AuthorizedPsbt         string `json:"authorizedPsbt"`
	AuthorizedPendingProof string `json:"authorizedPendingProof"`
	ArkTxid                string `json:"arkTxid"`
}

// VtxoCheckpointAuthorizeRequest is the post-submit signing stage. The
// Operator rebuilds and signs checkpoint PSBTs during submit, so the user and
// VaultCosigner signatures must be added to that returned stage, not to the
// pre-submit checkpoints.
type VtxoCheckpointAuthorizeRequest struct {
	VaultID         string   `json:"vaultId"`
	OperationID     string   `json:"operationId"`
	BundleDigest    string   `json:"bundleDigest"`
	CheckpointPsbts []string `json:"checkpointPsbts"`
}

// VtxoCheckpointAuthorizeResponse returns checkpoints ready for Operator
// finalization.
type VtxoCheckpointAuthorizeResponse struct {
	OperationID     string   `json:"operationId"`
	BundleDigest    string   `json:"bundleDigest"`
	CheckpointPsbts []string `json:"checkpointPsbts"`
	ArkTxid         string   `json:"arkTxid"`
}

// VtxoFinalizeRequest is POST /v1/vtxo/finalize.
type VtxoFinalizeRequest struct {
	VaultID      string `json:"vaultId"`
	OperationID  string `json:"operationId"`
	BundleDigest string `json:"bundleDigest"`
	ArkTxid      string `json:"arkTxid"`
}

// VtxoFinalizeResponse is the terminal spend receipt.
type VtxoFinalizeResponse struct {
	OperationID  string `json:"operationId"`
	BundleDigest string `json:"bundleDigest"`
	State        string `json:"state"`
	ArkTxid      string `json:"arkTxid"`
}

func (s *Service) requireArkResolver() error {
	if s == nil || isNilInterface(s.ArkResolver) {
		return apperr.New(apperr.CodeRejected, "ark indexer unavailable")
	}
	return nil
}

func (s *Service) vtxoNow() time.Time {
	if s != nil && s.Stores.VtxoOperations != nil {
		return s.Stores.VtxoOperations.NowUTC()
	}
	if s != nil && s.SessionNow != nil {
		return s.SessionNow().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) ReserveVtxo(ctx context.Context, req VtxoReserveRequest) (*VtxoReserveResponse, error) {
	opID, err := canonicalVtxoOperationID(req.OperationID)
	if err != nil {
		return nil, err
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	if err := s.requireVaultPolicyV1Exit(); err != nil {
		return nil, err
	}
	purpose := strings.TrimSpace(req.Purpose)
	if purpose != policy.VtxoPurposeSpend {
		return nil, apperr.New(apperr.CodeRejected, "vtxo purpose must be spend")
	}
	if req.AmountSats == 0 {
		return nil, apperr.New(apperr.CodeRejected, "amount required")
	}
	if err := s.requireArkResolver(); err != nil {
		return nil, err
	}
	vaultID, snap, rec, err := s.resolveSpendVaultRecord(req.VaultID)
	if err != nil {
		return nil, err
	}
	tree, err := s.buildVtxoPolicyTree(vaultID, snap)
	if err != nil {
		return nil, apperr.New(apperr.CodeRejected, "vault-policy-v1 dest unavailable")
	}
	destScript, destAddr, err := s.decodeVtxoDest(req.DestAddress)
	if err != nil {
		return nil, err
	}
	_ = destAddr
	if err := verifyVtxoReservePhoneSignature(req, vaultID, destScript, snap.PhoneBIP340); err != nil {
		return nil, err
	}
	if err := s.refuseDefaultVtxoChange(snap, destScript); err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	feeCap, err := vtxoFeeCap(rec)
	if err != nil {
		return nil, err
	}
	if err := enforceVtxoAmount(req.AmountSats, 0, rec); err != nil {
		return nil, err
	}
	if existing, err := s.Stores.VtxoOperations.GetVtxoOperation(ctx, opID); err == nil {
		return s.replayVtxoReservation(ctx, existing, vaultID, purpose, req.AmountSats, destScript, tree)
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	feePolicy, err := s.ArkResolver.IntentFeePolicy(ctx)
	if err != nil {
		return nil, apperr.New(apperr.CodeRejected, "Operator fee policy unavailable")
	}
	estimator, feePolicyDigest, err := newVtxoFeeEstimator(feePolicy)
	if err != nil {
		return nil, err
	}
	selected, feeSats, changeSats, err := s.selectSpendVtxos(ctx, tree.PkScript, destScript, req.AmountSats, feeCap, estimator)
	if err != nil {
		return nil, err
	}
	if err := enforceVtxoAmount(req.AmountSats, feeSats, rec); err != nil {
		return nil, err
	}
	checkpoint := s.ArkResolver.CheckpointTapscript()
	if len(checkpoint) == 0 {
		return nil, apperr.New(apperr.CodeRejected, "checkpoint tapscript required")
	}
	var changeScript []byte
	var changeVout *uint32
	if changeSats > 0 {
		changeScript = bytes.Clone(tree.PkScript)
		vout := uint32(1)
		changeVout = &vout
	}
	inputs := make([]policy.VtxoBundleInput, len(selected))
	opInputs := make([]policy.VtxoOperationInput, len(selected))
	for i, coin := range selected {
		inputs[i] = policy.VtxoBundleInput{Txid: bytes.Clone(coin.Txid), Vout: coin.Vout, ValueSats: coin.ValueSats}
		opInputs[i] = policy.VtxoOperationInput{
			Txid: bytes.Clone(coin.Txid), Vout: int(coin.Vout), ValueSats: int64(coin.ValueSats), Script: bytes.Clone(coin.Script),
		}
	}
	now := s.vtxoNow()
	created := now.Format(time.RFC3339)
	expires := now.Add(vtxoReserveAuthorizeTimeout).Format(time.RFC3339)
	digest, err := policy.ComputeVtxoBundleDigest(
		purpose, vaultID, destScript, changeScript, req.AmountSats, feeSats,
		changeSats, changeVout, feePolicyDigest, inputs, created,
	)
	if err != nil {
		return nil, err
	}
	recRow := policy.VtxoOperation{
		OperationID:         opID,
		VaultID:             vaultID,
		Purpose:             purpose,
		BundleDigest:        digest,
		State:               policy.VtxoStateReserved,
		AmountSats:          int64(req.AmountSats),
		FeeSats:             int64(feeSats),
		FeePolicyDigest:     feePolicyDigest,
		DestScript:          destScript,
		ChangeScript:        changeScript,
		ChangeSats:          int64(changeSats),
		ChangeVout:          changeVout,
		CheckpointTapscript: checkpoint,
		ExpiresAt:           expires,
		CreatedAt:           created,
		LastDestScript:      destScript,
	}
	allowance := periodAllowanceSats(rec, nil)
	if err := s.Stores.Allowance.ReserveVtxoOperation(ctx, recRow, opInputs, allowance); err != nil {
		// Two exact retries can both observe a missing row before SQLite
		// serializes their inserts. Re-read by the caller's durable identifier;
		// only the exact original request may recover the winning reservation.
		if existing, loadErr := s.Stores.VtxoOperations.GetVtxoOperation(ctx, opID); loadErr == nil {
			return s.replayVtxoReservation(ctx, existing, vaultID, purpose, req.AmountSats, destScript, tree)
		}
		return nil, mapLedgerBusy(err)
	}
	return vtxoReserveResponse(recRow, opInputs, tree.ArkAddress), nil
}

func verifyVtxoReservePhoneSignature(req VtxoReserveRequest, vaultID string, destScript []byte, phone *btcec.PublicKey) error {
	if phone == nil {
		return apperr.New(apperr.CodeRejected, "enrolled phone key required")
	}
	digest, err := policy.ComputeVtxoReserveDigest(req.OperationID, vaultID, strings.TrimSpace(req.Purpose), destScript, req.AmountSats)
	if err != nil {
		return apperr.New(apperr.CodeRejected, err.Error())
	}
	raw, err := hex.DecodeString(req.PhoneSignature)
	if err != nil || len(raw) != schnorr.SignatureSize || req.PhoneSignature != strings.ToLower(req.PhoneSignature) {
		return apperr.New(apperr.CodeRejected, "phoneSignature must be a lowercase 64-byte Schnorr signature")
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil || !sig.Verify(digest, phone) {
		return apperr.New(apperr.CodeRejected, "phoneSignature invalid")
	}
	return nil
}

func canonicalVtxoOperationID(raw string) (string, error) {
	id := strings.TrimSpace(raw)
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 || id != strings.ToLower(id) {
		return "", apperr.New(apperr.CodeRejected, "operationId must be 16 random bytes encoded as lowercase hex")
	}
	return id, nil
}

func (s *Service) replayVtxoReservation(
	ctx context.Context,
	op policy.VtxoOperation,
	vaultID, purpose string,
	amount uint64,
	destScript []byte,
	tree *vtxoPolicyTree,
) (*VtxoReserveResponse, error) {
	if op.VaultID != vaultID || op.Purpose != purpose || op.AmountSats < 0 || op.FeeSats < 0 || op.ChangeSats < 0 ||
		uint64(op.AmountSats) != amount || !bytes.Equal(op.DestScript, destScript) ||
		len(op.FeePolicyDigest) != 32 || !validStoredVtxoChange(op, tree.PkScript) {
		return nil, apperr.New(apperr.CodeRejected, "operationId is already bound to a different reserve request")
	}
	if op.State == policy.VtxoStateAborted || op.State == policy.VtxoStateUnresolved {
		return nil, apperr.New(apperr.CodeRejected, "reservation is no longer usable")
	}
	op, err := s.expireReservedVtxo(ctx, op)
	if err != nil {
		return nil, err
	}
	if op.State == policy.VtxoStateAborted {
		return nil, apperr.New(apperr.CodeRejected, "reservation expired")
	}
	inputs, err := s.Stores.VtxoOperations.GetVtxoOperationInputs(ctx, op.OperationID)
	if err != nil {
		return nil, err
	}
	return vtxoReserveResponse(op, inputs, tree.ArkAddress), nil
}

func vtxoReserveResponse(op policy.VtxoOperation, inputs []policy.VtxoOperationInput, changeAddress string) *VtxoReserveResponse {
	views := make([]VtxoInputView, len(inputs))
	for i, in := range inputs {
		views[i] = VtxoInputView{
			Txid: hex.EncodeToString(in.Txid), Vout: uint32(in.Vout), ValueSats: uint64(in.ValueSats), ScriptHex: hex.EncodeToString(in.Script),
		}
	}
	if op.ChangeSats == 0 {
		changeAddress = ""
	}
	return &VtxoReserveResponse{
		OperationID:         op.OperationID,
		BundleDigest:        hex.EncodeToString(op.BundleDigest),
		ReservationExpires:  op.ExpiresAt,
		Inputs:              views,
		ChangeAddress:       changeAddress,
		ChangeScript:        hex.EncodeToString(op.ChangeScript),
		DestScript:          hex.EncodeToString(op.DestScript),
		FeeSats:             uint64(op.FeeSats),
		FeePolicyDigest:     hex.EncodeToString(op.FeePolicyDigest),
		ChangeSats:          uint64(op.ChangeSats),
		ChangeVout:          cloneVout(op.ChangeVout),
		CheckpointTapscript: hex.EncodeToString(op.CheckpointTapscript),
	}
}

type reservedCoin struct {
	Txid      []byte
	Vout      uint32
	ValueSats uint64
	Script    []byte
	FeeInput  arkfee.OffchainInput
	Effective uint64
}

func (s *Service) selectSpendVtxos(ctx context.Context, pkScript, destScript []byte, amountSats, feeCap uint64, estimator *arkfee.Estimator) ([]reservedCoin, uint64, uint64, error) {
	vtxos, err := s.ArkResolver.SpendableVtxos(ctx, pkScript)
	if err != nil {
		return nil, 0, 0, apperr.New(apperr.CodeRejected, "ark indexer")
	}
	releaseFeeSelection, err := s.acquireFeeSelection(ctx)
	if err != nil {
		return nil, 0, 0, err
	}
	defer releaseFeeSelection()
	budget := feeEvaluationBudget{remaining: maxVtxoFeeProgramEvaluations}
	coins, err := vtxosToCoins(vtxos, pkScript, estimator, &budget)
	if err != nil {
		return nil, 0, 0, err
	}
	listed := make([]policy.VtxoBundleInput, len(coins))
	for i, coin := range coins {
		listed[i] = policy.VtxoBundleInput{Txid: coin.Txid, Vout: coin.Vout, ValueSats: coin.ValueSats}
	}
	if _, err := policy.CanonicalVtxoBundleInputs(listed); err != nil {
		return nil, 0, 0, apperr.New(apperr.CodeRejected, err.Error())
	}
	sort.Slice(coins, func(i, j int) bool {
		if coins[i].Effective != coins[j].Effective {
			return coins[i].Effective > coins[j].Effective
		}
		if cmp := bytes.Compare(coins[i].Txid, coins[j].Txid); cmp != 0 {
			return cmp < 0
		}
		return coins[i].Vout < coins[j].Vout
	})
	limit := len(coins)
	if limit > maxVtxoSpendInputs {
		limit = maxVtxoSpendInputs
	}
	for count := 1; count <= limit; count++ {
		fee, change, ok, solveErr := solveVtxoSpendWithBudget(ctx, coins[:count], destScript, pkScript, amountSats, feeCap, estimator, &budget)
		if solveErr != nil {
			return nil, 0, 0, solveErr
		}
		if !ok {
			continue
		}
		picked := append([]reservedCoin(nil), coins[:count]...)
		sort.Slice(picked, func(i, j int) bool {
			if cmp := bytes.Compare(picked[i].Txid, picked[j].Txid); cmp != 0 {
				return cmp < 0
			}
			return picked[i].Vout < picked[j].Vout
		})
		return picked, fee, change, nil
	}
	return nil, 0, 0, apperr.New(apperr.CodeRejected, "insufficient economic vtxo funds")
}

const maxVtxoSpendInputs = policy.MaxVtxoOperationInputs

func vtxosToCoins(vtxos []ports.ResolvedVtxo, pkScript []byte, estimator *arkfee.Estimator, budget *feeEvaluationBudget) ([]reservedCoin, error) {
	out := make([]reservedCoin, 0, len(vtxos))
	for _, v := range vtxos {
		raw, err := hex.DecodeString(v.Txid)
		if err != nil || len(raw) != 32 || v.Txid != strings.ToLower(v.Txid) || !bytes.Equal(v.Script, pkScript) || v.ValueSats > math.MaxInt64 {
			return nil, apperr.New(apperr.CodeRejected, "invalid indexed vtxo")
		}
		feeInput := resolvedArkFeeInput(v)
		if err := budget.consume(); err != nil {
			return nil, err
		}
		inputFee, err := estimator.EvalOffchainInput(feeInput)
		if err != nil {
			return nil, apperr.New(apperr.CodeRejected, "Operator input fee evaluation")
		}
		feeSats, err := exactFeeSats(inputFee)
		if err != nil {
			return nil, err
		}
		if feeSats >= v.ValueSats {
			continue
		}
		out = append(out, reservedCoin{
			Txid: raw, Vout: v.Vout, ValueSats: v.ValueSats, Script: bytes.Clone(pkScript),
			FeeInput: feeInput, Effective: v.ValueSats - feeSats,
		})
	}
	return out, nil
}

func newVtxoFeeEstimator(fee ports.IntentFeePolicy) (*arkfee.Estimator, []byte, error) {
	// Hash the exact Operator strings below. Normalization exists only because
	// an explicitly empty program is the protocol's zero-fee program, while the
	// estimator API otherwise treats absence as an implementation detail.
	estimator, err := arkfee.New(intentFeeEstimatorConfig(fee))
	if err != nil {
		return nil, nil, apperr.New(apperr.CodeRejected, "Operator fee policy invalid")
	}
	digest := policy.ComputeIntentFeePolicyDigest(fee.OffchainInput, fee.OffchainOutput, fee.OnchainInput, fee.OnchainOutput)
	return estimator, digest, nil
}

func intentFeeEstimatorConfig(fee ports.IntentFeePolicy) arkfee.Config {
	normalize := func(program string) string {
		if program == "" {
			return "0.0"
		}
		return program
	}
	return arkfee.Config{
		IntentOffchainInputProgram:  normalize(fee.OffchainInput),
		IntentOffchainOutputProgram: normalize(fee.OffchainOutput),
		IntentOnchainInputProgram:   normalize(fee.OnchainInput),
		IntentOnchainOutputProgram:  normalize(fee.OnchainOutput),
	}
}

func resolvedArkFeeInput(v ports.ResolvedVtxo) arkfee.OffchainInput {
	kind := arkfee.VtxoTypeVtxo
	if v.IsSwept {
		kind = arkfee.VtxoTypeRecoverable
	} else if len(v.CommitmentTxids) == 0 {
		kind = arkfee.VtxoTypeNote
	}
	input := arkfee.OffchainInput{
		Amount: v.ValueSats, Birth: time.Unix(v.CreatedAt, 0), Type: kind, Weight: 0,
	}
	if v.ExpiresAt != nil {
		input.Expiry = time.Unix(*v.ExpiresAt, 0)
	}
	return input
}

func exactFeeSats(fee arkfee.FeeAmount) (uint64, error) {
	value := float64(fee)
	rounded := math.Ceil(value)
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || rounded >= float64(uint64(1)<<63) {
		return 0, apperr.New(apperr.CodeRejected, "Operator fee result invalid")
	}
	return uint64(rounded), nil
}

func solveVtxoSpend(ctx context.Context, coins []reservedCoin, destScript, changeScript []byte, amount, feeCap uint64, estimator *arkfee.Estimator) (fee, change uint64, ok bool, err error) {
	budget := feeEvaluationBudget{remaining: maxVtxoFeeProgramEvaluations}
	return solveVtxoSpendWithBudget(ctx, coins, destScript, changeScript, amount, feeCap, estimator, &budget)
}

const maxVtxoFeeProgramEvaluations = 20_000

type feeEvaluationBudget struct {
	remaining int
}

func (b *feeEvaluationBudget) consume() error {
	if b == nil || b.remaining == 0 {
		return apperr.New(apperr.CodeBusy, "Operator fee policy exceeds evaluation limit")
	}
	b.remaining--
	return nil
}

func solveVtxoSpendWithBudget(ctx context.Context, coins []reservedCoin, destScript, changeScript []byte, amount, feeCap uint64, estimator *arkfee.Estimator, budget *feeEvaluationBudget) (fee, change uint64, ok bool, err error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, false, apperr.New(apperr.CodeBusy, "fee selection cancelled")
	}
	var total uint64
	feeInputs := make([]arkfee.OffchainInput, len(coins))
	for i, coin := range coins {
		if coin.ValueSats > math.MaxUint64-total {
			return 0, 0, false, apperr.New(apperr.CodeRejected, "vtxo input amount overflow")
		}
		total += coin.ValueSats
		feeInputs[i] = coin.FeeInput
	}
	if total < amount {
		return 0, 0, false, nil
	}
	dest := arkfee.Output{Amount: amount, Script: hex.EncodeToString(destScript)}
	if err := budget.consume(); err != nil {
		return 0, 0, false, err
	}
	withoutChange, evalErr := estimator.Eval(feeInputs, nil, []arkfee.Output{dest}, nil)
	if evalErr != nil {
		return 0, 0, false, apperr.New(apperr.CodeRejected, "Operator fee evaluation")
	}
	noChangeFee, evalErr := exactFeeSats(withoutChange)
	if evalErr != nil {
		return 0, 0, false, evalErr
	}
	if noChangeFee <= feeCap && total-amount == noChangeFee {
		return noChangeFee, 0, true, nil
	}
	maxCandidate := feeCap
	if available := total - amount; maxCandidate > available {
		maxCandidate = available
	}
	for candidate := uint64(0); candidate <= maxCandidate; candidate++ {
		if err := ctx.Err(); err != nil {
			return 0, 0, false, apperr.New(apperr.CodeBusy, "fee selection cancelled")
		}
		candidateChange := total - amount - candidate
		if candidateChange < uint64(program.DustSats) {
			continue
		}
		if err := budget.consume(); err != nil {
			return 0, 0, false, err
		}
		withChange, evalErr := estimator.Eval(feeInputs, nil, []arkfee.Output{
			dest,
			{Amount: candidateChange, Script: hex.EncodeToString(changeScript)},
		}, nil)
		if evalErr != nil {
			return 0, 0, false, apperr.New(apperr.CodeRejected, "Operator fee evaluation")
		}
		actual, evalErr := exactFeeSats(withChange)
		if evalErr != nil {
			return 0, 0, false, evalErr
		}
		if actual == candidate {
			return candidate, candidateChange, true, nil
		}
		if candidate == math.MaxUint64 {
			break
		}
	}
	return 0, 0, false, nil
}

func validStoredVtxoChange(op policy.VtxoOperation, wantScript []byte) bool {
	if op.ChangeSats == 0 {
		return op.ChangeVout == nil && len(op.ChangeScript) == 0
	}
	return op.ChangeSats >= program.DustSats && op.ChangeVout != nil && *op.ChangeVout == 1 && bytes.Equal(op.ChangeScript, wantScript)
}

func cloneVout(vout *uint32) *uint32 {
	if vout == nil {
		return nil
	}
	copy := *vout
	return &copy
}

func vtxoFeeCap(rec *policy.VaultRecord) (uint64, error) {
	capSats := program.AbsoluteFeeCeiling
	if rec != nil {
		capSats = rec.AbsoluteFeeCapSats
	}
	if capSats < 0 {
		return 0, apperr.New(apperr.CodeRejected, "fee ceiling invalid")
	}
	return uint64(capSats), nil
}

func (s *Service) requireCurrentVtxoFeePolicy(ctx context.Context, op policy.VtxoOperation) error {
	fee, err := s.ArkResolver.IntentFeePolicy(ctx)
	if err != nil {
		return apperr.New(apperr.CodeRejected, "Operator fee policy unavailable")
	}
	_, digest, err := newVtxoFeeEstimator(fee)
	if err != nil {
		return err
	}
	if len(op.FeePolicyDigest) != 32 || !bytes.Equal(digest, op.FeePolicyDigest) {
		return apperr.New(apperr.CodeRejected, "Operator fee policy changed after reservation")
	}
	return nil
}

func enforceVtxoAmount(amount, fee uint64, rec *policy.VaultRecord) error {
	capSats := program.TxRecipientCapSats
	feeCap := program.AbsoluteFeeCeiling
	if rec != nil {
		if rec.TxRecipientCapSats > 0 {
			capSats = rec.TxRecipientCapSats
		}
		if rec.AbsoluteFeeCapSats >= 0 {
			feeCap = rec.AbsoluteFeeCapSats
		}
	}
	if amount > math.MaxInt64 || capSats < 0 || amount > uint64(capSats) {
		return apperr.New(apperr.CodeRejected, "recipient exceeds transaction cap")
	}
	if fee > math.MaxInt64 || feeCap < 0 || fee > uint64(feeCap) {
		return apperr.New(apperr.CodeRejected, "fee exceeds ceiling")
	}
	if amount < uint64(program.DustSats) {
		return apperr.New(apperr.CodeRejected, "recipient below dust")
	}
	return nil
}

func (s *Service) decodeVtxoDest(addr string) ([]byte, string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, "", apperr.New(apperr.CodeRejected, "destAddress required")
	}
	if decoded, err := arklib.DecodeAddressV0(addr); err == nil {
		if decoded.HRP != arklib.BitcoinTestNet.Addr {
			return nil, "", apperr.New(apperr.CodeRejected, "destAddress network")
		}
		operator, err := btcec.ParsePubKey(s.operatorSignerPub())
		if err != nil || decoded.Signer == nil ||
			!bytes.Equal(schnorr.SerializePubKey(decoded.Signer), schnorr.SerializePubKey(operator)) {
			return nil, "", apperr.New(apperr.CodeRejected, "destAddress Operator")
		}
		script, err := decoded.GetPkScript()
		if err != nil {
			return nil, "", apperr.New(apperr.CodeRejected, "destAddress")
		}
		return script, addr, nil
	}
	return nil, "", apperr.New(apperr.CodeRejected, "destAddress must be a pinned-Operator Arkade address")
}

func (s *Service) loadLiveVtxo(ctx context.Context, vaultID, operationID, wantPurpose string) (policy.VtxoOperation, []policy.VtxoOperationInput, error) {
	if operationID == "" {
		return policy.VtxoOperation{}, nil, apperr.New(apperr.CodeRejected, "operationId required")
	}
	rec, err := s.Stores.VtxoOperations.GetVtxoOperation(ctx, operationID)
	if err == sql.ErrNoRows {
		return policy.VtxoOperation{}, nil, apperr.ErrNotFound
	}
	if err != nil {
		return policy.VtxoOperation{}, nil, err
	}
	if rec.VaultID != vaultID {
		return policy.VtxoOperation{}, nil, apperr.New(apperr.CodeRejected, "operation does not belong to this vault")
	}
	if rec.Purpose != wantPurpose {
		return policy.VtxoOperation{}, nil, apperr.New(apperr.CodeRejected, "vtxo purpose")
	}
	if rec.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err != nil {
			return policy.VtxoOperation{}, nil, apperr.New(apperr.CodeRejected, "reservation expiry")
		}
		if rec.State == policy.VtxoStateReserved && !s.vtxoNow().Before(exp) {
			next := rec
			next.State = policy.VtxoStateAborted
			_, _, _ = s.Stores.VtxoOperations.TransitionVtxoOperation(ctx, policy.VtxoStateReserved, next)
			return policy.VtxoOperation{}, nil, apperr.New(apperr.CodeRejected, "reservation expired")
		}
	}
	inputs, err := s.Stores.VtxoOperations.GetVtxoOperationInputs(ctx, operationID)
	if err != nil {
		return policy.VtxoOperation{}, nil, err
	}
	return rec, inputs, nil
}

func requireBundleDigest(got string, want []byte) error {
	raw, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(got)))
	if err != nil || len(raw) != 32 {
		return apperr.New(apperr.CodeRejected, "bundleDigest")
	}
	if !bytes.Equal(raw, want) {
		return apperr.New(apperr.CodeRejected, "bundleDigest mismatch")
	}
	return nil
}

func vtxoCheckpointAuthorizableState(state string) bool {
	return state == policy.VtxoStateSigned || state == policy.VtxoStateSubmitted
}

func vtxoFinalizableState(state string) bool {
	return state == policy.VtxoStateSubmitted
}

// VtxoOperationView is the idempotent status of one spend. No client mutation.
// Signed and submitted rows include the PSBT material needed to resume a lost
// authorize or checkpoint-authorize response.
type VtxoOperationView struct {
	OperationID            string   `json:"operationId"`
	BundleDigest           string   `json:"bundleDigest"`
	State                  string   `json:"state"`
	ArkTxid                string   `json:"arkTxid,omitempty"`
	ExpiresAt              string   `json:"expiresAt,omitempty"`
	FeeSats                uint64   `json:"feeSats"`
	FeePolicyDigest        string   `json:"feePolicyDigest"`
	ChangeSats             uint64   `json:"changeSats"`
	ChangeVout             *uint32  `json:"changeVout,omitempty"`
	ChangeScript           string   `json:"changeScript"`
	AuthorizedPsbt         string   `json:"authorizedPsbt,omitempty"`
	AuthorizedPendingProof string   `json:"authorizedPendingProof,omitempty"`
	CheckpointPsbts        []string `json:"checkpointPsbts,omitempty"`
}

func (s *Service) expireReservedVtxo(ctx context.Context, op policy.VtxoOperation) (policy.VtxoOperation, error) {
	if op.State != policy.VtxoStateReserved || op.ExpiresAt == "" {
		return op, nil
	}
	exp, err := time.Parse(time.RFC3339, op.ExpiresAt)
	if err != nil {
		return op, apperr.New(apperr.CodeRejected, "reservation expiry")
	}
	if s.vtxoNow().Before(exp) {
		return op, nil
	}
	next := op
	next.State = policy.VtxoStateAborted
	current, swapped, err := s.Stores.VtxoOperations.TransitionVtxoOperation(ctx, policy.VtxoStateReserved, next)
	if err != nil {
		return op, err
	}
	if swapped {
		return next, nil
	}
	return current, nil
}

func (s *Service) GetVtxoOperationView(ctx context.Context, vaultID, operationID string) (*VtxoOperationView, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	id, _, _, err := s.resolveSpendVaultRecord(vaultID)
	if err != nil {
		return nil, err
	}
	op, err := s.Stores.VtxoOperations.GetVtxoOperation(ctx, operationID)
	if err == sql.ErrNoRows {
		return nil, apperr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if op.VaultID != id {
		return nil, apperr.New(apperr.CodeRejected, "operation does not belong to this vault")
	}
	// Reconcile only the operation the client asked about. Scanning every
	// historical operation made one status read trigger unbounded remote work.
	if op.State == policy.VtxoStateSigned || op.State == policy.VtxoStateSubmitted {
		if err := s.promoteSubmittedVtxo(ctx, op); err == nil {
			if current, loadErr := s.Stores.VtxoOperations.GetVtxoOperation(ctx, operationID); loadErr == nil {
				op = current
			}
		}
	}
	op, err = s.expireReservedVtxo(ctx, op)
	if err != nil {
		return nil, err
	}
	view := &VtxoOperationView{
		OperationID: op.OperationID, BundleDigest: hex.EncodeToString(op.BundleDigest),
		State: op.State, ArkTxid: op.ArkTxid, ExpiresAt: op.ExpiresAt,
		FeeSats: uint64(op.FeeSats), FeePolicyDigest: hex.EncodeToString(op.FeePolicyDigest),
		ChangeSats: uint64(op.ChangeSats), ChangeVout: cloneVout(op.ChangeVout),
		ChangeScript: hex.EncodeToString(op.ChangeScript),
	}
	switch op.State {
	case policy.VtxoStateSigned:
		view.AuthorizedPsbt = op.AuthorizedPSBT
		view.AuthorizedPendingProof = op.AuthorizedPendingProof
	case policy.VtxoStateSubmitted:
		view.AuthorizedPsbt = op.AuthorizedPSBT
		view.AuthorizedPendingProof = op.AuthorizedPendingProof
		view.CheckpointPsbts = decodeJSONStringSlice(op.CheckpointPSBTs)
	}
	return view, nil
}

func (s *Service) promoteSubmittedVtxo(ctx context.Context, op policy.VtxoOperation) error {
	if op.State != policy.VtxoStateSigned && op.State != policy.VtxoStateSubmitted {
		return nil
	}
	inputs, err := s.Stores.VtxoOperations.GetVtxoOperationInputs(ctx, op.OperationID)
	if err != nil {
		return err
	}
	reserved := make([]ports.ResolvedVtxo, 0, len(inputs))
	for _, in := range inputs {
		reserved = append(reserved, ports.ResolvedVtxo{
			Txid: hex.EncodeToString(in.Txid), Vout: uint32(in.Vout), ValueSats: uint64(in.ValueSats), Script: bytes.Clone(in.Script),
		})
	}
	if len(inputs) == 0 {
		return fmt.Errorf("reserved inputs required")
	}
	pkScript := inputs[0].Script
	if op.ChangeSats > 0 && op.ChangeVout == nil {
		return fmt.Errorf("change vout missing")
	}
	if op.ChangeSats > 0 && !bytes.Equal(op.ChangeScript, pkScript) {
		return fmt.Errorf("change script does not match reserved inputs")
	}
	state, err := s.ArkResolver.SubmittedVtxoState(ctx, pkScript, reserved, op.ArkTxid, op.ChangeVout, uint64(op.ChangeSats))
	if err != nil {
		return err
	}
	if state == ports.SubmittedVtxoPending {
		return nil
	}
	if op.State == policy.VtxoStateSigned {
		submitted := op
		submitted.State = policy.VtxoStateSubmitted
		current, swapped, transitionErr := s.Stores.VtxoOperations.TransitionVtxoOperation(ctx, policy.VtxoStateSigned, submitted)
		if transitionErr != nil {
			return transitionErr
		}
		if !swapped {
			if current.State == policy.VtxoStateFinalized || current.State == policy.VtxoStateUnresolved {
				return nil
			}
			if current.State != policy.VtxoStateSubmitted {
				return apperr.New(apperr.CodeRejected, "vtxo operation changed concurrently")
			}
			op = current
		} else {
			op = submitted
		}
	}
	if state == ports.SubmittedVtxoConflict {
		next := op
		next.State = policy.VtxoStateUnresolved
		next.CreatedAt = s.vtxoNow().Format(time.RFC3339)
		current, swapped, transitionErr := s.Stores.VtxoOperations.TransitionVtxoOperation(ctx, policy.VtxoStateSubmitted, next)
		if transitionErr != nil {
			return transitionErr
		}
		if !swapped && current.State != policy.VtxoStateUnresolved {
			return apperr.New(apperr.CodeRejected, "vtxo operation changed concurrently")
		}
		return nil
	}
	if state != ports.SubmittedVtxoFinalized {
		return fmt.Errorf("unknown submitted vtxo state")
	}
	next := op
	next.State = policy.VtxoStateFinalized
	next.CreatedAt = s.vtxoNow().Format(time.RFC3339)
	current, swapped, err := s.Stores.VtxoOperations.TransitionVtxoOperation(ctx, policy.VtxoStateSubmitted, next)
	if err != nil {
		return err
	}
	if !swapped && current.State != policy.VtxoStateFinalized {
		return apperr.New(apperr.CodeRejected, "vtxo operation changed concurrently")
	}
	return nil
}

func (s *Service) AuthorizeVtxoSpend(ctx context.Context, req VtxoAuthorizeRequest) (*VtxoAuthorizeResponse, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	if err := s.requireVaultPolicyV1Exit(); err != nil {
		return nil, err
	}
	if err := s.requireArkResolver(); err != nil {
		return nil, err
	}
	vaultID, snap, _, err := s.resolveSpendVaultRecord(req.VaultID)
	if err != nil {
		return nil, err
	}
	op, inputs, err := s.loadLiveVtxo(ctx, vaultID, req.OperationID, policy.VtxoPurposeSpend)
	if err != nil {
		return nil, err
	}
	if op.State != policy.VtxoStateReserved && op.State != policy.VtxoStateSigned {
		return nil, apperr.New(apperr.CodeRejected, "vtxo operation state")
	}
	if err := s.requireCurrentVtxoFeePolicy(ctx, op); err != nil {
		return nil, err
	}
	if err := requireBundleDigest(req.BundleDigest, op.BundleDigest); err != nil {
		return nil, err
	}
	tree, err := s.buildVtxoPolicyTree(vaultID, snap)
	if err != nil {
		return nil, apperr.New(apperr.CodeRejected, "vault-policy-v1 spend unavailable")
	}
	arkPkt, err := parsePSBT(req.UnsignedArkPsbt)
	if err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	if len(req.UnsignedCheckpointPsbts) != len(inputs) {
		return nil, apperr.New(apperr.CodeRejected, "checkpoint count")
	}
	checkpoints := make([]*psbt.Packet, len(req.UnsignedCheckpointPsbts))
	for i, raw := range req.UnsignedCheckpointPsbts {
		cp, err := parsePSBT(raw)
		if err != nil {
			return nil, apperr.New(apperr.CodeRejected, "checkpoint psbt")
		}
		if err := verifyUnsignedCheckpointPSBT(cp, inputs[i], op, tree); err != nil {
			return nil, apperr.New(apperr.CodeRejected, err.Error())
		}
		checkpoints[i] = cp
	}
	if err := verifySpendPSBT(arkPkt, op, inputs, tree, checkpoints); err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	if err := verifyPhonePendingProof(req.PendingProof, inputs, tree, snap.PhoneBIP340); err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	pendingDigest, err := pendingProofDigest(req.PendingProof)
	if err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	signedReplay := op.State == policy.VtxoStateSigned
	if signedReplay && (op.UnsignedPSBT != req.UnsignedArkPsbt ||
		op.CheckpointPSBTs != encodeJSONStringSlice(req.UnsignedCheckpointPsbts) ||
		!bytes.Equal(op.PendingProofDigest, pendingDigest) || op.AuthorizedPendingProof == "") {
		return nil, apperr.New(apperr.CodeRejected, "changed psbt")
	}
	credentialID, signCount, err := s.verifyVtxoAuthorization(ctx, vaultID, op.BundleDigest, WebAuthnAssertionRequest{
		CredentialID: req.CredentialID, ClientDataJSON: req.ClientDataJSON,
		AuthenticatorData: req.AuthenticatorData, Signature: req.Signature,
	}, req.DirectSig)
	if err != nil {
		return nil, err
	}
	if signedReplay {
		if err := s.Stores.VtxoOperations.VerifySignedVtxoReplay(ctx, op.OperationID, vaultID, credentialID, signCount); err != nil {
			return nil, err
		}
		return &VtxoAuthorizeResponse{
			OperationID:            op.OperationID,
			BundleDigest:           hex.EncodeToString(op.BundleDigest),
			AuthorizedPsbt:         op.AuthorizedPSBT,
			AuthorizedPendingProof: op.AuthorizedPendingProof,
			ArkTxid:                op.ArkTxid,
		}, nil
	}
	arkTxid := arkPkt.UnsignedTx.TxHash().String()
	op.UnsignedPSBT = req.UnsignedArkPsbt
	op.PendingProofDigest = bytes.Clone(pendingDigest)
	op.CheckpointPSBTs = encodeJSONStringSlice(req.UnsignedCheckpointPsbts)
	op.ArkTxid = arkTxid
	keyContext, err := s.vtxoKeyContext(vaultID)
	if err != nil {
		return nil, err
	}
	expected := schnorr.SerializePubKey(tree.CosignerPub)
	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	signCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	authorization, err := newVtxoTransactionAuthorization(
		keyContext, req.UnsignedArkPsbt, req.PendingProof, tree.SpendLeaf, expected,
	)
	if err != nil {
		return nil, err
	}
	signedArk, authorizedPendingProof, err := s.keys.vtxoTransactionAuthorization(signCtx, authorization)
	if err != nil {
		return nil, err
	}
	if err := requireOnlyVaultSignatureAdded(req.PendingProof, authorizedPendingProof, expected); err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	if err := verifyDualSignedPendingProof(authorizedPendingProof, inputs, tree, snap.PhoneBIP340); err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	op.AuthorizedPSBT = signedArk
	op.AuthorizedPendingProof = authorizedPendingProof
	// Persist the exact unsigned stage. The Operator reconstructs checkpoints
	// during submit, so signing these now would only create signatures that are
	// discarded before finalization.
	op.CheckpointPSBTs = encodeJSONStringSlice(req.UnsignedCheckpointPsbts)
	op.State = policy.VtxoStateSigned
	current, swapped, err := s.Stores.VtxoOperations.CommitSignedVtxoOperation(ctx, op, credentialID, signCount)
	if err != nil {
		return nil, err
	}
	if !swapped {
		if current.State != policy.VtxoStateSigned || current.UnsignedPSBT != req.UnsignedArkPsbt ||
			current.CheckpointPSBTs != encodeJSONStringSlice(req.UnsignedCheckpointPsbts) ||
			!bytes.Equal(current.PendingProofDigest, pendingDigest) || current.AuthorizedPendingProof == "" {
			return nil, apperr.New(apperr.CodeRejected, "vtxo operation changed concurrently")
		}
		op = current
		signedArk = current.AuthorizedPSBT
		authorizedPendingProof = current.AuthorizedPendingProof
		arkTxid = current.ArkTxid
	}
	return &VtxoAuthorizeResponse{
		OperationID:            op.OperationID,
		BundleDigest:           hex.EncodeToString(op.BundleDigest),
		AuthorizedPsbt:         signedArk,
		AuthorizedPendingProof: authorizedPendingProof,
		ArkTxid:                arkTxid,
	}, nil
}

func (s *Service) AuthorizeVtxoCheckpoints(ctx context.Context, req VtxoCheckpointAuthorizeRequest) (*VtxoCheckpointAuthorizeResponse, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	if err := s.requireVaultPolicyV1Exit(); err != nil {
		return nil, err
	}
	if err := s.requireArkResolver(); err != nil {
		return nil, err
	}
	vaultID, snap, _, err := s.resolveSpendVaultRecord(req.VaultID)
	if err != nil {
		return nil, err
	}
	op, inputs, err := s.loadLiveVtxo(ctx, vaultID, req.OperationID, policy.VtxoPurposeSpend)
	if err != nil {
		return nil, err
	}
	if !vtxoCheckpointAuthorizableState(op.State) {
		return nil, apperr.New(apperr.CodeRejected, "vtxo operation state")
	}
	if err := s.requireCurrentVtxoFeePolicy(ctx, op); err != nil {
		return nil, err
	}
	if err := requireBundleDigest(req.BundleDigest, op.BundleDigest); err != nil {
		return nil, err
	}
	if len(req.CheckpointPsbts) != len(inputs) {
		return nil, apperr.New(apperr.CodeRejected, "checkpoint count")
	}
	tree, err := s.buildVtxoPolicyTree(vaultID, snap)
	if err != nil {
		return nil, apperr.New(apperr.CodeRejected, "vault-policy-v1 spend unavailable")
	}
	storedRaw := decodeJSONStringSlice(op.CheckpointPSBTs)
	if len(storedRaw) != len(req.CheckpointPsbts) {
		return nil, apperr.New(apperr.CodeRejected, "stored checkpoint count")
	}
	for i, raw := range req.CheckpointPsbts {
		candidate, err := parsePSBT(raw)
		if err != nil {
			return nil, apperr.New(apperr.CodeRejected, "checkpoint psbt")
		}
		stored, err := parsePSBT(storedRaw[i])
		if err != nil || !sameUnsignedPSBT(stored, candidate) {
			return nil, apperr.New(apperr.CodeRejected, "changed checkpoint")
		}
		if err := verifySubmittedCheckpointPSBT(candidate, inputs[i], op, tree); err != nil {
			return nil, apperr.New(apperr.CodeRejected, err.Error())
		}
	}
	requestBinding := encodeJSONStringSlice(req.CheckpointPsbts)
	digestHex := hex.EncodeToString(op.BundleDigest)
	if op.State == policy.VtxoStateSubmitted {
		if op.CheckpointRequestPSBTs != requestBinding {
			return nil, apperr.New(apperr.CodeRejected, "changed checkpoint")
		}
		return &VtxoCheckpointAuthorizeResponse{
			OperationID: op.OperationID, BundleDigest: digestHex,
			CheckpointPsbts: storedRaw, ArkTxid: op.ArkTxid,
		}, nil
	}
	keyContext, err := s.vtxoKeyContext(vaultID)
	if err != nil {
		return nil, err
	}
	expected := schnorr.SerializePubKey(tree.CosignerPub)
	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	signCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	authorization, err := newVtxoCheckpointAuthorization(keyContext, req.CheckpointPsbts, tree.SpendLeaf, expected)
	if err != nil {
		return nil, err
	}
	authorized, err := s.keys.vtxoCheckpointAuthorization(signCtx, authorization)
	if err != nil {
		return nil, err
	}
	op.CheckpointPSBTs = encodeJSONStringSlice(authorized)
	op.CheckpointRequestPSBTs = requestBinding
	op.State = policy.VtxoStateSubmitted
	current, swapped, err := s.Stores.VtxoOperations.TransitionVtxoOperation(ctx, policy.VtxoStateSigned, op)
	if err != nil {
		return nil, err
	}
	if !swapped {
		if current.State != policy.VtxoStateSubmitted || current.CheckpointRequestPSBTs != requestBinding {
			return nil, apperr.New(apperr.CodeRejected, "vtxo operation changed concurrently")
		}
		op = current
		authorized = decodeJSONStringSlice(current.CheckpointPSBTs)
	}
	return &VtxoCheckpointAuthorizeResponse{
		OperationID: op.OperationID, BundleDigest: digestHex,
		CheckpointPsbts: authorized, ArkTxid: op.ArkTxid,
	}, nil
}

func (s *Service) FinalizeVtxo(ctx context.Context, req VtxoFinalizeRequest) (*VtxoFinalizeResponse, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	if err := s.requireVaultPolicyV1Exit(); err != nil {
		return nil, err
	}
	arkTxid := strings.ToLower(strings.TrimSpace(req.ArkTxid))
	if err := requireTxid(arkTxid); err != nil {
		return nil, apperr.New(apperr.CodeRejected, "arkTxid")
	}
	vaultID, _, _, err := s.resolveSpendVaultRecord(req.VaultID)
	if err != nil {
		return nil, err
	}
	op, err := s.Stores.VtxoOperations.GetVtxoOperation(ctx, req.OperationID)
	if err == sql.ErrNoRows {
		return nil, apperr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if op.VaultID != vaultID {
		return nil, apperr.New(apperr.CodeRejected, "operation does not belong to this vault")
	}
	if op.Purpose != policy.VtxoPurposeSpend {
		return nil, apperr.New(apperr.CodeRejected, "vtxo purpose must be spend")
	}
	if err := requireBundleDigest(req.BundleDigest, op.BundleDigest); err != nil {
		return nil, err
	}
	digestHex := hex.EncodeToString(op.BundleDigest)
	if op.State == policy.VtxoStateFinalized && strings.EqualFold(op.ArkTxid, arkTxid) {
		return &VtxoFinalizeResponse{OperationID: op.OperationID, BundleDigest: digestHex, State: op.State, ArkTxid: op.ArkTxid}, nil
	}
	if !vtxoFinalizableState(op.State) {
		return nil, apperr.New(apperr.CodeRejected, "vtxo operation state")
	}
	if !strings.EqualFold(op.ArkTxid, arkTxid) {
		return nil, apperr.New(apperr.CodeRejected, "arkTxid mismatch")
	}
	if err := s.requireArkResolver(); err != nil {
		return nil, err
	}
	if err := s.promoteSubmittedVtxo(ctx, op); err != nil {
		return nil, err
	}
	op, err = s.Stores.VtxoOperations.GetVtxoOperation(ctx, req.OperationID)
	if err != nil {
		return nil, err
	}
	if op.State != policy.VtxoStateFinalized {
		return nil, apperr.New(apperr.CodeRejected, "reserved outpoint not spent by ark txid")
	}
	return &VtxoFinalizeResponse{OperationID: op.OperationID, BundleDigest: digestHex, State: op.State, ArkTxid: op.ArkTxid}, nil
}

func (s *Service) verifyVtxoAuthorization(ctx context.Context, vaultID string, digest []byte, req WebAuthnAssertionRequest, directSigHex string) ([]byte, uint32, error) {
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	if len(digest) != 32 {
		return nil, 0, apperr.New(apperr.CodeRejected, "bundle digest must be 32 bytes")
	}
	assertion, err := decodeAssertion(req)
	if err != nil {
		return nil, 0, err
	}
	if err := rejectPRF(assertion.ClientDataJSON); err != nil {
		return nil, 0, err
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return nil, 0, err
	}
	if cred == nil {
		return nil, 0, fmt.Errorf("not enrolled")
	}
	if err := s.rejectCrossVaultCredential(vaultID, cred.ID); err != nil {
		return nil, 0, err
	}
	verified, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID,
		WebAuthnP256: cred.WebAuthnP256,
		Challenge:    digest,
		Origin:       cred.Origin,
		RPID:         cred.RPID,
	})
	if err != nil {
		return nil, 0, err
	}
	directSig, err := decodeHex(directSigHex)
	if err != nil {
		return nil, 0, apperr.New(apperr.CodeRejected, "directSig")
	}
	if err := verifyDirectAuth(cred.PhoneDirectP256, digest, directSig); err != nil {
		return nil, 0, err
	}
	return bytes.Clone(cred.ID), verified.SignCount, nil
}

func matchReservedOutpoint(seen map[string]policy.VtxoOperationInput, op wire.OutPoint) (policy.VtxoOperationInput, bool) {
	display, err := hex.DecodeString(op.Hash.String())
	if err != nil {
		return policy.VtxoOperationInput{}, false
	}
	in, ok := seen[outpointKey(display, op.Index)]
	return in, ok
}

func encodeJSONStringSlice(v []string) string {
	if len(v) == 0 {
		return ""
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

func decodeJSONStringSlice(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil
	}
	return out
}

func outpointKey(txid []byte, vout uint32) string {
	return hex.EncodeToString(txid) + ":" + fmt.Sprintf("%d", vout)
}
