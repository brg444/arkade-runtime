package application

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/program"
)

const (
	vaultBoardRegisterTTL = 2 * time.Minute
	vaultBoardDeleteTTL   = 2 * time.Minute
	// Covers the 15-second stock Operator timeout plus the five-second SQLite
	// busy window, with room to fail before a proof can expire.
	vaultBoardDispatchMargin = 30 * time.Second
	vaultBoardHandleDomain   = "arkade-vault/vault-board-v1-handle/v1"
	vaultBoardHandleMax      = 1536
)

type vaultBoardRuntime struct {
	chain        vaultBoardChain
	operatorDial func(context.Context) (vaultBoardOperator, error)
	// batchExpiry is a release pin, not a caller- or Operator-selected value.
	// Zero deliberately leaves final authorization disabled.
	batchExpiry uint32
}

type vaultBoardPrepareInput struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type vaultBoardPrepareRecipient struct {
	Address    string `json:"address"`
	AmountSats uint64 `json:"amountSats"`
	HasAssets  bool   `json:"-"`
}

type vaultBoardPrepareRequest struct {
	VaultID    string                       `json:"vaultId"`
	Inputs     []vaultBoardPrepareInput     `json:"inputs"`
	Recipients []vaultBoardPrepareRecipient `json:"recipients"`
}

type vaultBoardHandleClaims struct {
	Version          uint32 `json:"version"`
	Kind             string `json:"kind"`
	VaultID          string `json:"vaultId"`
	OperationID      string `json:"operationId"`
	Txid             string `json:"txid"`
	Vout             uint32 `json:"vout"`
	Attempt          uint32 `json:"attempt"`
	ReceiverSats     int64  `json:"receiverSats"`
	FeeSats          int64  `json:"feeSats"`
	RegisterExpireAt int64  `json:"registerExpireAt"`
	DeleteExpireAt   int64  `json:"deleteExpireAt"`
}

type vaultBoardPrepareResult struct {
	State            vaultBoardPrepareState
	Handle           string
	RegisterExpireAt int64
	DeleteExpireAt   int64
	Reason           string
	CommitmentTxid   string
}

type vaultBoardRegisterResult string

const (
	vaultBoardRegistered             vaultBoardRegisterResult = "registered"
	vaultBoardDefinitelyNotSubmitted vaultBoardRegisterResult = "definitely_not_submitted"
	vaultBoardRegisterAmbiguous      vaultBoardRegisterResult = "ambiguous"
)

type vaultBoardRegisterResponse struct {
	Status   vaultBoardRegisterResult
	IntentID string
}

type vaultBoardReleaseResult string

const (
	vaultBoardReleased         vaultBoardReleaseResult = "released"
	vaultBoardReleaseAmbiguous vaultBoardReleaseResult = "ambiguous"
)

type vaultBoardCommitmentResult string

const (
	vaultBoardCommitmentSubmitted vaultBoardCommitmentResult = "submitted"
	vaultBoardCommitmentAmbiguous vaultBoardCommitmentResult = "ambiguous"
)

type vaultBoardRegisterPhaseRequest struct {
	Handle       string
	PSBT         string
	Message      string
	InputIndexes []int
}

type vaultBoardDeletePhaseRequest struct {
	Handle       string
	PSBT         string
	Message      string
	InputIndexes []int
}

type vaultBoardFinalPhaseRequest struct {
	Handle         string
	PSBT           string
	InputIndexes   []int
	SignedForfeits []string
	Batch          vaultBoardFinalEvidence
}

type exactVaultBoardVtxoResolver interface {
	exactVtxo(context.Context, string, uint32, []byte) (*ports.ResolvedVtxo, error)
}

func (s *Service) requireVaultBoardRuntime() (*vaultBoardRuntime, error) {
	if s == nil || s.Stores.VaultBoard == nil || s.vaultBoardRuntime == nil ||
		s.vaultBoardRuntime.chain == nil || s.vaultBoardRuntime.operatorDial == nil {
		return nil, fmt.Errorf("vault-board-v1 authorization runtime unavailable")
	}
	return s.vaultBoardRuntime, nil
}

func (s *Service) prepareVaultBoard(ctx context.Context, req vaultBoardPrepareRequest) (vaultBoardPrepareResult, error) {
	runtime, err := s.requireVaultBoardRuntime()
	if err != nil {
		return vaultBoardPrepareResult{}, err
	}
	if len(req.Inputs) != 1 || len(req.Recipients) != 1 || req.Recipients[0].HasAssets || req.Recipients[0].AmountSats > math.MaxInt64 {
		return vaultBoardPrepareResult{}, fmt.Errorf("vault-board-v1 requires one boarding input and one BTC receiver")
	}
	ctxState, err := s.loadVaultBoardContext(ctx, runtime, req.VaultID, req.Inputs[0].Txid, req.Inputs[0].Vout)
	if err != nil {
		return vaultBoardPrepareResult{}, err
	}
	destScript, _, err := s.decodeVtxoDest(req.Recipients[0].Address)
	if err != nil || !bytes.Equal(destScript, ctxState.receiverScript) {
		return vaultBoardPrepareResult{}, fmt.Errorf("vault-board-v1 receiver must be the enrolled Spending script")
	}
	receiverSats := int64(req.Recipients[0].AmountSats)
	operationID, err := policy.ComputeVaultBoardOperationID(ctxState.vaultID, ctxState.chain.Txid, ctxState.chain.Vout)
	if err != nil {
		return vaultBoardPrepareResult{}, err
	}
	snapshot, err := s.Stores.VaultBoard.GetCurrentVaultBoardAttempt(ctx, operationID)
	if err != nil {
		return vaultBoardPrepareResult{}, err
	}
	if snapshot != nil {
		if err := requireSameVaultBoardChainFacts(snapshot.Operation, ctxState.chain, ctxState.receiverScript); err != nil {
			return vaultBoardPrepareResult{}, err
		}
		if finalized, commitment, err := s.reconcileVaultBoardFinal(ctx, ctxState.chain, snapshot); err != nil {
			return vaultBoardPrepareResult{}, err
		} else if finalized {
			return vaultBoardPrepareResult{State: vaultBoardFinalized, CommitmentTxid: commitment}, nil
		}
	}
	// Final reconciliation above is factual and remains available after the
	// recovery leaf matures. Only new cooperative signing is cut off by MTP.
	if err := requireVaultBoardMTP(ctxState.chain, s.boardExitDelay()); err != nil {
		return vaultBoardPrepareResult{}, err
	}
	if ctxState.chain.Spent {
		return vaultBoardPrepareResult{State: vaultBoardBlocked, Reason: "boarding outpoint is already spent"}, nil
	}
	feeSats, err := s.requireVaultBoardFee(ctx, ctxState.record, ctxState.chain.ValueSats, receiverSats, destScript)
	if err != nil {
		return vaultBoardPrepareResult{}, err
	}
	now := s.vtxoNow()
	preparation := classifyVaultBoardAttempt(snapshot, now)
	nowUnix := now.Unix()
	switch preparation.State {
	case vaultBoardReady:
		expireAt := nowUnix + int64(vaultBoardRegisterTTL/time.Second)
		claims := vaultBoardHandleClaims{
			Version: 1, Kind: string(vaultBoardReady), VaultID: ctxState.vaultID,
			OperationID: operationID, Txid: req.Inputs[0].Txid, Vout: req.Inputs[0].Vout,
			Attempt: preparation.Attempt, ReceiverSats: receiverSats, FeeSats: feeSats,
			RegisterExpireAt: expireAt,
		}
		handle, err := s.sealVaultBoardHandle(claims)
		return vaultBoardPrepareResult{State: vaultBoardReady, Handle: handle, RegisterExpireAt: expireAt}, err
	case vaultBoardReleaseRequired:
		expireAt := nowUnix + int64(vaultBoardDeleteTTL/time.Second)
		claims := vaultBoardHandleClaims{
			Version: 1, Kind: string(vaultBoardReleaseRequired), VaultID: ctxState.vaultID,
			OperationID: operationID, Txid: req.Inputs[0].Txid, Vout: req.Inputs[0].Vout,
			Attempt: preparation.Attempt, DeleteExpireAt: expireAt,
		}
		handle, err := s.sealVaultBoardHandle(claims)
		return vaultBoardPrepareResult{State: vaultBoardReleaseRequired, Handle: handle, DeleteExpireAt: expireAt}, err
	default:
		return vaultBoardPrepareResult{State: vaultBoardBlocked, Reason: preparation.Reason}, nil
	}
}

type vaultBoardContext struct {
	vaultID        string
	snapshot       enrolledSnapshot
	record         *policy.VaultRecord
	boardTree      *vtxoBoardTree
	receiverScript []byte
	chain          vaultBoardConfirmedOutpoint
}

func (s *Service) loadVaultBoardContext(ctx context.Context, runtime *vaultBoardRuntime, vaultID, txid string, vout uint32) (vaultBoardContext, error) {
	if requireTxid(txid) != nil {
		return vaultBoardContext{}, fmt.Errorf("vault-board-v1 canonical outpoint required")
	}
	id, snap, rec, err := s.resolveSpendVaultRecord(vaultID)
	if err != nil {
		return vaultBoardContext{}, err
	}
	if snap.Board == nil || snap.Board.BoardingPub == nil {
		return vaultBoardContext{}, fmt.Errorf("vault is not enrolled for vault-board-v1")
	}
	boardTree, err := s.buildVtxoBoardTree(id, snap, snap.Board.BoardingPub)
	if err != nil || !bytes.Equal(boardTree.PkScript, snap.Board.PkScript) {
		return vaultBoardContext{}, fmt.Errorf("vault-board-v1 enrollment policy mismatch")
	}
	receiverTree, err := s.buildVtxoPolicyTree(id, snap)
	if err != nil {
		return vaultBoardContext{}, err
	}
	chain, err := runtime.chain.confirmedOutpoint(ctx, txid, vout)
	if err != nil {
		return vaultBoardContext{}, err
	}
	if !bytes.Equal(chain.PkScript, boardTree.PkScript) || chain.ValueSats <= 0 {
		return vaultBoardContext{}, fmt.Errorf("confirmed enrolled vault-board-v1 outpoint required")
	}
	return vaultBoardContext{
		vaultID: id, snapshot: snap, record: rec, boardTree: boardTree,
		receiverScript: bytes.Clone(receiverTree.PkScript), chain: chain,
	}, nil
}

func requireVaultBoardMTP(chain vaultBoardConfirmedOutpoint, delay uint32) error {
	return requireVaultBoardCooperativeMTP(chain.SequenceAnchorMTP, chain.TipMTP, int64(delay))
}

func requireVaultBoardCooperativeMTP(anchor, tip, delay int64) error {
	if delay <= 0 || anchor <= 0 || tip <= 0 || anchor > math.MaxInt64-delay ||
		tip >= anchor+delay {
		return fmt.Errorf("vault-board-v1 cooperative path has matured")
	}
	return nil
}

func requireSameVaultBoardChainFacts(operation policy.VaultBoardOperation, chain vaultBoardConfirmedOutpoint, receiver []byte) error {
	if operation.VaultID == "" || !bytes.Equal(operation.Txid, chain.Txid) || operation.Vout != chain.Vout ||
		operation.ValueSats != chain.ValueSats || !bytes.Equal(operation.BoardingScript, chain.PkScript) ||
		!bytes.Equal(operation.ReceiverScript, receiver) || operation.SequenceAnchorMTP != chain.SequenceAnchorMTP {
		return fmt.Errorf("vault-board-v1 authoritative outpoint facts changed")
	}
	return nil
}

func (s *Service) requireVaultBoardFee(ctx context.Context, rec *policy.VaultRecord, value, receiver int64, script []byte) (int64, error) {
	if value <= 0 || receiver < int64(program.DustSats) || receiver > value || len(script) == 0 || isNilInterface(s.ArkResolver) {
		return 0, fmt.Errorf("vault-board-v1 receiver amount")
	}
	feePolicy, err := s.ArkResolver.IntentFeePolicy(ctx)
	if err != nil {
		return 0, fmt.Errorf("vault-board-v1 Operator fee policy unavailable")
	}
	estimator, _, err := newVtxoFeeEstimator(feePolicy)
	if err != nil {
		return 0, err
	}
	evaluated, err := estimator.Eval(nil,
		[]arkfee.OnchainInput{{Amount: uint64(value)}},
		[]arkfee.Output{{Amount: uint64(receiver), Script: hex.EncodeToString(script)}}, nil)
	if err != nil {
		return 0, fmt.Errorf("vault-board-v1 Operator fee evaluation")
	}
	want, err := exactFeeSats(evaluated)
	if err != nil || want > math.MaxInt64 || int64(want) != value-receiver {
		return 0, fmt.Errorf("vault-board-v1 exact Operator fee required")
	}
	capSats := int64(program.AbsoluteFeeCeiling)
	if rec != nil {
		capSats = rec.AbsoluteFeeCapSats
	}
	if capSats < 0 || int64(want) > capSats {
		return 0, fmt.Errorf("vault-board-v1 fee exceeds vault ceiling")
	}
	return int64(want), nil
}

func (s *Service) sealVaultBoardHandle(claims vaultBoardHandleClaims) (string, error) {
	if claims.Version != 1 || claims.VaultID == "" || claims.OperationID == "" || requireTxid(claims.Txid) != nil {
		return "", fmt.Errorf("vault-board-v1 handle claims")
	}
	payload, err := json.Marshal(claims)
	if err != nil || len(payload) > vaultBoardHandleMax {
		return "", fmt.Errorf("vault-board-v1 handle claims")
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		zeroServiceBytes(payload)
		return "", err
	}
	defer zeroServiceBytes(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(vaultBoardHandleDomain))
	_, _ = mac.Write(payload)
	sig := mac.Sum(nil)
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	zeroServiceBytes(payload)
	zeroServiceBytes(sig)
	return token, nil
}

func (s *Service) openVaultBoardHandle(raw, kind string) (vaultBoardHandleClaims, error) {
	if len(raw) == 0 || len(raw) > vaultBoardHandleMax*2 || strings.Count(raw, ".") != 1 {
		return vaultBoardHandleClaims{}, fmt.Errorf("vault-board-v1 handle")
	}
	parts := strings.SplitN(raw, ".", 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > vaultBoardHandleMax {
		zeroServiceBytes(payload)
		return vaultBoardHandleClaims{}, fmt.Errorf("vault-board-v1 handle")
	}
	defer zeroServiceBytes(payload)
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(sig) != sha256.Size {
		zeroServiceBytes(sig)
		return vaultBoardHandleClaims{}, fmt.Errorf("vault-board-v1 handle")
	}
	defer zeroServiceBytes(sig)
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return vaultBoardHandleClaims{}, err
	}
	defer zeroServiceBytes(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(vaultBoardHandleDomain))
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return vaultBoardHandleClaims{}, fmt.Errorf("vault-board-v1 handle")
	}
	var claims vaultBoardHandleClaims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil || claims.Version != 1 || claims.Kind != kind || claims.VaultID == "" ||
		claims.OperationID == "" || requireTxid(claims.Txid) != nil {
		return vaultBoardHandleClaims{}, fmt.Errorf("vault-board-v1 handle")
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(canonical, payload) {
		zeroServiceBytes(canonical)
		return vaultBoardHandleClaims{}, fmt.Errorf("vault-board-v1 handle")
	}
	zeroServiceBytes(canonical)
	return claims, nil
}

func (s *Service) reconcileVaultBoardFinal(ctx context.Context, chain vaultBoardConfirmedOutpoint, snapshot *policy.VaultBoardAttemptSnapshot) (bool, string, error) {
	if snapshot == nil || snapshot.FinalAuthorization == nil {
		return false, "", nil
	}
	auth := snapshot.FinalAuthorization
	if auth.CommitmentTxid == "" || auth.ReceiverTxid == "" || !chain.Spent || chain.SpendingTxid != auth.CommitmentTxid {
		return false, "", nil
	}
	resolver, ok := s.ArkResolver.(exactVaultBoardVtxoResolver)
	if !ok {
		return false, "", fmt.Errorf("vault-board-v1 exact VTXO resolver unavailable")
	}
	vtxo, err := resolver.exactVtxo(ctx, auth.ReceiverTxid, auth.ReceiverVout, snapshot.Operation.ReceiverScript)
	if err != nil || vtxo == nil {
		return false, "", err
	}
	if vtxo.ValueSats != uint64(snapshot.Register.ReceiverSats) || vtxo.Txid != auth.ReceiverTxid || vtxo.Vout != auth.ReceiverVout ||
		!containsCanonicalTxid(vtxo.CommitmentTxids, auth.CommitmentTxid) {
		return false, "", fmt.Errorf("vault-board-v1 exact receiver VTXO evidence conflicts")
	}
	return true, auth.CommitmentTxid, nil
}

func containsCanonicalTxid(values []string, want string) bool {
	seen := make(map[string]struct{}, len(values))
	found := false
	for _, value := range values {
		if requireTxid(value) != nil {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
		if value == want {
			found = true
		}
	}
	return found
}

func (s *Service) vaultBoardOperationFromClaims(ctxState vaultBoardContext, claims vaultBoardHandleClaims) (policy.VaultBoardOperation, error) {
	if claims.VaultID != ctxState.vaultID || claims.Txid != hex.EncodeToString(ctxState.chain.Txid) || claims.Vout != ctxState.chain.Vout {
		return policy.VaultBoardOperation{}, fmt.Errorf("vault-board-v1 handle does not match outpoint")
	}
	wantID, err := policy.ComputeVaultBoardOperationID(ctxState.vaultID, ctxState.chain.Txid, ctxState.chain.Vout)
	if err != nil || claims.OperationID != wantID {
		return policy.VaultBoardOperation{}, fmt.Errorf("vault-board-v1 handle does not match operation")
	}
	return policy.VaultBoardOperation{
		OperationID: wantID, VaultID: ctxState.vaultID, Txid: bytes.Clone(ctxState.chain.Txid), Vout: ctxState.chain.Vout,
		ValueSats: ctxState.chain.ValueSats, BoardingScript: bytes.Clone(ctxState.chain.PkScript),
		ReceiverScript: bytes.Clone(ctxState.receiverScript), SequenceAnchorMTP: ctxState.chain.SequenceAnchorMTP,
	}, nil
}

func vaultBoardChainPolicy(chain vaultBoardConfirmedOutpoint) policy.VaultBoardChainState {
	return policy.VaultBoardChainState{TipMTP: chain.TipMTP}
}

func revalidateVaultBoardOutpoint(runtime *vaultBoardRuntime, prior vaultBoardConfirmedOutpoint) (vaultBoardConfirmedOutpoint, error) {
	if runtime == nil || runtime.chain == nil {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 chain unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), vaultBoardChainTimeout)
	defer cancel()
	return runtime.chain.revalidateOutpoint(ctx, prior)
}

func vaultBoardFinalExpiry(value uint32) arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: value}
}
