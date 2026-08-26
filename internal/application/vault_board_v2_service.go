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
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/ports"
	"github.com/brg444/arkade-vault-server/internal/program"
)

const (
	vaultBoardV2RegisterTTL = 2 * time.Minute
	vaultBoardV2DeleteTTL   = 2 * time.Minute
	// Covers the 15-second stock Operator timeout plus the five-second SQLite
	// busy window, with room to fail before a proof can expire.
	vaultBoardV2DispatchMargin = 30 * time.Second
	vaultBoardV2HandleDomain   = "arkade-vault/vault-board-v2-handle/v1"
	vaultBoardV2HandleMax      = 1536
)

type vaultBoardV2Runtime struct {
	chain        vaultBoardV2Chain
	operatorDial func(context.Context) (vaultBoardV2Operator, error)
	// batchExpiry is a release pin, not a caller- or Operator-selected value.
	// Zero deliberately leaves final authorization disabled.
	batchExpiry uint32
}

type vaultBoardV2PrepareInput struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type vaultBoardV2PrepareRecipient struct {
	Address    string `json:"address"`
	AmountSats uint64 `json:"amountSats"`
	HasAssets  bool   `json:"-"`
}

type vaultBoardV2PrepareRequest struct {
	VaultID    string                         `json:"vaultId"`
	Inputs     []vaultBoardV2PrepareInput     `json:"inputs"`
	Recipients []vaultBoardV2PrepareRecipient `json:"recipients"`
}

type vaultBoardV2HandleClaims struct {
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

type vaultBoardV2PrepareResult struct {
	State            vaultBoardV2PrepareState
	Handle           string
	RegisterExpireAt int64
	DeleteExpireAt   int64
	Reason           string
	CommitmentTxid   string
}

type vaultBoardV2RegisterResult string

const (
	vaultBoardV2Registered             vaultBoardV2RegisterResult = "registered"
	vaultBoardV2DefinitelyNotSubmitted vaultBoardV2RegisterResult = "definitely_not_submitted"
	vaultBoardV2RegisterAmbiguous      vaultBoardV2RegisterResult = "ambiguous"
)

type vaultBoardV2RegisterResponse struct {
	Status   vaultBoardV2RegisterResult
	IntentID string
}

type vaultBoardV2ReleaseResult string

const (
	vaultBoardV2Released         vaultBoardV2ReleaseResult = "released"
	vaultBoardV2ReleaseAmbiguous vaultBoardV2ReleaseResult = "ambiguous"
)

type vaultBoardV2CommitmentResult string

const (
	vaultBoardV2CommitmentSubmitted vaultBoardV2CommitmentResult = "submitted"
	vaultBoardV2CommitmentAmbiguous vaultBoardV2CommitmentResult = "ambiguous"
)

type vaultBoardV2RegisterPhaseRequest struct {
	Handle       string
	PSBT         string
	Message      string
	InputIndexes []int
}

type vaultBoardV2DeletePhaseRequest struct {
	Handle       string
	PSBT         string
	Message      string
	InputIndexes []int
}

type vaultBoardV2FinalPhaseRequest struct {
	Handle         string
	PSBT           string
	InputIndexes   []int
	SignedForfeits []string
	Batch          vaultBoardV2FinalEvidence
}

type exactVaultBoardV2VtxoResolver interface {
	exactVtxo(context.Context, string, uint32, []byte) (*ports.ResolvedVtxo, error)
}

func (s *Service) requireVaultBoardV2Runtime() (*vaultBoardV2Runtime, error) {
	if s == nil || s.VaultBoardV2Store == nil || s.vaultBoardV2Runtime == nil ||
		s.vaultBoardV2Runtime.chain == nil || s.vaultBoardV2Runtime.operatorDial == nil {
		return nil, fmt.Errorf("vault-board-v2 authorization runtime unavailable")
	}
	return s.vaultBoardV2Runtime, nil
}

func (s *Service) prepareVaultBoardV2(ctx context.Context, req vaultBoardV2PrepareRequest) (vaultBoardV2PrepareResult, error) {
	runtime, err := s.requireVaultBoardV2Runtime()
	if err != nil {
		return vaultBoardV2PrepareResult{}, err
	}
	if len(req.Inputs) != 1 || len(req.Recipients) != 1 || req.Recipients[0].HasAssets || req.Recipients[0].AmountSats > math.MaxInt64 {
		return vaultBoardV2PrepareResult{}, fmt.Errorf("vault-board-v2 requires one boarding input and one BTC receiver")
	}
	ctxState, err := s.loadVaultBoardV2Context(ctx, runtime, req.VaultID, req.Inputs[0].Txid, req.Inputs[0].Vout)
	if err != nil {
		return vaultBoardV2PrepareResult{}, err
	}
	destScript, _, err := s.decodeVtxoDest(req.Recipients[0].Address)
	if err != nil || !bytes.Equal(destScript, ctxState.receiverScript) {
		return vaultBoardV2PrepareResult{}, fmt.Errorf("vault-board-v2 receiver must be the enrolled Spending script")
	}
	receiverSats := int64(req.Recipients[0].AmountSats)
	operationID, err := policy.ComputeVaultBoardV2OperationID(ctxState.vaultID, ctxState.chain.Txid, ctxState.chain.Vout)
	if err != nil {
		return vaultBoardV2PrepareResult{}, err
	}
	snapshot, err := s.VaultBoardV2Store.GetCurrentVaultBoardV2Attempt(ctx, operationID)
	if err != nil {
		return vaultBoardV2PrepareResult{}, err
	}
	if snapshot != nil {
		if err := requireSameVaultBoardV2ChainFacts(snapshot.Operation, ctxState.chain, ctxState.receiverScript); err != nil {
			return vaultBoardV2PrepareResult{}, err
		}
		if finalized, commitment, err := s.reconcileVaultBoardV2Final(ctx, ctxState.chain, snapshot); err != nil {
			return vaultBoardV2PrepareResult{}, err
		} else if finalized {
			return vaultBoardV2PrepareResult{State: vaultBoardV2Finalized, CommitmentTxid: commitment}, nil
		}
	}
	// Final reconciliation above is factual and remains available after the
	// recovery leaf matures. Only new cooperative signing is cut off by MTP.
	if err := requireVaultBoardV2MTP(ctxState.chain); err != nil {
		return vaultBoardV2PrepareResult{}, err
	}
	if ctxState.chain.Spent {
		return vaultBoardV2PrepareResult{State: vaultBoardV2Blocked, Reason: "boarding outpoint is already spent"}, nil
	}
	feeSats, err := s.requireVaultBoardV2Fee(ctx, ctxState.record, ctxState.chain.ValueSats, receiverSats, destScript)
	if err != nil {
		return vaultBoardV2PrepareResult{}, err
	}
	preparation := classifyVaultBoardV2Attempt(operationID, snapshot)
	now := s.vtxoNow().Unix()
	switch preparation.State {
	case vaultBoardV2Ready:
		expireAt := now + int64(vaultBoardV2RegisterTTL/time.Second)
		claims := vaultBoardV2HandleClaims{
			Version: 1, Kind: string(vaultBoardV2Ready), VaultID: ctxState.vaultID,
			OperationID: operationID, Txid: req.Inputs[0].Txid, Vout: req.Inputs[0].Vout,
			Attempt: preparation.Attempt, ReceiverSats: receiverSats, FeeSats: feeSats,
			RegisterExpireAt: expireAt,
		}
		handle, err := s.sealVaultBoardV2Handle(claims)
		return vaultBoardV2PrepareResult{State: vaultBoardV2Ready, Handle: handle, RegisterExpireAt: expireAt}, err
	case vaultBoardV2ReleaseRequired:
		expireAt := now + int64(vaultBoardV2DeleteTTL/time.Second)
		claims := vaultBoardV2HandleClaims{
			Version: 1, Kind: string(vaultBoardV2ReleaseRequired), VaultID: ctxState.vaultID,
			OperationID: operationID, Txid: req.Inputs[0].Txid, Vout: req.Inputs[0].Vout,
			Attempt: preparation.Attempt, DeleteExpireAt: expireAt,
		}
		handle, err := s.sealVaultBoardV2Handle(claims)
		return vaultBoardV2PrepareResult{State: vaultBoardV2ReleaseRequired, Handle: handle, DeleteExpireAt: expireAt}, err
	default:
		return vaultBoardV2PrepareResult{State: vaultBoardV2Blocked, Reason: preparation.Reason}, nil
	}
}

type vaultBoardV2Context struct {
	vaultID        string
	snapshot       enrolledSnapshot
	record         *policy.VaultRecord
	boardTree      *vtxoBoardV2Tree
	receiverScript []byte
	chain          vaultBoardV2ConfirmedOutpoint
}

func (s *Service) loadVaultBoardV2Context(ctx context.Context, runtime *vaultBoardV2Runtime, vaultID, txid string, vout uint32) (vaultBoardV2Context, error) {
	if requireTxid(txid) != nil {
		return vaultBoardV2Context{}, fmt.Errorf("vault-board-v2 canonical outpoint required")
	}
	id, snap, rec, err := s.resolveSpendVaultRecord(vaultID)
	if err != nil {
		return vaultBoardV2Context{}, err
	}
	if snap.BoardV2 == nil || snap.BoardV2.BoardingPub == nil {
		return vaultBoardV2Context{}, fmt.Errorf("vault is not enrolled for vault-board-v2")
	}
	boardTree, err := s.buildVtxoBoardV2Tree(id, snap, snap.BoardV2.BoardingPub)
	if err != nil || !bytes.Equal(boardTree.PkScript, snap.BoardV2.PkScript) {
		return vaultBoardV2Context{}, fmt.Errorf("vault-board-v2 enrollment policy mismatch")
	}
	receiverTree, err := s.buildVtxoPolicyTree(id, snap)
	if err != nil {
		return vaultBoardV2Context{}, err
	}
	chain, err := runtime.chain.confirmedOutpoint(ctx, txid, vout)
	if err != nil {
		return vaultBoardV2Context{}, err
	}
	if !bytes.Equal(chain.PkScript, boardTree.PkScript) || chain.ValueSats <= 0 {
		return vaultBoardV2Context{}, fmt.Errorf("confirmed enrolled vault-board-v2 outpoint required")
	}
	return vaultBoardV2Context{
		vaultID: id, snapshot: snap, record: rec, boardTree: boardTree,
		receiverScript: bytes.Clone(receiverTree.PkScript), chain: chain,
	}, nil
}

func requireVaultBoardV2MTP(chain vaultBoardV2ConfirmedOutpoint) error {
	return requireVaultBoardV2CooperativeMTP(chain.SequenceAnchorMTP, chain.TipMTP)
}

func requireVaultBoardV2CooperativeMTP(anchor, tip int64) error {
	if anchor <= 0 || tip <= 0 || anchor > math.MaxInt64-int64(program.VaultBoardV2ExitDelay) ||
		tip >= anchor+int64(program.VaultBoardV2ExitDelay) {
		return fmt.Errorf("vault-board-v2 cooperative path has matured")
	}
	return nil
}

func requireSameVaultBoardV2ChainFacts(operation policy.VaultBoardV2Operation, chain vaultBoardV2ConfirmedOutpoint, receiver []byte) error {
	if operation.VaultID == "" || !bytes.Equal(operation.Txid, chain.Txid) || operation.Vout != chain.Vout ||
		operation.ValueSats != chain.ValueSats || !bytes.Equal(operation.BoardingScript, chain.PkScript) ||
		!bytes.Equal(operation.ReceiverScript, receiver) || operation.SequenceAnchorMTP != chain.SequenceAnchorMTP {
		return fmt.Errorf("vault-board-v2 authoritative outpoint facts changed")
	}
	return nil
}

func (s *Service) requireVaultBoardV2Fee(ctx context.Context, rec *policy.VaultRecord, value, receiver int64, script []byte) (int64, error) {
	if value <= 0 || receiver < int64(program.DustSats) || receiver > value || len(script) == 0 || isNilInterface(s.ArkResolver) {
		return 0, fmt.Errorf("vault-board-v2 receiver amount")
	}
	feePolicy, err := s.ArkResolver.IntentFeePolicy(ctx)
	if err != nil {
		return 0, fmt.Errorf("vault-board-v2 Operator fee policy unavailable")
	}
	estimator, _, err := newVtxoFeeEstimator(feePolicy)
	if err != nil {
		return 0, err
	}
	evaluated, err := estimator.Eval(nil,
		[]arkfee.OnchainInput{{Amount: uint64(value)}},
		[]arkfee.Output{{Amount: uint64(receiver), Script: hex.EncodeToString(script)}}, nil)
	if err != nil {
		return 0, fmt.Errorf("vault-board-v2 Operator fee evaluation")
	}
	want, err := exactFeeSats(evaluated)
	if err != nil || want > math.MaxInt64 || int64(want) != value-receiver {
		return 0, fmt.Errorf("vault-board-v2 exact Operator fee required")
	}
	capSats := int64(program.AbsoluteFeeCeiling)
	if rec != nil {
		capSats = rec.AbsoluteFeeCapSats
	}
	if capSats < 0 || int64(want) > capSats {
		return 0, fmt.Errorf("vault-board-v2 fee exceeds vault ceiling")
	}
	return int64(want), nil
}

func (s *Service) sealVaultBoardV2Handle(claims vaultBoardV2HandleClaims) (string, error) {
	if claims.Version != 1 || claims.VaultID == "" || claims.OperationID == "" || requireTxid(claims.Txid) != nil {
		return "", fmt.Errorf("vault-board-v2 handle claims")
	}
	payload, err := json.Marshal(claims)
	if err != nil || len(payload) > vaultBoardV2HandleMax {
		return "", fmt.Errorf("vault-board-v2 handle claims")
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		zeroServiceBytes(payload)
		return "", err
	}
	defer zeroServiceBytes(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(vaultBoardV2HandleDomain))
	_, _ = mac.Write(payload)
	sig := mac.Sum(nil)
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	zeroServiceBytes(payload)
	zeroServiceBytes(sig)
	return token, nil
}

func (s *Service) openVaultBoardV2Handle(raw, kind string) (vaultBoardV2HandleClaims, error) {
	if len(raw) == 0 || len(raw) > vaultBoardV2HandleMax*2 || strings.Count(raw, ".") != 1 {
		return vaultBoardV2HandleClaims{}, fmt.Errorf("vault-board-v2 handle")
	}
	parts := strings.SplitN(raw, ".", 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > vaultBoardV2HandleMax {
		zeroServiceBytes(payload)
		return vaultBoardV2HandleClaims{}, fmt.Errorf("vault-board-v2 handle")
	}
	defer zeroServiceBytes(payload)
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(sig) != sha256.Size {
		zeroServiceBytes(sig)
		return vaultBoardV2HandleClaims{}, fmt.Errorf("vault-board-v2 handle")
	}
	defer zeroServiceBytes(sig)
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return vaultBoardV2HandleClaims{}, err
	}
	defer zeroServiceBytes(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(vaultBoardV2HandleDomain))
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return vaultBoardV2HandleClaims{}, fmt.Errorf("vault-board-v2 handle")
	}
	var claims vaultBoardV2HandleClaims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil || claims.Version != 1 || claims.Kind != kind || claims.VaultID == "" ||
		claims.OperationID == "" || requireTxid(claims.Txid) != nil {
		return vaultBoardV2HandleClaims{}, fmt.Errorf("vault-board-v2 handle")
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(canonical, payload) {
		zeroServiceBytes(canonical)
		return vaultBoardV2HandleClaims{}, fmt.Errorf("vault-board-v2 handle")
	}
	zeroServiceBytes(canonical)
	return claims, nil
}

func (s *Service) reconcileVaultBoardV2Final(ctx context.Context, chain vaultBoardV2ConfirmedOutpoint, snapshot *policy.VaultBoardV2AttemptSnapshot) (bool, string, error) {
	if snapshot == nil || snapshot.FinalAuthorization == nil {
		return false, "", nil
	}
	auth := snapshot.FinalAuthorization
	if auth.CommitmentTxid == "" || auth.ReceiverTxid == "" || !chain.Spent || chain.SpendingTxid != auth.CommitmentTxid {
		return false, "", nil
	}
	resolver, ok := s.ArkResolver.(exactVaultBoardV2VtxoResolver)
	if !ok {
		return false, "", fmt.Errorf("vault-board-v2 exact VTXO resolver unavailable")
	}
	vtxo, err := resolver.exactVtxo(ctx, auth.ReceiverTxid, auth.ReceiverVout, snapshot.Operation.ReceiverScript)
	if err != nil || vtxo == nil {
		return false, "", err
	}
	if vtxo.ValueSats != uint64(snapshot.Register.ReceiverSats) || vtxo.Txid != auth.ReceiverTxid || vtxo.Vout != auth.ReceiverVout ||
		!containsCanonicalTxid(vtxo.CommitmentTxids, auth.CommitmentTxid) {
		return false, "", fmt.Errorf("vault-board-v2 exact receiver VTXO evidence conflicts")
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

func (s *Service) vaultBoardV2OperationFromClaims(ctxState vaultBoardV2Context, claims vaultBoardV2HandleClaims) (policy.VaultBoardV2Operation, error) {
	if claims.VaultID != ctxState.vaultID || claims.Txid != hex.EncodeToString(ctxState.chain.Txid) || claims.Vout != ctxState.chain.Vout {
		return policy.VaultBoardV2Operation{}, fmt.Errorf("vault-board-v2 handle does not match outpoint")
	}
	wantID, err := policy.ComputeVaultBoardV2OperationID(ctxState.vaultID, ctxState.chain.Txid, ctxState.chain.Vout)
	if err != nil || claims.OperationID != wantID {
		return policy.VaultBoardV2Operation{}, fmt.Errorf("vault-board-v2 handle does not match operation")
	}
	return policy.VaultBoardV2Operation{
		OperationID: wantID, VaultID: ctxState.vaultID, Txid: bytes.Clone(ctxState.chain.Txid), Vout: ctxState.chain.Vout,
		ValueSats: ctxState.chain.ValueSats, BoardingScript: bytes.Clone(ctxState.chain.PkScript),
		ReceiverScript: bytes.Clone(ctxState.receiverScript), SequenceAnchorMTP: ctxState.chain.SequenceAnchorMTP,
	}, nil
}

func vaultBoardV2ChainPolicy(chain vaultBoardV2ConfirmedOutpoint) policy.VaultBoardV2ChainState {
	return policy.VaultBoardV2ChainState{TipMTP: chain.TipMTP}
}

func revalidateVaultBoardV2Outpoint(runtime *vaultBoardV2Runtime, prior vaultBoardV2ConfirmedOutpoint) (vaultBoardV2ConfirmedOutpoint, error) {
	if runtime == nil || runtime.chain == nil {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 chain unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), vaultBoardV2ChainTimeout)
	defer cancel()
	return runtime.chain.revalidateOutpoint(ctx, prior)
}

func vaultBoardV2FinalExpiry(value uint32) arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: value}
}
