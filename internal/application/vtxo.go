package application

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
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
	VaultID     string `json:"vaultId"`
	Purpose     string `json:"purpose"`
	DestAddress string `json:"destAddress"`
	AmountSats  uint64 `json:"amountSats"`
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
	CheckpointTapscript string          `json:"checkpointTapscript,omitempty"`
}

// VtxoAuthorizeRequest is POST /v1/vtxo/authorize (spend).
type VtxoAuthorizeRequest struct {
	VaultID                 string   `json:"vaultId"`
	OperationID             string   `json:"operationId"`
	BundleDigest            string   `json:"bundleDigest"`
	UnsignedArkPsbt         string   `json:"unsignedArkPsbt"`
	UnsignedCheckpointPsbts []string `json:"unsignedCheckpointPsbts"`
	CredentialID            string   `json:"credentialId"`
	ClientDataJSON          string   `json:"clientDataJSON"`
	AuthenticatorData       string   `json:"authenticatorData"`
	Signature               string   `json:"signature"`
	DirectSig               string   `json:"directSig"`
}

// VtxoAuthorizeResponse returns the VaultCosigner-authorized Ark PSBT. The
// Operator-returned checkpoints use the separate post-submit endpoint.
type VtxoAuthorizeResponse struct {
	OperationID    string `json:"operationId"`
	BundleDigest   string `json:"bundleDigest"`
	AuthorizedPsbt string `json:"authorizedPsbt"`
	ArkTxid        string `json:"arkTxid"`
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
	if s != nil && s.Ledger != nil {
		return s.Ledger.NowUTC()
	}
	if s != nil && s.SessionNow != nil {
		return s.SessionNow().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) ReserveVtxo(ctx context.Context, req VtxoReserveRequest) (*VtxoReserveResponse, error) {
	if err := s.attachLedgerIntegrity(); err != nil {
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
	if err := s.refuseDefaultVtxoChange(snap, destScript); err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	feeSats := uint64(0)
	if err := enforceVtxoAmount(req.AmountSats, feeSats, rec, snap); err != nil {
		return nil, err
	}
	selected, err := s.selectSpendVtxos(ctx, tree.PkScript, req.AmountSats)
	if err != nil {
		return nil, err
	}
	if len(selected) != 1 {
		return nil, apperr.New(apperr.CodeRejected, "exact spend program requires one input")
	}
	if selected[0].ValueSats < req.AmountSats+uint64(program.DustSats) {
		return nil, apperr.New(apperr.CodeRejected, "change below dust")
	}
	checkpoint := s.ArkResolver.CheckpointTapscript()
	if len(checkpoint) == 0 {
		return nil, apperr.New(apperr.CodeRejected, "checkpoint tapscript required")
	}
	inputs := make([]policy.VtxoBundleInput, len(selected))
	opInputs := make([]policy.VtxoOperationInput, len(selected))
	views := make([]VtxoInputView, len(selected))
	for i, coin := range selected {
		inputs[i] = policy.VtxoBundleInput{Txid: bytes.Clone(coin.Txid), Vout: coin.Vout, ValueSats: coin.ValueSats}
		opInputs[i] = policy.VtxoOperationInput{
			Txid: bytes.Clone(coin.Txid), Vout: int(coin.Vout), ValueSats: int64(coin.ValueSats), Script: bytes.Clone(coin.Script),
		}
		views[i] = VtxoInputView{
			Txid: hex.EncodeToString(coin.Txid), Vout: coin.Vout, ValueSats: coin.ValueSats, ScriptHex: hex.EncodeToString(coin.Script),
		}
	}
	ordered, err := policy.CanonicalVtxoBundleInputs(inputs)
	if err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	now := s.vtxoNow()
	created := now.Format(time.RFC3339)
	expires := now.Add(vtxoReserveAuthorizeTimeout).Format(time.RFC3339)
	digest, err := policy.ComputeVtxoBundleDigest(purpose, vaultID, destScript, tree.PkScript, req.AmountSats, feeSats, ordered, created)
	if err != nil {
		return nil, err
	}
	opID, err := randomHex(16)
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
		DestScript:          destScript,
		ChangeScript:        bytes.Clone(tree.PkScript),
		CheckpointTapscript: checkpoint,
		ExpiresAt:           expires,
		CreatedAt:           created,
		LastDestScript:      destScript,
	}
	allowance := periodAllowanceSats(rec, nil)
	if err := s.Ledger.ReserveVtxoOperation(ctx, recRow, opInputs, allowance); err != nil {
		return nil, mapLedgerBusy(err)
	}
	return &VtxoReserveResponse{
		OperationID:         opID,
		BundleDigest:        hex.EncodeToString(digest),
		ReservationExpires:  expires,
		Inputs:              views,
		ChangeAddress:       tree.ArkAddress,
		ChangeScript:        hex.EncodeToString(tree.PkScript),
		DestScript:          hex.EncodeToString(destScript),
		FeeSats:             feeSats,
		CheckpointTapscript: hex.EncodeToString(checkpoint),
	}, nil
}

type reservedCoin struct {
	Txid      []byte
	Vout      uint32
	ValueSats uint64
	Script    []byte
}

func (s *Service) selectSpendVtxos(ctx context.Context, pkScript []byte, amountSats uint64) ([]reservedCoin, error) {
	if amountSats > math.MaxUint64-uint64(program.DustSats) {
		return nil, apperr.New(apperr.CodeRejected, "amount overflow")
	}
	vtxos, err := s.ArkResolver.SpendableVtxos(ctx, pkScript)
	if err != nil {
		return nil, apperr.New(apperr.CodeRejected, "ark indexer")
	}
	coins := vtxosToCoins(vtxos, pkScript)
	listed := make([]policy.VtxoBundleInput, len(coins))
	for i, coin := range coins {
		listed[i] = policy.VtxoBundleInput{Txid: coin.Txid, Vout: coin.Vout, ValueSats: coin.ValueSats}
	}
	if _, err := policy.CanonicalVtxoBundleInputs(listed); err != nil {
		return nil, apperr.New(apperr.CodeRejected, err.Error())
	}
	need := amountSats + uint64(program.DustSats)
	picked, err := pickCoins(coins, need)
	if err != nil {
		return nil, err
	}
	if len(picked) != 1 {
		return nil, apperr.New(apperr.CodeRejected, "exact spend program requires one input")
	}
	return picked, nil
}

func vtxosToCoins(vtxos []ports.ResolvedVtxo, pkScript []byte) []reservedCoin {
	out := make([]reservedCoin, 0, len(vtxos))
	for _, v := range vtxos {
		raw, err := hex.DecodeString(v.Txid)
		if err != nil || len(raw) != 32 {
			continue
		}
		out = append(out, reservedCoin{Txid: raw, Vout: v.Vout, ValueSats: v.ValueSats, Script: bytes.Clone(pkScript)})
	}
	return out
}

func pickCoins(coins []reservedCoin, need uint64) ([]reservedCoin, error) {
	if need == 0 {
		return nil, apperr.New(apperr.CodeRejected, "amount required")
	}
	sorted := append([]reservedCoin(nil), coins...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].ValueSats > sorted[i].ValueSats {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	var picked []reservedCoin
	var sum uint64
	for _, c := range sorted {
		picked = append(picked, c)
		sum += c.ValueSats
		if sum >= need {
			return picked, nil
		}
	}
	return nil, apperr.New(apperr.CodeRejected, "insufficient vtxo funds")
}

func enforceVtxoAmount(amount, fee uint64, rec *policy.VaultRecord, snap enrolledSnapshot) error {
	capSats := program.TxRecipientCapSats
	feeCap := program.AbsoluteFeeCeiling
	if rec != nil {
		if rec.TxRecipientCapSats > 0 {
			capSats = rec.TxRecipientCapSats
		}
		if rec.AbsoluteFeeCapSats >= 0 {
			feeCap = rec.AbsoluteFeeCapSats
		}
	} else if snap.Operational != nil {
		capSats = snap.Operational.Record.AuthorizationPolicy.RecipientCapSats
		feeCap = snap.Operational.Record.AuthorizationPolicy.AbsoluteFeeCeilingSats
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
	rec, err := s.Ledger.GetVtxoOperation(ctx, operationID)
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
			rec.State = policy.VtxoStateAborted
			_ = s.Ledger.PutVtxoOperation(ctx, rec)
			return policy.VtxoOperation{}, nil, apperr.New(apperr.CodeRejected, "reservation expired")
		}
	}
	inputs, err := s.Ledger.GetVtxoOperationInputs(ctx, operationID)
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
	OperationID     string   `json:"operationId"`
	BundleDigest    string   `json:"bundleDigest"`
	State           string   `json:"state"`
	ArkTxid         string   `json:"arkTxid,omitempty"`
	ExpiresAt       string   `json:"expiresAt,omitempty"`
	AuthorizedPsbt  string   `json:"authorizedPsbt,omitempty"`
	CheckpointPsbts []string `json:"checkpointPsbts,omitempty"`
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
	op.State = policy.VtxoStateAborted
	if err := s.Ledger.PutVtxoOperation(ctx, op); err != nil {
		return op, err
	}
	return op, nil
}

func (s *Service) GetVtxoOperationView(ctx context.Context, vaultID, operationID string) (*VtxoOperationView, error) {
	if err := s.attachLedgerIntegrity(); err != nil {
		return nil, err
	}
	id, _, _, err := s.resolveSpendVaultRecord(vaultID)
	if err != nil {
		return nil, err
	}
	op, err := s.Ledger.GetVtxoOperation(ctx, operationID)
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
	if op.State == policy.VtxoStateSubmitted {
		if err := s.promoteSubmittedVtxo(ctx, op); err == nil {
			if current, loadErr := s.Ledger.GetVtxoOperation(ctx, operationID); loadErr == nil {
				op = current
			}
		}
	}
	op, err = s.expireReservedVtxo(ctx, op)
	if err != nil {
		return nil, err
	}
	view := &VtxoOperationView{
		OperationID:  op.OperationID,
		BundleDigest: hex.EncodeToString(op.BundleDigest),
		State:        op.State,
		ArkTxid:      op.ArkTxid,
		ExpiresAt:    op.ExpiresAt,
	}
	switch op.State {
	case policy.VtxoStateSigned:
		view.AuthorizedPsbt = op.AuthorizedPSBT
	case policy.VtxoStateSubmitted:
		view.AuthorizedPsbt = op.AuthorizedPSBT
		view.CheckpointPsbts = decodeJSONStringSlice(op.CheckpointPSBTs)
	}
	return view, nil
}

func (s *Service) promoteSubmittedVtxo(ctx context.Context, op policy.VtxoOperation) error {
	if op.State != policy.VtxoStateSubmitted {
		return nil
	}
	inputs, err := s.Ledger.GetVtxoOperationInputs(ctx, op.OperationID)
	if err != nil {
		return err
	}
	reserved := make([]ports.ResolvedVtxo, 0, len(inputs))
	for _, in := range inputs {
		reserved = append(reserved, ports.ResolvedVtxo{
			Txid: hex.EncodeToString(in.Txid), Vout: uint32(in.Vout), ValueSats: uint64(in.ValueSats), Script: bytes.Clone(in.Script),
		})
	}
	pkScript := op.ChangeScript
	if len(pkScript) == 0 && len(inputs) > 0 {
		pkScript = inputs[0].Script
	}
	err = s.ArkResolver.ReservedSpentByArkTxid(ctx, pkScript, reserved, op.ArkTxid)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not spent by ark txid") {
			op.State = policy.VtxoStateUnresolved
			return s.Ledger.PutVtxoOperation(ctx, op)
		}
		if strings.Contains(msg, "reserved outpoints not spent") || strings.Contains(msg, "missing from indexer") {
			return nil
		}
		return err
	}
	if len(inputs) != 1 {
		return fmt.Errorf("exact spend program requires one input")
	}
	changeSats := uint64(inputs[0].ValueSats) - uint64(op.AmountSats) - uint64(op.FeeSats)
	if err := s.ArkResolver.ChangeVtxoFromArkTx(ctx, op.ChangeScript, op.ArkTxid, 1, changeSats); err != nil {
		if strings.Contains(err.Error(), "change vtxo not yet projected") {
			return nil
		}
		return err
	}
	op.State = policy.VtxoStateFinalized
	return s.Ledger.PutVtxoOperation(ctx, op)
}

func (s *Service) AuthorizeVtxoSpend(ctx context.Context, req VtxoAuthorizeRequest) (*VtxoAuthorizeResponse, error) {
	if err := s.attachLedgerIntegrity(); err != nil {
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
	if err := s.bindVtxoAuthorization(ctx, vaultID, op.BundleDigest, AuthorizeRequest{
		VaultID: vaultID, CredentialID: req.CredentialID, ClientDataJSON: req.ClientDataJSON,
		AuthenticatorData: req.AuthenticatorData, Signature: req.Signature,
	}, req.DirectSig); err != nil {
		return nil, err
	}
	if op.State == policy.VtxoStateSigned {
		prevArk, err := parsePSBT(op.UnsignedPSBT)
		if err != nil || !unsignedPSBTEqual(prevArk, arkPkt) {
			return nil, apperr.New(apperr.CodeRejected, "changed psbt")
		}
		return &VtxoAuthorizeResponse{
			OperationID:    op.OperationID,
			BundleDigest:   hex.EncodeToString(op.BundleDigest),
			AuthorizedPsbt: op.AuthorizedPSBT,
			ArkTxid:        op.ArkTxid,
		}, nil
	}
	arkTxid := arkPkt.UnsignedTx.TxHash().String()
	op.UnsignedPSBT = req.UnsignedArkPsbt
	op.CheckpointPSBTs = encodeJSONStringSlice(req.UnsignedCheckpointPsbts)
	op.ArkTxid = arkTxid
	cosigner, err := s.deriveVtxoVaultCosigner(vaultID)
	if err != nil {
		return nil, err
	}
	expected := schnorr.SerializePubKey(cosigner.PubKey())
	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	signCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	signedArk, err := signExactArkStage(signCtx, req.UnsignedArkPsbt, cosigner, expected, tree.SpendLeaf)
	if err != nil {
		return nil, err
	}
	op.AuthorizedPSBT = signedArk
	// Persist the exact unsigned stage. The Operator reconstructs checkpoints
	// during submit, so signing these now would only create signatures that are
	// discarded before finalization.
	op.CheckpointPSBTs = encodeJSONStringSlice(req.UnsignedCheckpointPsbts)
	op.State = policy.VtxoStateSigned
	if err := s.Ledger.PutVtxoOperation(ctx, op); err != nil {
		return nil, err
	}
	return &VtxoAuthorizeResponse{
		OperationID:    op.OperationID,
		BundleDigest:   hex.EncodeToString(op.BundleDigest),
		AuthorizedPsbt: signedArk,
		ArkTxid:        arkTxid,
	}, nil
}

func (s *Service) AuthorizeVtxoCheckpoints(ctx context.Context, req VtxoCheckpointAuthorizeRequest) (*VtxoCheckpointAuthorizeResponse, error) {
	if err := s.attachLedgerIntegrity(); err != nil {
		return nil, err
	}
	if err := s.requireVaultPolicyV1Exit(); err != nil {
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
	digestHex := hex.EncodeToString(op.BundleDigest)
	if op.State == policy.VtxoStateSubmitted {
		return &VtxoCheckpointAuthorizeResponse{
			OperationID: op.OperationID, BundleDigest: digestHex,
			CheckpointPsbts: storedRaw, ArkTxid: op.ArkTxid,
		}, nil
	}
	cosigner, err := s.deriveVtxoVaultCosigner(vaultID)
	if err != nil {
		return nil, err
	}
	expected := schnorr.SerializePubKey(cosigner.PubKey())
	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	signCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	authorized := make([]string, len(req.CheckpointPsbts))
	for i, raw := range req.CheckpointPsbts {
		signed, err := signExactArkStage(signCtx, raw, cosigner, expected, tree.SpendLeaf)
		if err != nil {
			return nil, err
		}
		authorized[i] = signed
	}
	op.CheckpointPSBTs = encodeJSONStringSlice(authorized)
	op.State = policy.VtxoStateSubmitted
	if err := s.Ledger.PutVtxoOperation(ctx, op); err != nil {
		return nil, err
	}
	return &VtxoCheckpointAuthorizeResponse{
		OperationID: op.OperationID, BundleDigest: digestHex,
		CheckpointPsbts: authorized, ArkTxid: op.ArkTxid,
	}, nil
}

func (s *Service) FinalizeVtxo(ctx context.Context, req VtxoFinalizeRequest) (*VtxoFinalizeResponse, error) {
	if err := s.attachLedgerIntegrity(); err != nil {
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
	op, err := s.Ledger.GetVtxoOperation(ctx, req.OperationID)
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
	op, err = s.Ledger.GetVtxoOperation(ctx, req.OperationID)
	if err != nil {
		return nil, err
	}
	if op.State != policy.VtxoStateFinalized {
		return nil, apperr.New(apperr.CodeRejected, "reserved outpoint not spent by ark txid")
	}
	return &VtxoFinalizeResponse{OperationID: op.OperationID, BundleDigest: digestHex, State: op.State, ArkTxid: op.ArkTxid}, nil
}

func (s *Service) bindVtxoAuthorization(ctx context.Context, vaultID string, digest []byte, req AuthorizeRequest, directSigHex string) error {
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return err
	}
	defer release()
	if len(digest) != 32 {
		return apperr.New(apperr.CodeRejected, "bundle digest must be 32 bytes")
	}
	assertion, err := decodeAssertion(req)
	if err != nil {
		return err
	}
	if err := rejectPRF(assertion.ClientDataJSON); err != nil {
		return err
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return err
	}
	if cred == nil {
		return fmt.Errorf("not enrolled")
	}
	if err := s.rejectCrossVaultCredential(vaultID, cred.ID); err != nil {
		return err
	}
	verified, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID,
		WebAuthnP256: cred.WebAuthnP256,
		Challenge:    digest,
		Origin:       cred.Origin,
		RPID:         cred.RPID,
	})
	if err != nil {
		return err
	}
	if err := s.advanceSignCount(vaultID, cred.ID, verified.SignCount); err != nil {
		return err
	}
	directSig, err := decodeHex(directSigHex)
	if err != nil {
		return apperr.New(apperr.CodeRejected, "directSig")
	}
	return verifyDirectAuth(cred.PhoneDirectP256, digest, directSig)
}

func matchReservedOutpoint(seen map[string]policy.VtxoOperationInput, op wire.OutPoint) (policy.VtxoOperationInput, bool) {
	internal := make([]byte, 32)
	copy(internal, op.Hash[:])
	if in, ok := seen[outpointKey(internal, op.Index)]; ok {
		return in, true
	}
	display, err := hex.DecodeString(op.Hash.String())
	if err == nil {
		if in, ok := seen[outpointKey(display, op.Index)]; ok {
			return in, true
		}
	}
	return policy.VtxoOperationInput{}, false
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
