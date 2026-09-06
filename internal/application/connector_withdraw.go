package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/brg444/arkade-runtime/internal/apperr"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	maxConnectorWithdrawalsPerVaultPerMinute = 10
	connectorWithdrawRateWindow              = time.Minute
)

// ConnectorWithdrawRequest is one phone-signed connector candidate plus the
// candidate-bound passkey session. The wallet persists the exact phone-signed
// PSBT before dispatch and resubmits those bytes verbatim after a lost
// response or reload; a fresh challenge authenticates the same candidate.
type ConnectorWithdrawRequest struct {
	VaultID string `json:"vaultId"`
	PSBT    string `json:"psbt"`
	SessionAssertionRequest
}

// ConnectorWithdrawResponse carries the Guardian and Emulator stages for the
// retained candidate. Replay is true when the durable operation already
// existed; the operation ID is stable for exact retries and lost responses.
type ConnectorWithdrawResponse struct {
	SignedPSBT  string `json:"signedPsbt"`
	Replay      bool   `json:"replay"`
	OperationID string `json:"operationId"`
}

// ConnectorOperationView is the capability-bound status of one connector
// operation: vault ownership plus the unguessable operation ID. Reconciliation
// touches only the asked operation. Verified reports whether the returned
// resolution was re-proved against the release-pinned chain in this call: a
// terminal resolution with verified=false is retained history that the chain
// could not revalidate (outage or ambiguity), never fresh proof.
type ConnectorOperationView struct {
	OperationID   string `json:"operationId"`
	Phase         string `json:"phase"`
	Resolution    string `json:"resolution"`
	CandidateTxid string `json:"candidateTxid"`
	SignedPSBT    string `json:"signedPsbt,omitempty"`
	Verified      bool   `json:"verified"`
}

// AuthorizeConnectorWithdrawal validates, durably authorizes, and cosigns one
// Savings connector withdrawal. Service order: ledger integrity, MAC-verified
// credential plus origin, enrolled family rebuild, pure candidate validation,
// terminal-history revalidation plus confirmed and unspent checks for both
// parents, rate limit, candidate-bound passkey authentication, exact
// write-ahead authorization, Guardian stage, Emulator stage. No signing call
// happens before the durable authorization and sequence advancement, and no
// Spending allowance is debited: only Savings amount, dust, fee, and anchor
// rules apply.
func (s *Service) AuthorizeConnectorWithdrawal(ctx context.Context, req ConnectorWithdrawRequest) (*ConnectorWithdrawResponse, error) {
	vaultID, err := s.routeVaultID(req.VaultID)
	if err != nil {
		return nil, err
	}
	if len(req.PSBT) == 0 || len(req.PSBT) > 131072 {
		return nil, fmt.Errorf("connector candidate required")
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return nil, err
	}
	if !isConnectorCredential(cred) {
		return nil, fmt.Errorf("connector vault required")
	}
	candidate, err := parsePSBT(req.PSBT)
	if err != nil {
		return nil, err
	}
	candidateTxid := candidate.UnsignedTx.TxHash().String()
	fam, err := s.rebuildConnectorFamily(cred)
	if err != nil {
		return nil, err
	}
	phone, _, _, vaultBase, arkadeBase, err := parseConnectorCredentialKeys(cred)
	if err != nil {
		return nil, err
	}
	auth, err := newConnectorGuardianAuthorization(phone, vaultBase, arkadeBase, fam.Control, fam.Rules.ConnectorScript, fam.Rules)
	if err != nil {
		return nil, err
	}
	// Pure validation before any durable write or key use.
	if _, err := validateConnectorGuardianCandidate(req.PSBT, auth); err != nil {
		return nil, err
	}
	savingsOutpoint := candidate.UnsignedTx.TxIn[connector.SavingsInput].PreviousOutPoint
	connectorOutpoint := candidate.UnsignedTx.TxIn[connector.ConnectorInput].PreviousOutPoint
	dest := candidate.UnsignedTx.TxOut[0].PkScript
	amount := candidate.UnsignedTx.TxOut[0].Value
	fee, err := connectorCandidateFee(candidate)
	if err != nil {
		return nil, err
	}
	sighash, err := connectorCandidateSighash(candidate, auth.spendLeaf)
	if err != nil {
		return nil, err
	}
	chain, err := s.connectorChainViewFor(ctx)
	if err != nil {
		return nil, err
	}
	// Terminal history revalidates against the current chain view before a
	// formerly conflicting authorization is permitted; stored labels alone
	// never authorize reuse after a reorg.
	if err := s.revalidateConnectorHistory(ctx, chain, vaultID, strings.ToLower(savingsOutpoint.Hash.String()), savingsOutpoint.Index, strings.ToLower(connectorOutpoint.Hash.String()), connectorOutpoint.Index); err != nil {
		return nil, mapConnectorBusy(err)
	}
	// An exact replay of an already-authorized candidate must resume after
	// broadcast, when both parents are spent by the candidate itself. The
	// unconditional unspent check below would block that resume, so a
	// byte-identical active operation whose parents are unspent or spent by
	// the same candidate bypasses the fresh-authorization checks. Nothing is
	// released before candidate-bound passkey authentication below, and the
	// durable replay still governs before any stage is produced.
	replayed, err := s.findExactConnectorReplay(ctx, chain, vaultID, req.PSBT, candidate, candidateTxid, sighash)
	if err != nil {
		return nil, err
	}
	if replayed == nil {
		if err := s.verifyConnectorParents(ctx, chain, candidate, cred, fam); err != nil {
			return nil, err
		}
		if err := s.allowConnectorWithdraw(vaultID); err != nil {
			return nil, err
		}
	}
	if _, err := s.authenticateConnectorWithdrawSession(ctx, vaultID, req.SessionAssertionRequest, candidateTxid); err != nil {
		return nil, err
	}
	operationID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	action, stored, err := s.Stores.Connector.ApplyConnectorReplay(policy.ConnectorOperation{
		OperationID: strings.ToLower(operationID), VaultID: vaultID,
		SavingsTxid: strings.ToLower(savingsOutpoint.Hash.String()), SavingsVout: savingsOutpoint.Index,
		ConnectorTxid: strings.ToLower(connectorOutpoint.Hash.String()), ConnectorVout: connectorOutpoint.Index,
		DestScript: hex.EncodeToString(dest), AmountSats: amount, FeeSats: fee,
		ConnectorScript: append([]byte(nil), fam.Rules.ConnectorScript...),
		CandidatePSBT:   req.PSBT, LastSighash: sighash,
	})
	if err != nil {
		return nil, mapConnectorBusy(err)
	}
	// Sign the retained row bytes, never the request copy: on exact replay
	// they are identical, and after a crash the missing stages are reproduced
	// for the same candidate instead of authorizing a changed one.
	completed, err := s.completeConnectorStages(ctx, stored, auth)
	if err != nil {
		return nil, err
	}
	return &ConnectorWithdrawResponse{
		SignedPSBT: completed.EmulatorPSBT, Replay: action == policy.ConnectorReplayReplay, OperationID: completed.OperationID,
	}, nil
}

// findExactConnectorReplay returns the active operation for a byte-identical
// resubmission of an already-authorized candidate, or nil when this request
// needs fresh authorization. The replay is safe only while both parents are
// unspent or spent by the same candidate: parents spent by another
// transaction, or unreadable chain state, fall back to the fresh path, which
// refuses with the usual spent/unconfirmed errors. Terminal rows never replay:
// a confirmed or conflicted candidate's stages are read through GET, and a
// changed candidate for owned inputs stays refused by the durable replay.
func (s *Service) findExactConnectorReplay(ctx context.Context, chain connectorChainView, vaultID, rawPSBT string, candidate *psbt.Packet, candidateTxid, sighash string) (*policy.ConnectorOperation, error) {
	if candidate == nil || candidate.UnsignedTx == nil || len(candidate.UnsignedTx.TxIn) != 2 {
		return nil, nil
	}
	savingsIn := candidate.UnsignedTx.TxIn[connector.SavingsInput].PreviousOutPoint
	connectorIn := candidate.UnsignedTx.TxIn[connector.ConnectorInput].PreviousOutPoint
	conflicts, err := s.Stores.Connector.ListConnectorConflicts(vaultID,
		strings.ToLower(savingsIn.Hash.String()), savingsIn.Index,
		strings.ToLower(connectorIn.Hash.String()), connectorIn.Index)
	if err != nil {
		return nil, err
	}
	for _, row := range conflicts {
		if row == nil || row.VaultID != vaultID || row.Resolution != policy.ConnectorResolutionNone {
			continue
		}
		if row.CandidatePSBT != rawPSBT || row.LastSighash != sighash {
			continue
		}
		for _, in := range []wire.OutPoint{savingsIn, connectorIn} {
			state, err := chain.confirmedOutpoint(ctx, strings.ToLower(in.Hash.String()), in.Index)
			if err != nil {
				return nil, nil
			}
			if state.Spent && (state.SpendingTxid == "" || !strings.EqualFold(state.SpendingTxid, candidateTxid)) {
				return nil, nil
			}
		}
		return row, nil
	}
	return nil, nil
}

// completeConnectorStages produces any missing signing stages for the retained
// operation in Guardian-then-Emulator order and persists each exact stage.
func (s *Service) completeConnectorStages(ctx context.Context, stored *policy.ConnectorOperation, auth connectorGuardianAuthorization) (*policy.ConnectorOperation, error) {
	if stored == nil {
		return nil, fmt.Errorf("connector operation required")
	}
	op := stored
	if op.GuardianPSBT == "" {
		_, _, rec, err := s.resolveSpendVaultRecord(op.VaultID)
		if err != nil {
			return nil, err
		}
		authorization, err := newConnectorWithdrawalAuthorization(rec, op.CandidatePSBT, auth)
		if err != nil {
			return nil, err
		}
		guardianStage, err := s.keys.authorizeConnectorWithdrawal(ctx, authorization)
		if err != nil {
			return nil, err
		}
		op, err = s.Stores.Connector.StoreConnectorStage(op.OperationID, policy.ConnectorPhaseGuardianSigned, guardianStage)
		if err != nil {
			return nil, err
		}
	}
	if op.EmulatorPSBT == "" {
		emulatorStage, err := s.keys.authorizeConnectorEmulatorStage(ctx, publicEmulatorConnectorStage{
			guardianSignedPSBT: op.GuardianPSBT,
			expectedXOnly:      append([]byte(nil), auth.emulatorExpectedXOnly...),
			expectedLeaf:       append([]byte(nil), auth.spendLeaf...),
		})
		if err != nil {
			return nil, err
		}
		op, err = s.Stores.Connector.StoreConnectorStage(op.OperationID, policy.ConnectorPhaseEmulatorSigned, emulatorStage)
		if err != nil {
			return nil, err
		}
	}
	return op, nil
}

// GetConnectorOperationView returns the reconciled status of exactly the asked
// operation. Vault ownership plus the unguessable operation ID is the read
// capability; outpoint guessing never resolves an operation.
func (s *Service) GetConnectorOperationView(ctx context.Context, vaultID, operationID string) (*ConnectorOperationView, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	id, err := s.routeVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := s.resolveSpendVaultRecord(id); err != nil {
		return nil, err
	}
	op, err := s.Stores.Connector.GetConnectorOperation(operationID)
	if err != nil {
		return nil, err
	}
	if op == nil {
		return nil, apperr.ErrNotFound
	}
	if op.VaultID != id {
		return nil, apperr.New(apperr.CodeRejected, "operation does not belong to this vault")
	}
	op, verified := s.reconcileConnectorOperation(ctx, op)
	candidate, err := parsePSBT(op.CandidatePSBT)
	if err != nil {
		return nil, err
	}
	view := &ConnectorOperationView{
		OperationID: op.OperationID, Phase: op.Phase, Resolution: op.Resolution,
		CandidateTxid: candidate.UnsignedTx.TxHash().String(), Verified: verified,
	}
	if op.EmulatorPSBT != "" {
		view.SignedPSBT = op.EmulatorPSBT
	} else if op.GuardianPSBT != "" {
		view.SignedPSBT = op.GuardianPSBT
	}
	return view, nil
}

// reconcileConnectorOperation advances exactly one row on positive chain
// proof and never on ambiguity. Chain errors, unconfirmed spenders, and
// missing parents leave the row untouched: an HTTP 404, timeout, elapsed
// timer, or absent mempool entry is not confirmation of failure, and history
// rows are never deleted. The verified flag reports whether the returned
// resolution was re-proved against the current chain view in this call, so
// callers never mistake retained-but-unrevalidated terminal history for fresh
// proof after a chain outage.
func (s *Service) reconcileConnectorOperation(ctx context.Context, op *policy.ConnectorOperation) (*policy.ConnectorOperation, bool) {
	if op == nil {
		return nil, false
	}
	chain, err := s.connectorChainViewFor(ctx)
	if err != nil {
		return op, false
	}
	candidate, err := parsePSBT(op.CandidatePSBT)
	if err != nil {
		return op, false
	}
	candidateTxid := candidate.UnsignedTx.TxHash().String()
	savingsState, savingsErr := chain.confirmedOutpoint(ctx, strings.ToLower(op.SavingsTxid), op.SavingsVout)
	connectorState, connectorErr := chain.confirmedOutpoint(ctx, strings.ToLower(op.ConnectorTxid), op.ConnectorVout)
	// Terminal rows re-prove their stored evidence on every call. A reorg
	// that invalidates the stored proof restores the unresolved state instead
	// of trusting a label; a chain error that prevents revalidation retains
	// the row but reports it unverified instead of trusting it silently.
	if op.Resolution != policy.ConnectorResolutionNone {
		if savingsErr != nil || connectorErr != nil {
			return op, false
		}
		valid, stale := s.connectorTerminalEvidenceStatus(ctx, chain, op, savingsState, connectorState)
		if valid {
			return op, true
		}
		if !stale {
			return op, false
		}
		if rolled, err := s.Stores.Connector.ResolveConnectorOperation(op.OperationID, policy.ConnectorChainEvidence{
			Resolution: policy.ConnectorResolutionNone,
		}); err == nil && rolled != nil {
			op = rolled
		} else {
			return op, false
		}
		// Fall through and re-observe the rolled-back row against the fresh
		// parent states below.
	} else if savingsErr != nil || connectorErr != nil {
		// Ambiguous observation (reorg mid-query, unknown funding): only a
		// candidate confirmation may still proceed, on canonical proof alone.
		if blockHash, height, err := chain.confirmedTransaction(ctx, candidateTxid); err == nil {
			if resolved, err := s.Stores.Connector.ResolveConnectorOperation(op.OperationID, policy.ConnectorChainEvidence{
				Resolution: policy.ConnectorResolutionConfirmed, ResolutionTxid: candidateTxid,
				ResolutionBlockHash: blockHash, ResolutionBlockHeight: height,
			}); err == nil && resolved != nil {
				return resolved, true
			}
		}
		return op, false
	}
	spentByOther := ""
	for _, state := range []connectorOutpointState{savingsState, connectorState} {
		if state.Spent && state.SpendingTxid != "" && !strings.EqualFold(state.SpendingTxid, candidateTxid) {
			spentByOther = state.SpendingTxid
		}
	}
	if spentByOther != "" {
		// A conflicting spend resolves only on canonical confirmation proof
		// of the actual spender: funding confirmation plus spend observation
		// alone never suffices.
		if blockHash, height, err := chain.confirmedTransaction(ctx, spentByOther); err == nil {
			if resolved, err := s.Stores.Connector.ResolveConnectorOperation(op.OperationID, policy.ConnectorChainEvidence{
				Resolution: policy.ConnectorResolutionConflict, ResolutionTxid: strings.ToLower(spentByOther),
				ResolutionBlockHash: blockHash, ResolutionBlockHeight: height,
			}); err == nil && resolved != nil {
				return resolved, true
			}
		}
		return op, true
	}
	// No conflicting spender is observed: both parents are unspent, or one or
	// both are spent by the candidate itself while its confirmation is still
	// in flight. Either way only canonical confirmation of the candidate
	// resolves; an input spent by the candidate without confirmation proof is
	// a broadcast in flight, never a resolution.
	if blockHash, height, err := chain.confirmedTransaction(ctx, candidateTxid); err == nil {
		if resolved, err := s.Stores.Connector.ResolveConnectorOperation(op.OperationID, policy.ConnectorChainEvidence{
			Resolution: policy.ConnectorResolutionConfirmed, ResolutionTxid: candidateTxid,
			ResolutionBlockHash: blockHash, ResolutionBlockHeight: height,
		}); err == nil && resolved != nil {
			return resolved, true
		}
	}
	return op, true
}

// connectorTerminalEvidenceStatus re-proves stored terminal evidence against
// the current chain view. It reports (valid, stale): valid means the recorded
// transaction is still canonically confirmed and still spends the inputs it
// must; stale means positive proof that it no longer does (reorg). A chain
// error is neither: (false, false) retains the row without trusting it.
func (s *Service) connectorTerminalEvidenceStatus(ctx context.Context, chain connectorChainView, op *policy.ConnectorOperation, savingsState, connectorState connectorOutpointState) (valid, stale bool) {
	if op == nil || op.Resolution == policy.ConnectorResolutionNone || op.ResolutionTxid == "" {
		return false, false
	}
	if _, _, err := chain.confirmedTransaction(ctx, op.ResolutionTxid); err != nil {
		return false, errors.Is(err, errConnectorTransactionUnconfirmed)
	}
	if op.Resolution == policy.ConnectorResolutionConfirmed {
		return true, false
	}
	want := strings.ToLower(op.ResolutionTxid)
	if (savingsState.Spent && strings.ToLower(savingsState.SpendingTxid) == want) ||
		(connectorState.Spent && strings.ToLower(connectorState.SpendingTxid) == want) {
		return true, false
	}
	return false, true
}

// revalidateConnectorHistory permits a new authorization touching formerly
// terminal inputs only while every terminal row's evidence still validates
// against the current chain view. Stale terminal rows roll back to unresolved
// first, which makes the inputs actively owned again and refuses the changed
// candidate: the owner retries the exact old candidate instead.
func (s *Service) revalidateConnectorHistory(ctx context.Context, chain connectorChainView, vaultID, savingsTxid string, savingsVout uint32, connectorTxid string, connectorVout uint32) error {
	conflicts, err := s.Stores.Connector.ListConnectorConflicts(vaultID, savingsTxid, savingsVout, connectorTxid, connectorVout)
	if err != nil {
		return err
	}
	for _, row := range conflicts {
		if row == nil || row.Resolution == policy.ConnectorResolutionNone {
			continue
		}
		savingsState, savingsErr := chain.confirmedOutpoint(ctx, strings.ToLower(row.SavingsTxid), row.SavingsVout)
		connectorState, connectorErr := chain.confirmedOutpoint(ctx, strings.ToLower(row.ConnectorTxid), row.ConnectorVout)
		if savingsErr != nil || connectorErr != nil {
			// Ambiguous: the terminal row is retained, but its evidence is
			// not revalidated, so reuse stays blocked. Errors never prove a
			// reorg and never silently free the inputs.
			return policy.ErrConnectorBusy
		}
		valid, stale := s.connectorTerminalEvidenceStatus(ctx, chain, row, savingsState, connectorState)
		if valid {
			continue
		}
		if stale {
			// Positive staleness proof: roll back before refusing, so the
			// inputs are actively owned and the exact old candidate governs.
			_, _ = s.Stores.Connector.ResolveConnectorOperation(row.OperationID, policy.ConnectorChainEvidence{
				Resolution: policy.ConnectorResolutionNone,
			})
		}
		return policy.ErrConnectorBusy
	}
	return nil
}

// verifyConnectorParents requires both parents confirmed, unspent, and equal
// to the enrolled contract and the candidate's own prevout claims. Parent
// bytes alone never suffice: values and scripts revalidate against chain.
func (s *Service) verifyConnectorParents(ctx context.Context, chain connectorChainView, candidate *psbt.Packet, cred *policy.Credential, fam *connector.Family) error {
	if len(candidate.UnsignedTx.TxIn) != 2 || len(candidate.Inputs) != 2 {
		return fmt.Errorf("connector transaction requires exactly two inputs")
	}
	savingsIn := candidate.UnsignedTx.TxIn[connector.SavingsInput].PreviousOutPoint
	connectorIn := candidate.UnsignedTx.TxIn[connector.ConnectorInput].PreviousOutPoint
	savingsState, err := chain.confirmedOutpoint(ctx, strings.ToLower(savingsIn.Hash.String()), savingsIn.Index)
	if err != nil {
		return fmt.Errorf("connector Savings parent is not confirmed")
	}
	if savingsState.Spent {
		return fmt.Errorf("connector Savings parent is spent")
	}
	if !bytes.Equal(savingsState.PkScript, cred.SavingsScript) ||
		!bytes.Equal(savingsState.PkScript, candidate.Inputs[connector.SavingsInput].WitnessUtxo.PkScript) ||
		savingsState.ValueSats != candidate.Inputs[connector.SavingsInput].WitnessUtxo.Value {
		return fmt.Errorf("connector Savings parent mismatch")
	}
	connectorState, err := chain.confirmedOutpoint(ctx, strings.ToLower(connectorIn.Hash.String()), connectorIn.Index)
	if err != nil {
		return fmt.Errorf("connector reserve parent is not confirmed")
	}
	if connectorState.Spent {
		return fmt.Errorf("connector reserve parent is spent")
	}
	if connectorState.ValueSats != connector.ReserveSats ||
		!bytes.Equal(connectorState.PkScript, fam.Rules.ConnectorScript) ||
		!bytes.Equal(connectorState.PkScript, candidate.Inputs[connector.ConnectorInput].WitnessUtxo.PkScript) ||
		connectorState.ValueSats != candidate.Inputs[connector.ConnectorInput].WitnessUtxo.Value {
		return fmt.Errorf("connector reserve parent mismatch")
	}
	return nil
}

// connectorCandidateFee recomputes the candidate fee from its own prevouts and
// outputs. Bounds stay with connector.Validate during pure validation; the
// ledger stores the recomputed value.
func connectorCandidateFee(candidate *psbt.Packet) (int64, error) {
	if candidate == nil || candidate.UnsignedTx == nil || len(candidate.Inputs) != 2 {
		return 0, fmt.Errorf("connector candidate required")
	}
	var in, out int64
	for i := range candidate.Inputs {
		prev := candidate.Inputs[i].WitnessUtxo
		if prev == nil || prev.Value < 0 {
			return 0, fmt.Errorf("connector parent value")
		}
		in += prev.Value
	}
	for _, txOut := range candidate.UnsignedTx.TxOut {
		if txOut == nil || txOut.Value < 0 {
			return 0, fmt.Errorf("connector output value")
		}
		out += txOut.Value
	}
	if out > in {
		return 0, fmt.Errorf("connector fee is negative")
	}
	return in - out, nil
}

// connectorCandidateSighash binds the ledger row to the exact Savings input
// commitment the cosigners sign: the DEFAULT tapscript sighash over the
// enrolled normal leaf, committed against BOTH actual parents. The fetcher
// must carry the real connector-reserve prevout as well as the Savings
// prevout: a canned single-prevout fetcher would compute a different
// commitment than the phone and Savings signatures actually sign.
func connectorCandidateSighash(candidate *psbt.Packet, leaf []byte) (string, error) {
	if candidate == nil || len(candidate.Inputs) != 2 || candidate.Inputs[connector.SavingsInput].WitnessUtxo == nil {
		return "", fmt.Errorf("connector candidate required")
	}
	parents, err := requireConnectorPrevouts(candidate)
	if err != nil {
		return "", err
	}
	raw, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(candidate.UnsignedTx, parents),
		txscript.SigHashDefault, candidate.UnsignedTx, connector.SavingsInput, parents, txscript.NewBaseTapLeaf(leaf),
	)
	if err != nil {
		return "", fmt.Errorf("connector sighash: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func (s *Service) connectorChainViewFor(ctx context.Context) (connectorChainView, error) {
	_ = ctx
	if s != nil && s.connectorChain != nil {
		return s.connectorChain, nil
	}
	if s == nil {
		return nil, fmt.Errorf("connector chain required")
	}
	return dialConnectorChain(s.runtimeConfig().Network)
}

func (s *Service) allowConnectorWithdraw(vaultID string) error {
	now := time.Now()
	if s.EnrollmentNow != nil {
		now = s.EnrollmentNow()
	}
	s.connectorWithdrawRateMu.Lock()
	defer s.connectorWithdrawRateMu.Unlock()
	if s.connectorWithdrawRateHits == nil {
		s.connectorWithdrawRateHits = make(map[string][]time.Time)
	}
	hits := s.connectorWithdrawRateHits[vaultID]
	cut := now.Add(-connectorWithdrawRateWindow)
	kept := hits[:0]
	for _, ts := range hits {
		if ts.After(cut) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= maxConnectorWithdrawalsPerVaultPerMinute {
		s.connectorWithdrawRateHits[vaultID] = kept
		return fmt.Errorf("too many connector withdrawals")
	}
	s.connectorWithdrawRateHits[vaultID] = append(kept, now)
	return nil
}

func mapConnectorBusy(err error) error {
	if errors.Is(err, policy.ErrConnectorBusy) {
		return apperr.ErrBusy
	}
	return mapLedgerBusy(err)
}
