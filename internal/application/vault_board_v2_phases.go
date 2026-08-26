package application

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const vaultBoardV2ResultPersistTimeout = 5 * time.Second

func (s *Service) persistVaultBoardV2Submission(rec policy.VaultBoardV2Submission) error {
	ctx, cancel := context.WithTimeout(context.Background(), vaultBoardV2ResultPersistTimeout)
	defer cancel()
	_, _, err := s.VaultBoardV2Store.AppendVaultBoardV2Submission(ctx, rec)
	return err
}

func (s *Service) registerVaultBoardV2(ctx context.Context, req vaultBoardV2RegisterPhaseRequest) (vaultBoardV2RegisterResponse, error) {
	runtime, err := s.requireVaultBoardV2Runtime()
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	claims, err := s.openVaultBoardV2Handle(req.Handle, string(vaultBoardV2Ready))
	if err != nil || claims.RegisterExpireAt <= s.vtxoNow().Unix() || claims.ReceiverSats <= 0 || claims.FeeSats < 0 {
		return vaultBoardV2RegisterResponse{}, fmt.Errorf("vault-board-v2 registration handle expired or invalid")
	}
	if len(req.InputIndexes) != 2 || req.InputIndexes[0] != 0 || req.InputIndexes[1] != 1 {
		return vaultBoardV2RegisterResponse{}, fmt.Errorf("vault-board-v2 register input indexes")
	}
	ctxState, err := s.loadVaultBoardV2Context(ctx, runtime, claims.VaultID, claims.Txid, claims.Vout)
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	if err := requireVaultBoardV2MTP(ctxState.chain); err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	if ctxState.chain.Spent {
		return vaultBoardV2RegisterResponse{}, fmt.Errorf("vault-board-v2 boarding outpoint is already spent")
	}
	operation, err := s.vaultBoardV2OperationFromClaims(ctxState, claims)
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	releaseVerification, err := s.acquireVerification(ctx)
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	verified, verifyErr := verifyVaultBoardV2RegisterProof(req.PSBT, req.Message, operation, ctxState.boardTree, claims.RegisterExpireAt)
	releaseVerification()
	err = verifyErr
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	if verified.ReceiverSats != claims.ReceiverSats || verified.FeeSats != claims.FeeSats ||
		!sameIntSlice(verified.InputIndexes, req.InputIndexes) {
		return vaultBoardV2RegisterResponse{}, fmt.Errorf("vault-board-v2 register request changed after prepare")
	}
	if _, err := s.requireVaultBoardV2Fee(ctx, ctxState.record, operation.ValueSats, verified.ReceiverSats, operation.ReceiverScript); err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	storedOperation, auth, _, err := s.VaultBoardV2Store.BeginVaultBoardV2Attempt(ctx, operation, policy.VaultBoardV2RegisterRequest{
		RequestDigest: verified.RequestDigest, TreeSessionPub: verified.TreeSession,
		ReceiverSats: verified.ReceiverSats, FeeSats: verified.FeeSats, ExpireAt: verified.ExpireAt,
	}, vaultBoardV2ChainPolicy(ctxState.chain))
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	if auth.Attempt != claims.Attempt || storedOperation.OperationID != claims.OperationID || !bytes.Equal(auth.RequestDigest, verified.RequestDigest) {
		return vaultBoardV2RegisterResponse{}, fmt.Errorf("vault-board-v2 prepared attempt is no longer current")
	}
	if result, done, err := s.replayVaultBoardV2Register(ctx, auth); done || err != nil {
		return result, err
	}
	keyContext, err := newVaultBoardV2KeyContext(ctxState.vaultID, s.runtimeConfig().Network, ctxState.boardTree.OperatorPub.SerializeCompressed())
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	signing, err := newVaultBoardV2Authorization(keyContext, verified.CanonicalPSBT, ctxState.boardTree.Collaborative,
		schnorr.SerializePubKey(ctxState.boardTree.CosignerPub), verified.InputIndexes, vaultBoardV2PhaseRegister)
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	releaseVerification, err = s.acquireVerification(ctx)
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	signed, signErr := s.keys.vaultBoardV2Authorization(ctx, signing)
	releaseVerification()
	err = signErr
	if err != nil {
		return vaultBoardV2RegisterResponse{}, err
	}
	defer func() { signed = "" }()
	chain, err := revalidateVaultBoardV2Outpoint(runtime, ctxState.chain)
	if err != nil || chain.Spent || requireSameVaultBoardV2ChainFacts(*storedOperation, chain, operation.ReceiverScript) != nil || requireVaultBoardV2MTP(chain) != nil {
		return vaultBoardV2RegisterResponse{Status: vaultBoardV2DefinitelyNotSubmitted}, nil
	}
	operator, err := runtime.operatorDial(ctx)
	if err != nil {
		return vaultBoardV2RegisterResponse{Status: vaultBoardV2DefinitelyNotSubmitted}, nil
	}
	if claims.RegisterExpireAt-s.vtxoNow().Unix() < int64(vaultBoardV2DispatchMargin/time.Second) {
		return vaultBoardV2RegisterResponse{Status: vaultBoardV2DefinitelyNotSubmitted}, nil
	}
	if _, created, err := s.VaultBoardV2Store.AppendVaultBoardV2Dispatch(ctx, policy.VaultBoardV2Dispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardV2PhaseRegister,
		RequestDigest: bytes.Clone(auth.RequestDigest),
	}, vaultBoardV2ChainPolicy(chain)); err != nil {
		return vaultBoardV2RegisterResponse{Status: vaultBoardV2DefinitelyNotSubmitted}, nil
	} else if !created {
		return vaultBoardV2RegisterResponse{Status: vaultBoardV2RegisterAmbiguous}, nil
	}
	intentID, err := operator.registerIntent(ctx, signed, verified.Message)
	if err != nil {
		if !isDefiniteVaultBoardV2RegisterRejection(err) {
			return vaultBoardV2RegisterResponse{Status: vaultBoardV2RegisterAmbiguous}, nil
		}
		if persistErr := s.persistVaultBoardV2Submission(policy.VaultBoardV2Submission{
			OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardV2PhaseRegister,
			RequestDigest: bytes.Clone(auth.RequestDigest), Outcome: policy.VaultBoardV2AuthRejected,
		}); persistErr != nil {
			return vaultBoardV2RegisterResponse{Status: vaultBoardV2RegisterAmbiguous}, nil
		}
		return vaultBoardV2RegisterResponse{Status: vaultBoardV2DefinitelyNotSubmitted}, nil
	}
	if err := s.persistVaultBoardV2Submission(policy.VaultBoardV2Submission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardV2PhaseRegister,
		RequestDigest: bytes.Clone(auth.RequestDigest), Outcome: policy.VaultBoardV2AuthSubmitted, OperatorRef: intentID,
	}); err != nil {
		return vaultBoardV2RegisterResponse{Status: vaultBoardV2RegisterAmbiguous}, nil
	}
	return vaultBoardV2RegisterResponse{Status: vaultBoardV2Registered, IntentID: intentID}, nil
}

func (s *Service) replayVaultBoardV2Register(ctx context.Context, auth *policy.VaultBoardV2Authorization) (vaultBoardV2RegisterResponse, bool, error) {
	snapshot, err := s.VaultBoardV2Store.GetCurrentVaultBoardV2Attempt(ctx, auth.OperationID)
	if err != nil {
		return vaultBoardV2RegisterResponse{}, true, err
	}
	if snapshot == nil || snapshot.Register.Attempt != auth.Attempt || !bytes.Equal(snapshot.Register.RequestDigest, auth.RequestDigest) {
		return vaultBoardV2RegisterResponse{}, true, fmt.Errorf("vault-board-v2 register attempt is no longer current")
	}
	if snapshot.RegisterSubmission != nil {
		switch snapshot.RegisterSubmission.Outcome {
		case policy.VaultBoardV2AuthSubmitted:
			return vaultBoardV2RegisterResponse{Status: vaultBoardV2Registered, IntentID: snapshot.RegisterSubmission.OperatorRef}, true, nil
		case policy.VaultBoardV2AuthRejected:
			return vaultBoardV2RegisterResponse{Status: vaultBoardV2DefinitelyNotSubmitted}, true, nil
		}
	}
	if snapshot.RegisterDispatch != nil {
		return vaultBoardV2RegisterResponse{Status: vaultBoardV2RegisterAmbiguous}, true, nil
	}
	return vaultBoardV2RegisterResponse{}, false, nil
}

func (s *Service) releaseVaultBoardV2(ctx context.Context, req vaultBoardV2DeletePhaseRequest) (vaultBoardV2ReleaseResult, error) {
	runtime, err := s.requireVaultBoardV2Runtime()
	if err != nil {
		return "", err
	}
	claims, err := s.openVaultBoardV2Handle(req.Handle, string(vaultBoardV2ReleaseRequired))
	if err != nil || claims.DeleteExpireAt <= s.vtxoNow().Unix() {
		return "", fmt.Errorf("vault-board-v2 release handle expired or invalid")
	}
	if len(req.InputIndexes) != 2 || req.InputIndexes[0] != 0 || req.InputIndexes[1] != 1 {
		return "", fmt.Errorf("vault-board-v2 delete input indexes")
	}
	ctxState, err := s.loadVaultBoardV2Context(ctx, runtime, claims.VaultID, claims.Txid, claims.Vout)
	if err != nil {
		return "", err
	}
	if err := requireVaultBoardV2MTP(ctxState.chain); err != nil {
		return "", err
	}
	if ctxState.chain.Spent {
		return vaultBoardV2ReleaseAmbiguous, nil
	}
	operation, err := s.vaultBoardV2OperationFromClaims(ctxState, claims)
	if err != nil {
		return "", err
	}
	snapshot, err := s.VaultBoardV2Store.GetCurrentVaultBoardV2Attempt(ctx, claims.OperationID)
	if err != nil || snapshot == nil || snapshot.Register.Attempt != claims.Attempt {
		return "", fmt.Errorf("vault-board-v2 release attempt is no longer current")
	}
	releaseVerification, err := s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	verified, verifyErr := verifyVaultBoardV2DeleteProof(req.PSBT, req.Message, operation, ctxState.boardTree, claims.DeleteExpireAt)
	releaseVerification()
	err = verifyErr
	if err != nil {
		return "", fmt.Errorf("vault-board-v2 delete proof: %w", err)
	}
	if !sameIntSlice(verified.InputIndexes, req.InputIndexes) {
		return "", fmt.Errorf("vault-board-v2 delete input indexes changed")
	}
	authRequest := policy.VaultBoardV2Authorization{
		OperationID: claims.OperationID, Attempt: claims.Attempt, Phase: policy.VaultBoardV2PhaseDelete,
		RequestDigest: bytes.Clone(verified.RequestDigest), ExpireAt: verified.ExpireAt,
	}
	if snapshot.DeleteSubmission != nil {
		return vaultBoardV2Released, nil
	}
	if snapshot.DeleteDispatch != nil {
		return vaultBoardV2ReleaseAmbiguous, nil
	}
	keyContext, err := newVaultBoardV2KeyContext(ctxState.vaultID, s.runtimeConfig().Network, ctxState.boardTree.OperatorPub.SerializeCompressed())
	if err != nil {
		return "", err
	}
	signing, err := newVaultBoardV2Authorization(keyContext, verified.CanonicalPSBT, ctxState.boardTree.Collaborative,
		schnorr.SerializePubKey(ctxState.boardTree.CosignerPub), verified.InputIndexes, vaultBoardV2PhaseDelete)
	if err != nil {
		return "", err
	}
	releaseVerification, err = s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	signed, signErr := s.keys.vaultBoardV2Authorization(ctx, signing)
	releaseVerification()
	err = signErr
	if err != nil {
		return "", err
	}
	defer func() { signed = "" }()
	chain, err := revalidateVaultBoardV2Outpoint(runtime, ctxState.chain)
	if err != nil || chain.Spent || requireSameVaultBoardV2ChainFacts(operation, chain, operation.ReceiverScript) != nil || requireVaultBoardV2MTP(chain) != nil {
		return vaultBoardV2ReleaseAmbiguous, nil
	}
	operator, err := runtime.operatorDial(ctx)
	if err != nil {
		return vaultBoardV2ReleaseAmbiguous, nil
	}
	if claims.DeleteExpireAt-s.vtxoNow().Unix() < int64(vaultBoardV2DispatchMargin/time.Second) {
		return "", fmt.Errorf("vault-board-v2 release proof expires too soon")
	}
	auth, _, created, err := s.VaultBoardV2Store.AppendVaultBoardV2AuthorizationAndDispatch(ctx, authRequest, vaultBoardV2ChainPolicy(chain))
	if err != nil || !created {
		return vaultBoardV2ReleaseAmbiguous, nil
	}
	if err := operator.deleteIntent(ctx, signed, verified.Message); err != nil {
		return vaultBoardV2ReleaseAmbiguous, nil
	}
	if err := s.persistVaultBoardV2Submission(policy.VaultBoardV2Submission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardV2PhaseDelete,
		RequestDigest: bytes.Clone(auth.RequestDigest), Outcome: policy.VaultBoardV2AuthReleased,
	}); err != nil {
		return vaultBoardV2ReleaseAmbiguous, nil
	}
	return vaultBoardV2Released, nil
}

func (s *Service) submitVaultBoardV2Commitment(ctx context.Context, req vaultBoardV2FinalPhaseRequest) (vaultBoardV2CommitmentResult, error) {
	runtime, err := s.requireVaultBoardV2Runtime()
	if err != nil {
		return "", err
	}
	if runtime.batchExpiry == 0 {
		return "", fmt.Errorf("vault-board-v2 batch expiry release pin unavailable")
	}
	claims, err := s.openVaultBoardV2Handle(req.Handle, string(vaultBoardV2Ready))
	if err != nil {
		return "", err
	}
	if len(req.SignedForfeits) != 0 || len(req.InputIndexes) != 1 || req.InputIndexes[0] < 0 ||
		req.PSBT != req.Batch.SignedCommitmentPSBT || !sameIntSlice(req.InputIndexes, req.Batch.InputIndexes) {
		return "", fmt.Errorf("vault-board-v2 one-input commitment required")
	}
	ctxState, err := s.loadVaultBoardV2Context(ctx, runtime, claims.VaultID, claims.Txid, claims.Vout)
	if err != nil {
		return "", err
	}
	if err := requireVaultBoardV2MTP(ctxState.chain); err != nil {
		return "", err
	}
	if ctxState.chain.Spent {
		return vaultBoardV2CommitmentAmbiguous, nil
	}
	operation, err := s.vaultBoardV2OperationFromClaims(ctxState, claims)
	if err != nil {
		return "", err
	}
	snapshot, err := s.VaultBoardV2Store.GetCurrentVaultBoardV2Attempt(ctx, claims.OperationID)
	if err != nil || snapshot == nil || snapshot.Register.Attempt != claims.Attempt || snapshot.RegisterSubmission == nil ||
		snapshot.RegisterSubmission.Outcome != policy.VaultBoardV2AuthSubmitted {
		return "", fmt.Errorf("vault-board-v2 accepted register attempt required")
	}
	releaseVerification, err := s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	verified, verifyErr := verifyVaultBoardV2Final(req.Batch, operation, snapshot.Register, ctxState.boardTree, vaultBoardV2FinalExpiry(runtime.batchExpiry))
	releaseVerification()
	err = verifyErr
	if err != nil {
		return "", err
	}
	authRequest := policy.VaultBoardV2Authorization{
		OperationID: claims.OperationID, Attempt: claims.Attempt, Phase: policy.VaultBoardV2PhaseFinalize,
		RequestDigest: bytes.Clone(verified.RequestDigest), CommitmentTxid: verified.CommitmentTxid,
		ReceiverTxid: verified.ReceiverTxid, ReceiverVout: verified.ReceiverVout,
	}
	if snapshot.FinalSubmission != nil {
		return vaultBoardV2CommitmentSubmitted, nil
	}
	if snapshot.FinalDispatch != nil {
		return vaultBoardV2CommitmentAmbiguous, nil
	}
	keyContext, err := newVaultBoardV2KeyContext(ctxState.vaultID, s.runtimeConfig().Network, ctxState.boardTree.OperatorPub.SerializeCompressed())
	if err != nil {
		return "", err
	}
	signing, err := newVaultBoardV2Authorization(keyContext, verified.CanonicalPSBT, ctxState.boardTree.Collaborative,
		schnorr.SerializePubKey(ctxState.boardTree.CosignerPub), []int{verified.InputIndex}, vaultBoardV2PhaseFinalize)
	if err != nil {
		return "", err
	}
	releaseVerification, err = s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	signed, signErr := s.keys.vaultBoardV2Authorization(ctx, signing)
	releaseVerification()
	err = signErr
	if err != nil {
		return "", err
	}
	defer func() { signed = "" }()
	chain, err := revalidateVaultBoardV2Outpoint(runtime, ctxState.chain)
	if err != nil || chain.Spent || requireSameVaultBoardV2ChainFacts(operation, chain, operation.ReceiverScript) != nil || requireVaultBoardV2MTP(chain) != nil {
		return vaultBoardV2CommitmentAmbiguous, nil
	}
	operator, err := runtime.operatorDial(ctx)
	if err != nil {
		return vaultBoardV2CommitmentAmbiguous, nil
	}
	auth, _, created, err := s.VaultBoardV2Store.AppendVaultBoardV2AuthorizationAndDispatch(ctx, authRequest, vaultBoardV2ChainPolicy(chain))
	if err != nil || !created {
		return vaultBoardV2CommitmentAmbiguous, nil
	}
	if err := operator.submitCommitment(ctx, signed); err != nil {
		return vaultBoardV2CommitmentAmbiguous, nil
	}
	if err := s.persistVaultBoardV2Submission(policy.VaultBoardV2Submission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardV2PhaseFinalize,
		RequestDigest: bytes.Clone(auth.RequestDigest), Outcome: policy.VaultBoardV2AuthSubmitted,
		CommitmentTxid: verified.CommitmentTxid, ReceiverTxid: verified.ReceiverTxid, ReceiverVout: verified.ReceiverVout,
	}); err != nil {
		return vaultBoardV2CommitmentAmbiguous, nil
	}
	return vaultBoardV2CommitmentSubmitted, nil
}

func sameIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
