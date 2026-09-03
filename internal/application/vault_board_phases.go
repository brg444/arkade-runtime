package application

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const vaultBoardResultPersistTimeout = 5 * time.Second

func (s *Service) persistVaultBoardSubmission(rec policy.VaultBoardSubmission) error {
	ctx, cancel := context.WithTimeout(context.Background(), vaultBoardResultPersistTimeout)
	defer cancel()
	_, _, err := s.Stores.VaultBoard.AppendVaultBoardSubmission(ctx, rec)
	return err
}

func (s *Service) registerVaultBoard(ctx context.Context, req vaultBoardRegisterPhaseRequest) (vaultBoardRegisterResponse, error) {
	runtime, err := s.requireVaultBoardRuntime()
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	claims, err := s.openVaultBoardHandle(req.Handle, string(vaultBoardReady))
	if err != nil || claims.RegisterExpireAt <= s.vtxoNow().Unix() || claims.ReceiverSats <= 0 || claims.FeeSats < 0 {
		return vaultBoardRegisterResponse{}, fmt.Errorf("vault-board-v1 registration handle expired or invalid")
	}
	if len(req.InputIndexes) != 2 || req.InputIndexes[0] != 0 || req.InputIndexes[1] != 1 {
		return vaultBoardRegisterResponse{}, fmt.Errorf("vault-board-v1 register input indexes")
	}
	ctxState, err := s.loadVaultBoardContext(ctx, runtime, claims.VaultID, claims.Txid, claims.Vout)
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	if err := requireVaultBoardMTP(ctxState.chain, s.boardExitDelay()); err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	if ctxState.chain.Spent {
		return vaultBoardRegisterResponse{}, fmt.Errorf("vault-board-v1 boarding outpoint is already spent")
	}
	operation, err := s.vaultBoardOperationFromClaims(ctxState, claims)
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	releaseVerification, err := s.acquireVerification(ctx)
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	verified, verifyErr := verifyVaultBoardRegisterProof(req.PSBT, req.Message, operation, ctxState.boardTree, claims.RegisterExpireAt)
	releaseVerification()
	err = verifyErr
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	if verified.ReceiverSats != claims.ReceiverSats || verified.FeeSats != claims.FeeSats ||
		!sameIntSlice(verified.InputIndexes, req.InputIndexes) {
		return vaultBoardRegisterResponse{}, fmt.Errorf("vault-board-v1 register request changed after prepare")
	}
	if _, err := s.requireVaultBoardFee(ctx, ctxState.record, operation.ValueSats, verified.ReceiverSats, operation.ReceiverScript); err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	storedOperation, auth, _, err := s.Stores.VaultBoard.BeginVaultBoardAttempt(ctx, operation, policy.VaultBoardRegisterRequest{
		RequestDigest: verified.RequestDigest, TreeSessionPub: verified.TreeSession,
		ReceiverSats: verified.ReceiverSats, FeeSats: verified.FeeSats, ExpireAt: verified.ExpireAt,
	}, vaultBoardChainPolicy(ctxState.chain))
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	if auth.Attempt != claims.Attempt || storedOperation.OperationID != claims.OperationID || !bytes.Equal(auth.RequestDigest, verified.RequestDigest) {
		return vaultBoardRegisterResponse{}, fmt.Errorf("vault-board-v1 prepared attempt is no longer current")
	}
	if result, done, err := s.replayVaultBoardRegister(ctx, auth); done || err != nil {
		return result, err
	}
	keyContext, err := newVaultBoardKeyContext(ctxState.vaultID, s.runtimeConfig().Network, ctxState.boardTree.OperatorPub.SerializeCompressed())
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	signing, err := newVaultBoardAuthorization(keyContext, verified.CanonicalPSBT, ctxState.boardTree.Collaborative,
		schnorr.SerializePubKey(ctxState.boardTree.CosignerPub), verified.InputIndexes, vaultBoardPhaseRegister)
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	releaseVerification, err = s.acquireVerification(ctx)
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	signed, signErr := s.keys.vaultBoardAuthorization(ctx, signing)
	releaseVerification()
	err = signErr
	if err != nil {
		return vaultBoardRegisterResponse{}, err
	}
	defer func() { signed = "" }()
	chain, err := revalidateVaultBoardOutpoint(runtime, ctxState.chain)
	if err != nil || chain.Spent || requireSameVaultBoardChainFacts(*storedOperation, chain, operation.ReceiverScript) != nil || requireVaultBoardMTP(chain, s.boardExitDelay()) != nil {
		return vaultBoardRegisterResponse{Status: vaultBoardDefinitelyNotSubmitted}, nil
	}
	operator, err := runtime.operatorDial(ctx)
	if err != nil {
		return vaultBoardRegisterResponse{Status: vaultBoardDefinitelyNotSubmitted}, nil
	}
	if claims.RegisterExpireAt-s.vtxoNow().Unix() < int64(vaultBoardDispatchMargin/time.Second) {
		return vaultBoardRegisterResponse{Status: vaultBoardDefinitelyNotSubmitted}, nil
	}
	if _, created, err := s.Stores.VaultBoard.AppendVaultBoardDispatch(ctx, policy.VaultBoardDispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardPhaseRegister,
		RequestDigest: bytes.Clone(auth.RequestDigest),
	}, vaultBoardChainPolicy(chain)); err != nil {
		return vaultBoardRegisterResponse{Status: vaultBoardDefinitelyNotSubmitted}, nil
	} else if !created {
		return vaultBoardRegisterResponse{Status: vaultBoardRegisterAmbiguous}, nil
	}
	intentID, err := operator.registerIntent(ctx, signed, verified.Message)
	if err != nil {
		if !isDefiniteVaultBoardRegisterRejection(err) {
			return vaultBoardRegisterResponse{Status: vaultBoardRegisterAmbiguous}, nil
		}
		if persistErr := s.persistVaultBoardSubmission(policy.VaultBoardSubmission{
			OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardPhaseRegister,
			RequestDigest: bytes.Clone(auth.RequestDigest), Outcome: policy.VaultBoardAuthRejected,
		}); persistErr != nil {
			return vaultBoardRegisterResponse{Status: vaultBoardRegisterAmbiguous}, nil
		}
		return vaultBoardRegisterResponse{Status: vaultBoardDefinitelyNotSubmitted}, nil
	}
	if err := s.persistVaultBoardSubmission(policy.VaultBoardSubmission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardPhaseRegister,
		RequestDigest: bytes.Clone(auth.RequestDigest), Outcome: policy.VaultBoardAuthSubmitted, OperatorRef: intentID,
	}); err != nil {
		return vaultBoardRegisterResponse{Status: vaultBoardRegisterAmbiguous}, nil
	}
	return vaultBoardRegisterResponse{Status: vaultBoardRegistered, IntentID: intentID}, nil
}

func (s *Service) replayVaultBoardRegister(ctx context.Context, auth *policy.VaultBoardAuthorization) (vaultBoardRegisterResponse, bool, error) {
	snapshot, err := s.Stores.VaultBoard.GetCurrentVaultBoardAttempt(ctx, auth.OperationID)
	if err != nil {
		return vaultBoardRegisterResponse{}, true, err
	}
	if snapshot == nil || snapshot.Register.Attempt != auth.Attempt || !bytes.Equal(snapshot.Register.RequestDigest, auth.RequestDigest) {
		return vaultBoardRegisterResponse{}, true, fmt.Errorf("vault-board-v1 register attempt is no longer current")
	}
	if snapshot.RegisterSubmission != nil {
		switch snapshot.RegisterSubmission.Outcome {
		case policy.VaultBoardAuthSubmitted:
			return vaultBoardRegisterResponse{Status: vaultBoardRegistered, IntentID: snapshot.RegisterSubmission.OperatorRef}, true, nil
		case policy.VaultBoardAuthRejected:
			return vaultBoardRegisterResponse{Status: vaultBoardDefinitelyNotSubmitted}, true, nil
		}
	}
	if snapshot.RegisterDispatch != nil {
		return vaultBoardRegisterResponse{Status: vaultBoardRegisterAmbiguous}, true, nil
	}
	return vaultBoardRegisterResponse{}, false, nil
}

func (s *Service) releaseVaultBoard(ctx context.Context, req vaultBoardDeletePhaseRequest) (vaultBoardReleaseResult, error) {
	runtime, err := s.requireVaultBoardRuntime()
	if err != nil {
		return "", err
	}
	claims, err := s.openVaultBoardHandle(req.Handle, string(vaultBoardReleaseRequired))
	if err != nil || claims.DeleteExpireAt <= s.vtxoNow().Unix() {
		return "", fmt.Errorf("vault-board-v1 release handle expired or invalid")
	}
	if len(req.InputIndexes) != 2 || req.InputIndexes[0] != 0 || req.InputIndexes[1] != 1 {
		return "", fmt.Errorf("vault-board-v1 delete input indexes")
	}
	ctxState, err := s.loadVaultBoardContext(ctx, runtime, claims.VaultID, claims.Txid, claims.Vout)
	if err != nil {
		return "", err
	}
	if err := requireVaultBoardMTP(ctxState.chain, s.boardExitDelay()); err != nil {
		return "", err
	}
	if ctxState.chain.Spent {
		return vaultBoardReleaseAmbiguous, nil
	}
	operation, err := s.vaultBoardOperationFromClaims(ctxState, claims)
	if err != nil {
		return "", err
	}
	snapshot, err := s.Stores.VaultBoard.GetCurrentVaultBoardAttempt(ctx, claims.OperationID)
	if err != nil || snapshot == nil || snapshot.Register.Attempt != claims.Attempt {
		return "", fmt.Errorf("vault-board-v1 release attempt is no longer current")
	}
	releaseVerification, err := s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	verified, verifyErr := verifyVaultBoardDeleteProof(req.PSBT, req.Message, operation, ctxState.boardTree, claims.DeleteExpireAt)
	releaseVerification()
	err = verifyErr
	if err != nil {
		return "", fmt.Errorf("vault-board-v1 delete proof: %w", err)
	}
	if !sameIntSlice(verified.InputIndexes, req.InputIndexes) {
		return "", fmt.Errorf("vault-board-v1 delete input indexes changed")
	}
	authRequest := policy.VaultBoardAuthorization{
		OperationID: claims.OperationID, Attempt: claims.Attempt, Phase: policy.VaultBoardPhaseDelete,
		RequestDigest: bytes.Clone(verified.RequestDigest), ExpireAt: verified.ExpireAt,
	}
	if snapshot.DeleteSubmission != nil {
		return vaultBoardReleased, nil
	}
	if snapshot.DeleteDispatch != nil {
		return vaultBoardReleaseAmbiguous, nil
	}
	keyContext, err := newVaultBoardKeyContext(ctxState.vaultID, s.runtimeConfig().Network, ctxState.boardTree.OperatorPub.SerializeCompressed())
	if err != nil {
		return "", err
	}
	signing, err := newVaultBoardAuthorization(keyContext, verified.CanonicalPSBT, ctxState.boardTree.Collaborative,
		schnorr.SerializePubKey(ctxState.boardTree.CosignerPub), verified.InputIndexes, vaultBoardPhaseDelete)
	if err != nil {
		return "", err
	}
	releaseVerification, err = s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	signed, signErr := s.keys.vaultBoardAuthorization(ctx, signing)
	releaseVerification()
	err = signErr
	if err != nil {
		return "", err
	}
	defer func() { signed = "" }()
	chain, err := revalidateVaultBoardOutpoint(runtime, ctxState.chain)
	if err != nil || chain.Spent || requireSameVaultBoardChainFacts(operation, chain, operation.ReceiverScript) != nil || requireVaultBoardMTP(chain, s.boardExitDelay()) != nil {
		return vaultBoardReleaseAmbiguous, nil
	}
	operator, err := runtime.operatorDial(ctx)
	if err != nil {
		return vaultBoardReleaseAmbiguous, nil
	}
	if claims.DeleteExpireAt-s.vtxoNow().Unix() < int64(vaultBoardDispatchMargin/time.Second) {
		return "", fmt.Errorf("vault-board-v1 release proof expires too soon")
	}
	auth, _, created, err := s.Stores.VaultBoard.AppendVaultBoardAuthorizationAndDispatch(ctx, authRequest, vaultBoardChainPolicy(chain))
	if err != nil || !created {
		return vaultBoardReleaseAmbiguous, nil
	}
	if err := operator.deleteIntent(ctx, signed, verified.Message); err != nil {
		return vaultBoardReleaseAmbiguous, nil
	}
	if err := s.persistVaultBoardSubmission(policy.VaultBoardSubmission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardPhaseDelete,
		RequestDigest: bytes.Clone(auth.RequestDigest), Outcome: policy.VaultBoardAuthReleased,
	}); err != nil {
		return vaultBoardReleaseAmbiguous, nil
	}
	return vaultBoardReleased, nil
}

func (s *Service) submitVaultBoardCommitment(ctx context.Context, req vaultBoardFinalPhaseRequest) (vaultBoardCommitmentResult, error) {
	runtime, err := s.requireVaultBoardRuntime()
	if err != nil {
		return "", err
	}
	if runtime.batchExpiry == 0 {
		return "", fmt.Errorf("vault-board-v1 batch expiry release pin unavailable")
	}
	claims, err := s.openVaultBoardHandle(req.Handle, string(vaultBoardReady))
	if err != nil {
		return "", err
	}
	if len(req.SignedForfeits) != 0 || len(req.InputIndexes) != 1 || req.InputIndexes[0] < 0 ||
		req.PSBT != req.Batch.SignedCommitmentPSBT || !sameIntSlice(req.InputIndexes, req.Batch.InputIndexes) {
		return "", fmt.Errorf("vault-board-v1 one-input commitment required")
	}
	ctxState, err := s.loadVaultBoardContext(ctx, runtime, claims.VaultID, claims.Txid, claims.Vout)
	if err != nil {
		return "", err
	}
	if err := requireVaultBoardMTP(ctxState.chain, s.boardExitDelay()); err != nil {
		return "", err
	}
	if ctxState.chain.Spent {
		return vaultBoardCommitmentAmbiguous, nil
	}
	operation, err := s.vaultBoardOperationFromClaims(ctxState, claims)
	if err != nil {
		return "", err
	}
	snapshot, err := s.Stores.VaultBoard.GetCurrentVaultBoardAttempt(ctx, claims.OperationID)
	if err != nil || snapshot == nil || snapshot.Register.Attempt != claims.Attempt || snapshot.RegisterSubmission == nil ||
		snapshot.RegisterSubmission.Outcome != policy.VaultBoardAuthSubmitted {
		return "", fmt.Errorf("vault-board-v1 accepted register attempt required")
	}
	releaseVerification, err := s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	verified, verifyErr := verifyVaultBoardFinal(req.Batch, operation, snapshot.Register, ctxState.boardTree, vaultBoardFinalExpiry(runtime.batchExpiry))
	releaseVerification()
	err = verifyErr
	if err != nil {
		return "", err
	}
	authRequest := policy.VaultBoardAuthorization{
		OperationID: claims.OperationID, Attempt: claims.Attempt, Phase: policy.VaultBoardPhaseFinalize,
		RequestDigest: bytes.Clone(verified.RequestDigest), CommitmentTxid: verified.CommitmentTxid,
		ReceiverTxid: verified.ReceiverTxid, ReceiverVout: verified.ReceiverVout,
	}
	if snapshot.FinalSubmission != nil {
		return vaultBoardCommitmentSubmitted, nil
	}
	if snapshot.FinalDispatch != nil {
		return vaultBoardCommitmentAmbiguous, nil
	}
	keyContext, err := newVaultBoardKeyContext(ctxState.vaultID, s.runtimeConfig().Network, ctxState.boardTree.OperatorPub.SerializeCompressed())
	if err != nil {
		return "", err
	}
	signing, err := newVaultBoardAuthorization(keyContext, verified.CanonicalPSBT, ctxState.boardTree.Collaborative,
		schnorr.SerializePubKey(ctxState.boardTree.CosignerPub), []int{verified.InputIndex}, vaultBoardPhaseFinalize)
	if err != nil {
		return "", err
	}
	releaseVerification, err = s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	signed, signErr := s.keys.vaultBoardAuthorization(ctx, signing)
	releaseVerification()
	err = signErr
	if err != nil {
		return "", err
	}
	defer func() { signed = "" }()
	chain, err := revalidateVaultBoardOutpoint(runtime, ctxState.chain)
	if err != nil || chain.Spent || requireSameVaultBoardChainFacts(operation, chain, operation.ReceiverScript) != nil || requireVaultBoardMTP(chain, s.boardExitDelay()) != nil {
		return vaultBoardCommitmentAmbiguous, nil
	}
	operator, err := runtime.operatorDial(ctx)
	if err != nil {
		return vaultBoardCommitmentAmbiguous, nil
	}
	auth, _, created, err := s.Stores.VaultBoard.AppendVaultBoardAuthorizationAndDispatch(ctx, authRequest, vaultBoardChainPolicy(chain))
	if err != nil || !created {
		return vaultBoardCommitmentAmbiguous, nil
	}
	if err := operator.submitCommitment(ctx, signed); err != nil {
		return vaultBoardCommitmentAmbiguous, nil
	}
	if err := s.persistVaultBoardSubmission(policy.VaultBoardSubmission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: policy.VaultBoardPhaseFinalize,
		RequestDigest: bytes.Clone(auth.RequestDigest), Outcome: policy.VaultBoardAuthSubmitted,
		CommitmentTxid: verified.CommitmentTxid, ReceiverTxid: verified.ReceiverTxid, ReceiverVout: verified.ReceiverVout,
	}); err != nil {
		return vaultBoardCommitmentAmbiguous, nil
	}
	return vaultBoardCommitmentSubmitted, nil
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
