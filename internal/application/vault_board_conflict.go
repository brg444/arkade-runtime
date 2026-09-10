package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/wire"
)

type vaultBoardCommitmentReader interface {
	commitmentTransaction(context.Context, string) (*wire.MsgTx, error)
}

// The indexer supplies public bytes only. The authenticated final txid, not
// the indexer's assertion of batch outcome, binds the transaction we inspect.
func (o *stockVaultBoardOperator) commitmentTransaction(ctx context.Context, txid string) (*wire.MsgTx, error) {
	if o == nil {
		return nil, fmt.Errorf("vault-board-v1 pinned commitment reader required")
	}
	id, err := deployment.IdentityFor(o.network)
	if err != nil || o.hc == nil || o.origin != id.OperatorOrigin || requireTxid(txid) != nil {
		return nil, fmt.Errorf("vault-board-v1 pinned commitment reader required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.origin+"/v1/indexer/virtualTx/"+txid, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := o.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault-board-v1 original commitment unavailable")
	}
	if res == nil || res.Body == nil {
		return nil, fmt.Errorf("vault-board-v1 original commitment unavailable")
	}
	defer res.Body.Close()
	content, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || content != "application/json" || res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault-board-v1 original commitment unavailable")
	}
	raw, err := readBoundedResponse(res.Body, vaultBoardChainTxLimit+16*1024)
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(raw)
	var response struct {
		Txs []string `json:"txs"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || len(response.Txs) != 1 {
		return nil, fmt.Errorf("vault-board-v1 exact original commitment required")
	}
	packet, err := parseCanonicalVaultBoardPSBT(response.Txs[0], maxVaultBoardProofBytes)
	if err != nil {
		return nil, fmt.Errorf("vault-board-v1 original commitment PSBT")
	}
	tx := packet.UnsignedTx
	if tx.TxHash().String() != txid || len(tx.TxIn) == 0 || len(tx.TxIn) > 128 {
		return nil, fmt.Errorf("vault-board-v1 original commitment hash")
	}
	// Persist the unsigned transaction only, excluding every PSBT signature.
	return tx.Copy(), nil
}

func hasCurrentVaultBoardConflict(snapshot *policy.VaultBoardAttemptSnapshot) bool {
	if snapshot == nil || snapshot.FinalAuthorization == nil {
		return false
	}
	for _, conflict := range snapshot.Conflicts {
		if conflict.Attempt == snapshot.Register.Attempt && conflict.Evidence.CommitmentTxid == snapshot.FinalAuthorization.CommitmentTxid && bytes.Equal(conflict.RequestDigest, snapshot.FinalAuthorization.RequestDigest) {
			return true
		}
	}
	return false
}

func (s *Service) requireVaultBoardConflictChecks(ctx context.Context, runtime *vaultBoardRuntime, snapshot *policy.VaultBoardAttemptSnapshot, chain vaultBoardConfirmedOutpoint) (policy.VaultBoardChainState, error) {
	out := vaultBoardChainPolicy(chain)
	if snapshot == nil || len(snapshot.Conflicts) == 0 {
		return out, nil
	}
	verifier, ok := runtime.chain.(bitcoinConflictChain)
	if !ok {
		return out, fmt.Errorf("vault-board-v1 conflict chain verifier unavailable")
	}
	for _, retained := range snapshot.Conflicts {
		original, err := policy.ParseVaultBoardConflictCommitment(retained)
		if err != nil {
			return out, err
		}
		current, err := verifier.confirmedBitcoinConflict(ctx, s.runtimeConfig().Network, original)
		if err != nil {
			return out, err
		}
		if current == nil || current.Validate() != nil || verifyBitcoinConflictTransaction(*current, original) != nil || current.FundingTxid == hex.EncodeToString(chain.Txid) && current.FundingVout == chain.Vout {
			return out, fmt.Errorf("vault-board-v1 prior commitment conflict is no longer confirmed")
		}
		// Reconfirmation on another branch is accepted only after the same six
		// confirmations are independently established by the current query.
		out.ConflictChecks = append(out.ConflictChecks, bytes.Clone(retained.IntegrityMAC))
	}
	return out, nil
}

func (s *Service) reconcileVaultBoardConflict(ctx context.Context, runtime *vaultBoardRuntime, snapshot *policy.VaultBoardAttemptSnapshot, chain vaultBoardConfirmedOutpoint) (bool, error) {
	if snapshot == nil || snapshot.FinalAuthorization == nil || snapshot.FinalSubmission != nil || chain.Spent || hasCurrentVaultBoardConflict(snapshot) {
		return false, nil
	}
	verifier, ok := runtime.chain.(bitcoinConflictChain)
	if !ok {
		return false, nil
	}
	operator, err := runtime.operatorDial(ctx)
	if err != nil {
		return false, err
	}
	reader, ok := operator.(vaultBoardCommitmentReader)
	if !ok {
		return false, nil
	}
	original, err := reader.commitmentTransaction(ctx, snapshot.FinalAuthorization.CommitmentTxid)
	if err != nil {
		return false, err
	}
	if original == nil || original.TxHash().String() != snapshot.FinalAuthorization.CommitmentTxid {
		return false, fmt.Errorf("vault-board-v1 conflict commitment changed")
	}
	proof, err := verifier.confirmedBitcoinConflict(ctx, s.runtimeConfig().Network, original)
	if err != nil || proof == nil {
		return false, err
	}
	if err := proof.Validate(); err != nil {
		return false, err
	}
	if err := verifyBitcoinConflictTransaction(*proof, original); err != nil {
		return false, err
	}
	if proof.FundingTxid == hex.EncodeToString(chain.Txid) && proof.FundingVout == chain.Vout {
		return false, fmt.Errorf("vault-board-v1 conflict must preserve boarding input")
	}
	fresh, err := revalidateVaultBoardOutpoint(runtime, chain)
	if err != nil || fresh.Spent || requireSameVaultBoardChainFacts(snapshot.Operation, fresh, snapshot.Operation.ReceiverScript) != nil {
		return false, fmt.Errorf("vault-board-v1 boarding outpoint changed during conflict recovery")
	}
	checks, err := s.requireVaultBoardConflictChecks(ctx, runtime, snapshot, fresh)
	if err != nil {
		return false, err
	}
	var raw bytes.Buffer
	if err := original.SerializeNoWitness(&raw); err != nil {
		return false, err
	}
	err = s.Stores.VaultBoard.AppendVaultBoardConflict(ctx, policy.VaultBoardConflict{
		OperationID: snapshot.Operation.OperationID, Attempt: snapshot.Register.Attempt,
		RequestDigest: bytes.Clone(snapshot.FinalAuthorization.RequestDigest), CommitmentRaw: hex.EncodeToString(raw.Bytes()), Evidence: *proof,
	}, checks)
	return err == nil, err
}
