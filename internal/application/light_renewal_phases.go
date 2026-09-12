package application

import (
	"context"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
)

type lightRenewalOperator interface {
	registerIntent(context.Context, string, string) (string, error)
	submitLightForfeit(context.Context, string) error
	requireUnendedCommitment(context.Context, string) error
}

func (o *stockVaultBoardOperator) submitLightForfeit(ctx context.Context, signed string) error {
	return o.post(ctx, "/v1/batch/submitForfeitTxs", struct {
		SignedForfeitTxs   []string `json:"signedForfeitTxs"`
		SignedCommitmentTx string   `json:"signedCommitmentTx"`
	}{[]string{signed}, ""}, nil)
}
func (s *Service) dialLightRenewalOperator(ctx context.Context) (lightRenewalOperator, error) {
	if s.lightRenewalOperatorDial != nil {
		return s.lightRenewalOperatorDial(ctx)
	}
	operator, err := dialVaultBoardOperator(ctx, s.runtimeConfig().Network)
	if err != nil {
		return nil, err
	}
	stock, ok := operator.(*stockVaultBoardOperator)
	if !ok {
		return nil, fmt.Errorf("Light renewal public Operator required")
	}
	return stock, nil
}

type lightRenewalRegisterRequest struct {
	VaultID     string                   `json:"vaultId"`
	OperationID string                   `json:"operationId"`
	PSBT        string                   `json:"psbt"`
	Message     string                   `json:"message"`
	Assertion   WebAuthnAssertionRequest `json:"assertion"`
	DirectSig   string                   `json:"directSig"`
}
type lightRenewalRegistrationEvidence struct {
	PSBT    string `json:"psbt"`
	Message string `json:"message"`
}
type lightRenewalResponse struct {
	State          string `json:"state"`
	Reason         string `json:"reason,omitempty"`
	IntentID       string `json:"intentId,omitempty"`
	CommitmentTxid string `json:"commitmentTxid,omitempty"`
	ReceiverTxid   string `json:"receiverTxid,omitempty"`
	ReceiverVout   uint32 `json:"receiverVout,omitempty"`
}
type lightRenewalFinalRequest struct {
	VaultID     string                    `json:"vaultId"`
	OperationID string                    `json:"operationId"`
	Evidence    lightRenewalFinalEvidence `json:"evidence"`
}

func (s *Service) persistLightRenewalEvent(e policy.LightRenewalEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := s.Stores.LightRenewal.AppendLightRenewalEvent(ctx, e, nil, 0)
	return err
}
