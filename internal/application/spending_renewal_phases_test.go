package application

import "context"

type spendingRenewalTestOperator struct {
	registers, finals, commitmentChecks, endedQueries  int
	registerErr, finalErr, commitmentError, endedError error
	commitmentErrorAt                                  int
	endedAt                                            int64
	signedProof, signedFinal                           string
}

func (o *spendingRenewalTestOperator) registerIntent(_ context.Context, proof, _ string) (string, error) {
	o.registers++
	o.signedProof = proof
	return "renewal-intent", o.registerErr
}
func (o *spendingRenewalTestOperator) submitLightForfeit(_ context.Context, raw string) error {
	o.finals++
	o.signedFinal = raw
	return o.finalErr
}
func (o *spendingRenewalTestOperator) requireUnendedCommitment(context.Context, string) error {
	o.commitmentChecks++
	if o.commitmentErrorAt > 0 && o.commitmentChecks < o.commitmentErrorAt {
		return nil
	}
	return o.commitmentError
}
func (o *spendingRenewalTestOperator) endedCommitmentAt(context.Context, string) (int64, error) {
	o.endedQueries++
	return o.endedAt, o.endedError
}

type spendingRenewalSettledResolver struct {
	stubArkResolver
	settled bool
}

func (r *spendingRenewalSettledResolver) spendingRenewalSettled(context.Context, spendingRenewalPlan, verifiedSpendingRenewalFinal, []byte) (bool, error) {
	return r.settled, nil
}
