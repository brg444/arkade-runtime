package application

import "context"

type lightRenewalTestOperator struct {
	registers, finals, commitmentChecks, endedQueries  int
	registerErr, finalErr, commitmentError, endedError error
	commitmentErrorAt                                  int
	endedAt                                            int64
	signedProof, signedFinal                           string
}

func (o *lightRenewalTestOperator) registerIntent(_ context.Context, proof, _ string) (string, error) {
	o.registers++
	o.signedProof = proof
	return "renewal-intent", o.registerErr
}
func (o *lightRenewalTestOperator) submitLightForfeit(_ context.Context, raw string) error {
	o.finals++
	o.signedFinal = raw
	return o.finalErr
}
func (o *lightRenewalTestOperator) requireUnendedCommitment(context.Context, string) error {
	o.commitmentChecks++
	if o.commitmentErrorAt > 0 && o.commitmentChecks < o.commitmentErrorAt {
		return nil
	}
	return o.commitmentError
}
func (o *lightRenewalTestOperator) endedCommitmentAt(context.Context, string) (int64, error) {
	o.endedQueries++
	return o.endedAt, o.endedError
}

type lightRenewalSettledResolver struct {
	stubArkResolver
	settled bool
}

func (r *lightRenewalSettledResolver) lightRenewalSettled(context.Context, lightRenewalPlan, verifiedLightRenewalFinal, []byte) (bool, error) {
	return r.settled, nil
}
