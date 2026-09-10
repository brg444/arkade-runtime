package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

type boardConflictTestChain struct {
	*vaultBoardTestChain
	proof       *policy.BitcoinConflictEvidence
	calls       int
	beforeCheck func(int)
}

func (c *boardConflictTestChain) confirmedBitcoinConflict(context.Context, string, *wire.MsgTx) (*policy.BitcoinConflictEvidence, error) {
	c.calls++
	if c.beforeCheck != nil {
		c.beforeCheck(c.calls)
	}
	return c.proof, nil
}

type boardConflictTestOperator struct {
	*vaultBoardTestOperator
	commitment *wire.MsgTx
}

func (o *boardConflictTestOperator) commitmentTransaction(context.Context, string) (*wire.MsgTx, error) {
	return o.commitment, nil
}

func TestVaultBoardConflictRecoveryRetainsAuthorityAndRechecksChain(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			f := newVaultBoardServiceFixtureForNetwork(t, network)
			prepared := f.prepare(t)
			f.register(t, prepared)
			id, _ := deployment.IdentityFor(network)
			final := newVaultBoardFinalFixtureForPolicy(t, f.proof, id.CheckpointForfeitPubHex, id.VtxoTreeExpirySeconds, false, true)
			f.operator.finalErr = fmt.Errorf("lost final response")
			originalReq := vaultBoardFinalPhaseRequest{Handle: prepared.Handle, PSBT: final.evidence.SignedCommitmentPSBT, InputIndexes: []int{0}, Batch: final.evidence}
			if state, err := f.svc.submitVaultBoardCommitment(t.Context(), originalReq); err != nil || state != vaultBoardCommitmentAmbiguous {
				t.Fatalf("initial final %s %v", state, err)
			}
			packet, _ := parsePSBT(final.evidence.UnsignedCommitmentPSBT)
			operationID, _ := policy.ComputeVaultBoardOperationID(f.vaultID, f.proof.operation.Txid, f.proof.operation.Vout)
			before, _ := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), operationID)
			beforeFinal, _ := json.Marshal(before.FinalAuthorization)
			chain := &boardConflictTestChain{vaultBoardTestChain: f.chain}
			operator := &boardConflictTestOperator{vaultBoardTestOperator: f.operator, commitment: packet.UnsignedTx}
			f.svc.vaultBoardRuntime.chain = chain
			f.svc.vaultBoardRuntime.operatorDial = func(context.Context) (vaultBoardOperator, error) { return operator, nil }
			prepare := func() (vaultBoardPrepareResult, error) {
				return f.svc.prepareVaultBoard(t.Context(), vaultBoardPrepareRequest{VaultID: f.vaultID, Inputs: []vaultBoardPrepareInput{{Txid: hex.EncodeToString(f.proof.operation.Txid), Vout: f.proof.operation.Vout}}, Recipients: []vaultBoardPrepareRecipient{{Address: f.receiver, AmountSats: uint64(f.proof.receiver.Value)}}})
			}
			if result, err := prepare(); err != nil || result.State != vaultBoardBlocked {
				t.Fatalf("no conflict released: %+v %v", result, err)
			}
			otherInput := packet.UnsignedTx.Copy()
			otherInput.TxIn = otherInput.TxIn[1:]
			proof := conflictFixture(t, otherInput)
			proof.CommitmentTxid = packet.UnsignedTx.TxHash().String()
			for _, scenario := range []string{"five confirmations", "wrong original", "wrong conflict", "boarding input", "spent boarding"} {
				t.Run(scenario, func(t *testing.T) {
					bad := proof
					chain.proof = &bad
					switch scenario {
					case "five confirmations":
						bad.TipHeight--
					case "wrong original":
						operator.commitment = otherInput
					case "wrong conflict":
						bad.ConflictingTxid = strings.Repeat("ab", 32)
					case "boarding input":
						bad = conflictFixture(t, packet.UnsignedTx)
					case "spent boarding":
						f.chain.state.Spent = true
						f.chain.state.SpendingTxid = proof.ConflictingTxid
					}
					result, err := prepare()
					if err == nil && result.State != vaultBoardBlocked {
						t.Fatalf("unsafe release %+v", result)
					}
					after, _ := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), operationID)
					if len(after.Conflicts) != 0 || f.operator.finals != 1 {
						t.Fatal("failure mutated conflict or signed again")
					}
					operator.commitment = packet.UnsignedTx
					f.chain.state.Spent = false
					f.chain.state.SpendingTxid = ""
				})
			}
			chain.proof = &proof
			result, err := prepare()
			if err != nil || result.State != vaultBoardReady {
				t.Fatalf("valid conflict %+v %v", result, err)
			}
			after, err := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), operationID)
			afterFinal, _ := json.Marshal(after.FinalAuthorization)
			if err != nil || len(after.Conflicts) != 1 || !bytes.Equal(beforeFinal, afterFinal) || after.FinalDispatch == nil {
				t.Fatal("original final authority was changed")
			}
			// A late response cannot resurrect a superseded commitment.
			a := before.FinalAuthorization
			if _, _, err := f.ledger.AppendVaultBoardSubmission(t.Context(), policy.VaultBoardSubmission{OperationID: operationID, Attempt: a.Attempt, Phase: policy.VaultBoardPhaseFinalize, RequestDigest: a.RequestDigest, Outcome: policy.VaultBoardAuthSubmitted, CommitmentTxid: a.CommitmentTxid, ReceiverTxid: a.ReceiverTxid, ReceiverVout: a.ReceiverVout}); err == nil {
				t.Fatal("late result resurrected failed commitment")
			}
			// A retained certificate never substitutes for current canonical chain facts.
			chain.proof = nil
			if _, err := prepare(); err == nil {
				t.Fatal("reorg allowed prepare")
			}
			chain.proof = &proof
			result, err = prepare()
			if err != nil {
				t.Fatal(err)
			}
			session, _ := btcec.NewPrivateKey()
			f.proof.treePubHex = hex.EncodeToString(session.PubKey().SerializeCompressed())
			chain.proof = nil
			registerProof := f.proof
			registerProof.expireAt = result.RegisterExpireAt
			message := registerProof.registerMessage(t)
			psbt := registerProof.proof(t, message, []*wire.TxOut{registerProof.receiver})
			regReq := vaultBoardRegisterPhaseRequest{Handle: result.Handle, PSBT: psbt, Message: message, InputIndexes: []int{0, 1}}
			if _, err := f.svc.registerVaultBoard(t.Context(), regReq); err == nil {
				t.Fatal("reorg allowed register")
			}
			chain.proof = &proof
			chain.calls = 0
			savedTime := *f.clock
			chain.beforeCheck = func(n int) {
				if n == 2 {
					*f.clock = time.Unix(result.RegisterExpireAt, 0)
				}
			}
			if state, err := f.svc.registerVaultBoard(t.Context(), regReq); err != nil || state.Status != vaultBoardDefinitelyNotSubmitted {
				t.Fatalf("expired during chain check: %+v %v", state, err)
			}
			if f.operator.registers != 1 {
				t.Fatal("expired proof reached Operator")
			}
			chain.beforeCheck = nil
			*f.clock = savedTime
			if state, err := f.svc.registerVaultBoard(t.Context(), regReq); err != nil || state.Status != vaultBoardRegistered {
				t.Fatalf("new registration %+v %v", state, err)
			}
			nextFinal := newVaultBoardFinalFixtureForNetwork(t, f.proof, network)
			chain.proof = nil
			if _, err := f.svc.submitVaultBoardCommitment(t.Context(), vaultBoardFinalPhaseRequest{Handle: result.Handle, PSBT: nextFinal.evidence.SignedCommitmentPSBT, InputIndexes: []int{0}, Batch: nextFinal.evidence}); err == nil {
				t.Fatal("reorg allowed final dispatch")
			}
			if f.operator.finals != 1 {
				t.Fatal("reorg released new final signature")
			}
			chain.proof = &proof
			f.operator.finalErr = nil
			if state, err := f.svc.submitVaultBoardCommitment(t.Context(), vaultBoardFinalPhaseRequest{Handle: result.Handle, PSBT: nextFinal.evidence.SignedCommitmentPSBT, InputIndexes: []int{0}, Batch: nextFinal.evidence}); err != nil || state != vaultBoardCommitmentSubmitted {
				t.Fatalf("new final %s %v", state, err)
			}
		})
	}
}

func TestVaultBoardOriginalCommitmentMustMatchAuthenticatedHash(t *testing.T) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	var raw bytes.Buffer
	_ = tx.Serialize(&raw)
	id, _ := deployment.IdentityFor(deployment.NetworkMainnet)
	for _, scenario := range []string{"valid", "wrong hash", "multiple", "trailing", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			packet, _ := psbt.NewFromUnsignedTx(tx)
			encoded, _ := packet.B64Encode()
			want := tx.TxHash().String()
			txs := []string{encoded}
			status := 200
			switch scenario {
			case "wrong hash":
				want = strings.Repeat("11", 64/2)
			case "multiple":
				txs = append(txs, encoded)
			case "trailing":
				txs[0] += "00"
			case "unavailable":
				status = 503
			}
			body, _ := json.Marshal(map[string]any{"txs": txs})
			o := &stockVaultBoardOperator{network: deployment.NetworkMainnet, origin: id.OperatorOrigin, hc: rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.String() != id.OperatorOrigin+"/v1/indexer/virtualTx/"+want {
					t.Fatal("unpinned read")
				}
				return jsonResponse(status, string(body)), nil
			})}
			got, err := o.commitmentTransaction(t.Context(), want)
			if scenario == "valid" {
				if err != nil || got == nil || got.TxHash() != tx.TxHash() {
					t.Fatalf("valid tx %v", err)
				}
			} else if err == nil {
				t.Fatal("unbound original accepted")
			}
		})
	}
}

func TestVaultBoardOriginalCommitmentAcceptsCapturedOperatorPSBT(t *testing.T) {
	const txid = "d88281acdaf9d25fd29bb9125ad34e76014d425abd394b2d372920cd21c2ebfe"
	const captured = "cHNidP8BALICAAAAAptEQMb8nLkE5//9KTP/jWDfu3rCps5mzTa8/TIXpC6zAQAAAAD/////T8AUUNeDIJFJjoCt3Gusl/gYEpXSrLvZ8FV02DmUQpkAAAAAAP////8CkHcAAAAAAAAiUSAldo0OjSdmapVGA6KhTXXRlWkMibIoHctKR+cviJfsflC3fQAAAAAAIlEg+Y+3+fKHaPF17fF/kqNy8Lxr/pAXMLZXI9O6vNQWa1gAAAAAAAEBK7C5fQAAAAAAIlEgXp5ByAEbTP9xUFvG3+dmPblN87vpI2CziW27oczawXkAAQErkHcAAAAAAAAiUSCGLBoieiHEohSW4SuoMUwHdcSOUBhWlYR/G3k8RqfV1AAAAA=="
	id, _ := deployment.IdentityFor(deployment.NetworkMainnet)
	body, _ := json.Marshal(map[string]any{"txs": []string{captured}})
	o := &stockVaultBoardOperator{network: deployment.NetworkMainnet, origin: id.OperatorOrigin, hc: rpcDoerFunc(func(req *http.Request) (*http.Response, error) { return jsonResponse(200, string(body)), nil })}
	tx, err := o.commitmentTransaction(t.Context(), txid)
	if err != nil || tx.TxHash().String() != txid || len(tx.TxIn) != 2 || tx.TxIn[0].PreviousOutPoint.Hash.String() != "b32ea41732fdbc36cd66cea6c27abbdf608dff3329fdffe704b99cfcc640449b" || tx.TxIn[0].PreviousOutPoint.Index != 1 || tx.TxIn[1].PreviousOutPoint.Hash.String() != "99429439d87455f0d9bbacd2951218f897ac6bdcad808e49912083d75014c04f" || tx.TxIn[1].PreviousOutPoint.Index != 0 {
		t.Fatalf("captured commitment not bound: %v", err)
	}
}

type boardEndingDuringChecksOperator struct {
	*vaultBoardTestOperator
	calls int
}

func (o *boardEndingDuringChecksOperator) requireUnendedCommitment(context.Context, string) error {
	o.calls++
	if o.calls > 1 {
		return fmt.Errorf("batch ended during chain verification")
	}
	return nil
}
func TestVaultBoardRechecksBatchEndBeforeDurableDispatch(t *testing.T) {
	f := newVaultBoardServiceFixture(t)
	prepared := f.prepare(t)
	f.register(t, prepared)
	operator := &boardEndingDuringChecksOperator{vaultBoardTestOperator: f.operator}
	f.svc.vaultBoardRuntime.operatorDial = func(context.Context) (vaultBoardOperator, error) { return operator, nil }
	final := newVaultBoardFinalFixtureFromProof(t, f.proof)
	opID, _ := policy.ComputeVaultBoardOperationID(f.vaultID, f.proof.operation.Txid, f.proof.operation.Vout)
	before, _ := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), opID)
	if _, err := f.svc.submitVaultBoardCommitment(t.Context(), vaultBoardFinalPhaseRequest{Handle: prepared.Handle, PSBT: final.evidence.SignedCommitmentPSBT, InputIndexes: []int{0}, Batch: final.evidence}); err == nil {
		t.Fatal("batch end during checks allowed final dispatch")
	}
	after, _ := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), opID)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) || f.operator.finals != 0 || operator.calls != 2 {
		t.Fatal("ended batch crossed durable authority boundary")
	}
}
