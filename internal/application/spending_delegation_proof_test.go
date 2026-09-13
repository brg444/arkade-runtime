package application

import (
	"encoding/hex"
	"encoding/json"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"testing"
)

func TestSpendingDelegationOwnerProofSubstitution(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			e, c, set := spendingDelegationFixture(t, network, "standard")
			original := set.request(set.Plans[0])
			forfeitScript, err := delegationForfeitScript(network)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyDelegationRequest(original, c, forfeitScript); err != nil {
				t.Fatal(err)
			}
			clone := func() spendingDelegationRequest {
				raw, _ := json.Marshal(original)
				var r spendingDelegationRequest
				if err := json.Unmarshal(raw, &r); err != nil {
					t.Fatal(err)
				}
				return r
			}
			// Re-sign the outer envelope so it cannot mask missing inner proof checks.
			resign := func(r *spendingDelegationRequest) {
				digest, err := spendingDelegationRequestDigest(*r)
				if err != nil {
					t.Fatal(err)
				}
				sig, err := schnorr.Sign(e.hot, digest)
				if err != nil {
					t.Fatal(err)
				}
				r.OwnerSignature = hex.EncodeToString(sig.Serialize())
			}
			for name, mutate := range map[string]func(*spendingDelegationRequest){
				"delete wrong message": func(r *spendingDelegationRequest) {
					r.DeleteIntent.Message = `{"type":"delete","expire_at":123}`
					resign(r)
				},
				"delete wrong input": func(r *spendingDelegationRequest) {
					p, err := parsePSBT(r.DeleteIntent.Proof)
					if err != nil {
						t.Fatal(err)
					}
					p.UnsignedTx.TxIn[1].PreviousOutPoint.Index++
					r.DeleteIntent.Proof, _ = p.B64Encode()
					resign(r)
				},
				"delete monetary output": func(r *spendingDelegationRequest) {
					p, err := parsePSBT(r.DeleteIntent.Proof)
					if err != nil {
						t.Fatal(err)
					}
					p.UnsignedTx.TxOut[0].Value = 330
					r.DeleteIntent.Proof, _ = p.B64Encode()
					resign(r)
				},
				"delete missing owner": func(r *spendingDelegationRequest) {
					p, err := parsePSBT(r.DeleteIntent.Proof)
					if err != nil {
						t.Fatal(err)
					}
					p.Inputs[1].TaprootScriptSpendSig = nil
					r.DeleteIntent.Proof, _ = p.B64Encode()
					resign(r)
				},
				"changed operation without owner authorization": func(r *spendingDelegationRequest) { r.OperationID = "44444444444444444444444444444444" },
				"wrong vault": func(r *spendingDelegationRequest) {
					r.VaultID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
					resign(r)
				},
				"changed intent schedule": func(r *spendingDelegationRequest) {
					var message map[string]any
					_ = json.Unmarshal([]byte(r.Intent.Message), &message)
					message["valid_at"] = message["valid_at"].(float64) + 1
					raw, _ := json.Marshal(message)
					r.Intent.Message = string(raw)
					resign(r)
				},
				"missing owner partial": func(r *spendingDelegationRequest) {
					p, err := parseCanonicalVaultBoardPSBT(r.ForfeitTxs[0], maxVaultBoardProofBytes)
					if err != nil {
						t.Fatal(err)
					}
					p.Inputs[0].TaprootScriptSpendSig = nil
					r.ForfeitTxs[0], err = p.B64Encode()
					if err != nil {
						t.Fatal(err)
					}
					resign(r)
				},
				"changed forfeit destination": func(r *spendingDelegationRequest) {
					p, err := parseCanonicalVaultBoardPSBT(r.ForfeitTxs[0], maxVaultBoardProofBytes)
					if err != nil {
						t.Fatal(err)
					}
					p.UnsignedTx.TxOut[0].PkScript = []byte{txscript.OP_TRUE}
					r.ForfeitTxs[0], err = p.B64Encode()
					if err != nil {
						t.Fatal(err)
					}
					resign(r)
				},
			} {
				t.Run(name, func(t *testing.T) {
					r := clone()
					mutate(&r)
					if _, err := verifyDelegationRequest(r, c, forfeitScript); err == nil {
						t.Fatal("mutated Spending request accepted")
					}
				})
			}
		})
	}
}
