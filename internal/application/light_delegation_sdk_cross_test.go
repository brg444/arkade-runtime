package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

// These requests were constructed by the actual wallet-owned SDK, not Go's
// verifier or the public delegate. All keys and outputs are public fixtures.
func TestLightDelegationActualSDKRequests(t *testing.T) {
	raw, err := os.ReadFile("testdata/light-delegation-sdk.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Fixtures []struct {
			Network        string                 `json:"network"`
			Descriptor     light.Descriptor       `json:"descriptor"`
			OperatorFee    int64                  `json:"operatorFee"`
			ForfeitAddress string                 `json:"forfeitAddress"`
			Request        lightDelegationRequest `json:"request"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Fixtures) != 4 {
		t.Fatal("both networks and zero/nonzero Operator fees required")
	}
	for _, vector := range vectors.Fixtures {
		t.Run(fmt.Sprintf("%s-fee-%d", vector.Network, vector.OperatorFee), func(t *testing.T) {
			svc := &Service{}
			svc.Deployment.Network = vector.Network
			pins, err := deployment.IdentityFor(vector.Network)
			if err != nil {
				t.Fatal(err)
			}
			tree, err := buildLightPolicyTree(vector.Descriptor, mustDecodeRenewalHex(pins.OperatorSignerPubHex), svc.vtxoAddrHRP())
			if err != nil {
				t.Fatal(err)
			}
			address, err := btcutil.DecodeAddress(vector.ForfeitAddress, nil)
			if err != nil {
				t.Fatal(err)
			}
			forfeitScript, err := txscript.PayToAddrScript(address)
			if err != nil {
				t.Fatal(err)
			}
			pinnedScript, err := delegationForfeitScript(vector.Network)
			if err != nil || !bytes.Equal(forfeitScript, pinnedScript) {
				t.Fatal("fixture forfeit destination differs from deployment pin")
			}
			plan, err := verifyLightDelegationRequest(vector.Request, vector.Descriptor, tree, forfeitScript)
			if err != nil {
				t.Fatalf("real SDK request rejected: %v", err)
			}
			if plan.Renewal.Txid != "1111111111111111111111111111111111111111111111111111111111111111" || plan.Renewal.ValueSats != 10000 || plan.Renewal.ReceiverSats != 10000-vector.OperatorFee || plan.Renewal.FeeSats != vector.OperatorFee {
				t.Fatalf("SDK request amounts changed: %+v", plan.Renewal)
			}
			clone := func() lightDelegationRequest {
				var req lightDelegationRequest
				raw, _ := json.Marshal(vector.Request)
				if err := json.Unmarshal(raw, &req); err != nil {
					t.Fatal(err)
				}
				return req
			}
			// Resigning the outer envelope prevents its signature check from masking
			// missing verification of the owner's original intent and partial forfeit.
			resign := func(r *lightDelegationRequest) {
				bytes := make([]byte, 32)
				for i := range bytes {
					bytes[i] = 1
				}
				key, _ := btcec.PrivKeyFromBytes(bytes)
				defer key.Key.Zero()
				digest, err := lightDelegationRequestDigest(*r)
				if err != nil {
					t.Fatal(err)
				}
				signature, err := schnorr.Sign(key, digest)
				if err != nil {
					t.Fatal(err)
				}
				r.OwnerSignature = hex.EncodeToString(signature.Serialize())
			}
			for name, mutate := range map[string]func(*lightDelegationRequest){
				"delete wrong message": func(r *lightDelegationRequest) {
					r.DeleteIntent.Message = `{"type":"delete","expire_at":123}`
					resign(r)
				},
				"delete wrong input": func(r *lightDelegationRequest) {
					p, err := parsePSBT(r.DeleteIntent.Proof)
					if err != nil {
						t.Fatal(err)
					}
					p.UnsignedTx.TxIn[1].PreviousOutPoint.Index++
					r.DeleteIntent.Proof, _ = p.B64Encode()
					resign(r)
				},
				"delete monetary output": func(r *lightDelegationRequest) {
					p, err := parsePSBT(r.DeleteIntent.Proof)
					if err != nil {
						t.Fatal(err)
					}
					p.UnsignedTx.TxOut[0].Value = 330
					r.DeleteIntent.Proof, _ = p.B64Encode()
					resign(r)
				},
				"delete missing owner": func(r *lightDelegationRequest) {
					p, err := parsePSBT(r.DeleteIntent.Proof)
					if err != nil {
						t.Fatal(err)
					}
					p.Inputs[1].TaprootScriptSpendSig = nil
					r.DeleteIntent.Proof, _ = p.B64Encode()
					resign(r)
				},
				"changed operation without owner authorization": func(r *lightDelegationRequest) { r.OperationID = "44444444444444444444444444444444" },
				"wrong vault": func(r *lightDelegationRequest) {
					r.VaultID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
					resign(r)
				},
				"changed intent schedule": func(r *lightDelegationRequest) {
					var message map[string]any
					_ = json.Unmarshal([]byte(r.Intent.Message), &message)
					message["valid_at"] = message["valid_at"].(float64) + 1
					raw, _ := json.Marshal(message)
					r.Intent.Message = string(raw)
					resign(r)
				},
				"missing owner partial": func(r *lightDelegationRequest) {
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
				"changed forfeit destination": func(r *lightDelegationRequest) {
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
					if _, err := verifyLightDelegationRequest(r, vector.Descriptor, tree, forfeitScript); err == nil {
						t.Fatal("mutated SDK request accepted")
					}
				})
			}
		})
	}
}
