package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func spendingDelegationFixture(t *testing.T, network, tier string, connected bool) (*env, renewalContract, spendingDelegationSetRequest) {
	t.Helper()
	e := newEnvForNetwork(t, network)
	id := strings.Repeat("ab", 32)
	e.credID = []byte{0x22}
	var recovery *btcec.PrivateKey
	if tier == "advanced" {
		recovery, _ = btcec.NewPrivateKey()
	}
	req := connectorEnrollRequestForNetwork(t, network, e.hot, e.externalOwner, e.boarding, tier, recovery, connector.Taproot, false)
	req.CredentialID = hex.EncodeToString(e.credID)
	req.WebAuthnP256 = hex.EncodeToString(webauthn.CompressedP256(e.p256))
	req.PhoneDirectP256 = hex.EncodeToString(webauthn.CompressedP256(e.direct))
	token := bytes.Repeat([]byte{0x55}, 32)
	putConnectorInvite(t, e.ledger, token)
	if connected {
		enrollConnectorVault(t, e.svc, id, token, req)
	} else {
		req.ConnectorType, req.ConnectorPub = "", ""
		req.ConnectorFingerprint, req.ConnectorPath = 0, nil
		preview, err := e.svc.previewVaultBoardEnrollmentDescriptor(id, req)
		if err != nil {
			t.Fatal(err)
		}
		req.DescriptorHash = preview.DescriptorHash
		if err := e.svc.CreateTenantVault(id, token, req); err != nil {
			t.Fatal(err)
		}
	}
	e.svc.LightDelegationEnabled = true
	c, err := e.svc.delegationContract(id, false)
	if err != nil {
		t.Fatal(err)
	}
	set := spendingDelegationSetRequest{Program: c.Binding.Program, DescriptorHash: c.DescriptorHash, VaultID: id, SetID: strings.Repeat("77", 16)}
	now := time.Now().Unix()
	expiry := now + 86400
	coins := []ports.ResolvedVtxo{}
	for i := 0; i < 2; i++ {
		point := wire.OutPoint{Hash: chainhash.Hash{byte(i + 1)}, Index: 0}
		value := int64(80000)
		proof := func(message string, output *wire.TxOut) string {
			p, err := intent.New(message, []intent.Input{{OutPoint: &point, Sequence: wire.MaxTxInSequenceNum, WitnessUtxo: &wire.TxOut{Value: value, PkScript: c.Tree.PkScript}}}, []*wire.TxOut{output})
			if err != nil {
				t.Fatal(err)
			}
			for index := range p.Inputs {
				p.Inputs[index].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{Script: c.Tree.SpendLeaf, ControlBlock: c.Tree.SpendControl, LeafVersion: txscript.BaseLeafVersion}}
				if index == 1 {
					if err := txutils.SetArkPsbtField(&p.Packet, index, txutils.VtxoTaprootTreeField, txutils.TapTree(c.Tree.RevealedScripts)); err != nil {
						t.Fatal(err)
					}
				}
				sig, err := signTapLeafAtWithSighash(&p.Packet, index, e.hot, c.Tree.SpendLeaf, txscript.SigHashAll)
				if err != nil {
					t.Fatal(err)
				}
				p.Inputs[index].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
			}
			raw, err := p.B64Encode()
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		message, err := (intent.RegisterMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister}, OnchainOutputIndexes: []int{}, ValidAt: now + 60, ExpireAt: now + 3600, CosignersPublicKeys: []string{"02" + c.Binding.CosignerPub}}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		deletion, err := (intent.DeleteMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: 0}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		forfeitScript, err := delegationForfeitScript(network)
		if err != nil {
			t.Fatal(err)
		}
		tx := wire.NewMsgTx(3)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: point, Sequence: wire.MaxTxInSequenceNum})
		anchor := txutils.AnchorOutput()
		tx.AddTxOut(&wire.TxOut{Value: value + 330 - anchor.Value, PkScript: forfeitScript})
		tx.AddTxOut(anchor)
		packet, err := psbt.NewFromUnsignedTx(tx)
		if err != nil {
			t.Fatal(err)
		}
		packet.Inputs[0].WitnessUtxo = &wire.TxOut{Value: value, PkScript: c.Tree.PkScript}
		packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{Script: c.Tree.SpendLeaf, ControlBlock: c.Tree.SpendControl, LeafVersion: txscript.BaseLeafVersion}}
		packet.Inputs[0].SighashType = delegatedOwnerSighash
		sig, err := signTapLeafAtWithSighash(packet, 0, e.hot, c.Tree.SpendLeaf, delegatedOwnerSighash)
		if err != nil {
			t.Fatal(err)
		}
		packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
		forfeit, err := packet.B64Encode()
		if err != nil {
			t.Fatal(err)
		}
		plan := spendingDelegationInput{OperationID: fmt.Sprintf("%032x", i+1), Intent: lightDelegateIntent{Proof: proof(message, &wire.TxOut{Value: value - 100, PkScript: c.Tree.PkScript}), Message: message}, ForfeitTxs: []string{forfeit}, DeleteIntent: lightDelegateIntent{Proof: proof(deletion, &wire.TxOut{PkScript: []byte{txscript.OP_RETURN}}), Message: deletion}, ExpiresAt: now + 3600}
		digest, err := set.planDigest(plan)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := schnorr.Sign(e.hot, digest)
		if err != nil {
			t.Fatal(err)
		}
		plan.OwnerSignature = hex.EncodeToString(owner.Serialize())
		set.Plans = append(set.Plans, plan)
		coins = append(coins, ports.ResolvedVtxo{Txid: point.Hash.String(), Vout: point.Index, ValueSats: uint64(value), Script: c.Tree.PkScript, ExpiresAt: &expiry, CommitmentTxids: []string{strings.Repeat("bb", 32)}})
	}
	e.svc.ArkResolver = stubArkResolver{network: network, signer: e.svc.operatorSignerPub(), vtxos: coins, feePolicy: ports.IntentFeePolicy{OffchainInput: "100.0"}}
	signSpendingSetFixture(t, e, &set, 7)
	return e, c, set
}

func signSpendingSetFixture(t *testing.T, e *env, set *spendingDelegationSetRequest, count uint32) {
	t.Helper()
	digest, err := set.digest()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(e.hot, digest)
	if err != nil {
		t.Fatal(err)
	}
	set.OwnerSignature = hex.EncodeToString(sig.Serialize())
	// Presence challenge deliberately differs from the set digest. Existing
	// Spending auth uses presence plus a separate operation-bound direct sig.
	assertion, err := webauthn.SynthWithSignCount(e.p256, e.credID, bytes.Repeat([]byte{0x91}, 32), e.svc.ClientOrigin(), e.svc.runtimeConfig().RPID, true, true, count)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.SignDigestLowS(e.direct, digest)
	if err != nil {
		t.Fatal(err)
	}
	set.Authorization = &spendingDelegationAuthorization{WebAuthnAssertionRequest: WebAuthnAssertionRequest{CredentialID: hex.EncodeToString(e.credID), ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON), AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature)}, DirectSig: hex.EncodeToString(direct)}
}

func spendingDelegationHTTP(t *testing.T, e *env, phase string, body any, want int) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/vtxo/delegate/"+phase, bytes.NewReader(raw))
	r.Header.Set("Origin", e.svc.ClientOrigin())
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testAuthorizer(e.svc).ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s HTTP %d, want%d: %s", phase, w.Code, want, w.Body.String())
	}
	return w.Body.Bytes()
}

func TestSpendingDelegationAPIAllVaultPrograms(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		for _, tier := range []string{"standard", "advanced"} {
			for _, connected := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/connector=%t", network, tier, connected), func(t *testing.T) {
					e, c, set := spendingDelegationFixture(t, network, tier, connected)
					spendingDelegationHTTP(t, e, "info", map[string]string{"vaultId": set.VaultID}, 200)
					bad := set
					bad.Authorization = nil
					spendingDelegationHTTP(t, e, "schedule", bad, 400)
					all, err := e.ledger.ListLightDelegations(t.Context())
					if err != nil || len(all) != 0 {
						t.Fatal("unauthorized plans persisted")
					}
					raw := spendingDelegationHTTP(t, e, "schedule", set, 200)
					var result spendingDelegationSetResponse
					if err := json.Unmarshal(raw, &result); err != nil {
						t.Fatal(err)
					}
					if result.SetID != set.SetID || len(result.Operations) != 2 || result.Operations[0].Program != c.Binding.Program || result.Operations[0].State != "armed" {
						t.Fatal("set response identity")
					}
					status, err := e.svc.StatusFor(t.Context(), set.VaultID)
					if err != nil || status.PeriodSpent != 0 {
						t.Fatalf("armed set debited principal/fees: %d %v", status.PeriodSpent, err)
					}
					if err := e.ledger.AdvanceSignCount(set.VaultID, e.credID, 9); err != nil {
						t.Fatal(err)
					}
					set.Authorization = nil
					spendingDelegationHTTP(t, e, "schedule", set, 200)
					changed := set
					changed.SetID = strings.Repeat("88", 16)
					changed.Plans = append([]spendingDelegationInput(nil), set.Plans...)
					for i := range changed.Plans {
						changed.Plans[i].OperationID = fmt.Sprintf("%032x", 100+i)
						digest, err := changed.planDigest(changed.Plans[i])
						if err != nil {
							t.Fatal(err)
						}
						sig, err := schnorr.Sign(e.hot, digest)
						if err != nil {
							t.Fatal(err)
						}
						changed.Plans[i].OwnerSignature = hex.EncodeToString(sig.Serialize())
					}
					signSpendingSetFixture(t, e, &changed, 7)
					if _, err := e.svc.scheduleSpendingDelegationSet(t.Context(), changed); err == nil || !strings.Contains(err.Error(), "sign count") {
						t.Fatalf("new set reused old counter: %v", err)
					}
					all, err = e.ledger.ListLightDelegations(t.Context())
					if err != nil || len(all) != 2 {
						t.Fatalf("changed membership: %v", err)
					}
					plan, err := delegationStoredPlanForContract(&all[0], c)
					if err != nil {
						t.Fatal(err)
					}
					signed, err := e.svc.keys.lightDelegation.authorizeSpendingDelegation(t.Context(), c, plan, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := requireOnlyVaultSignatureAdded(plan.Request.Intent.Proof, signed, mustDecodeRenewalHex(c.Binding.CosignerPub)); err != nil {
						t.Fatal(err)
					}
					altered := c
					altered.KeyScope.lightProfile = true
					if _, err := e.svc.keys.lightDelegation.authorizeSpendingDelegation(t.Context(), altered, plan, nil); err == nil {
						t.Fatal("Light key scope substituted")
					}
				})
			}
		}
	}
}

func TestSpendingDelegationSharedLightAndReadBoundaries(t *testing.T) {
	f, handler, now := delegationAPI(t)
	e := f.f.env
	delegationAPIPost(t, handler, "schedule", f.p.Request, 200)
	c, err := e.svc.delegationContract(f.p.Request.VaultID, false)
	if err != nil {
		t.Fatal(err)
	}
	r := spendingDelegationReadRequest{Program: c.Binding.Program, DescriptorHash: c.DescriptorHash, VaultID: c.Binding.VaultID, ExpiresAt: now.Unix() + 120}
	sign := func(purpose string) {
		var body any
		if purpose == "list" {
			body = struct {
				Program          string `json:"program"`
				DescriptorHash   string `json:"descriptorHash"`
				VaultID          string `json:"vaultId"`
				AfterOperationID string `json:"afterOperationId"`
				ExpiresAt        int64  `json:"expiresAt"`
			}{r.Program, r.DescriptorHash, r.VaultID, r.AfterOperationID, r.ExpiresAt}
		} else {
			body = struct {
				Program        string `json:"program"`
				DescriptorHash string `json:"descriptorHash"`
				VaultID        string `json:"vaultId"`
				OperationID    string `json:"operationId"`
				ExpiresAt      int64  `json:"expiresAt"`
			}{r.Program, r.DescriptorHash, r.VaultID, r.OperationID, r.ExpiresAt}
		}
		digest, err := spendingDelegationDigest(purpose, body)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := schnorr.Sign(f.f.owner, digest)
		if err != nil {
			t.Fatal(err)
		}
		r.OwnerSignature = hex.EncodeToString(sig.Serialize())
	}
	sign("list")
	var listed lightDelegationListResponse
	if err := json.Unmarshal(spendingDelegationHTTP(t, e, "list", r, 200), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Operations) != 1 || listed.Operations[0].DescriptorHash != c.DescriptorHash || listed.Operations[0].Program != c.Binding.Program {
		t.Fatal("legacy operation not bound to shared context")
	}
	r.OperationID = f.p.Request.OperationID
	spendingDelegationHTTP(t, e, "status", r, 400)
	sign("status")
	spendingDelegationHTTP(t, e, "status", r, 200)
	spendingDelegationHTTP(t, e, "cancel", r, 400)
	sign("cancel")
	spendingDelegationHTTP(t, e, "cancel", r, 200)
	set := spendingDelegationSetRequest{Program: c.Binding.Program, DescriptorHash: c.DescriptorHash, VaultID: c.Binding.VaultID, SetID: strings.Repeat("88", 16), Plans: []spendingDelegationInput{{OperationID: strings.Repeat("99", 16), Intent: f.p.Request.Intent, ForfeitTxs: f.p.Request.ForfeitTxs, DeleteIntent: f.p.Request.DeleteIntent, ExpiresAt: f.p.Request.ExpiresAt}}}
	digest, err := set.planDigest(set.Plans[0])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(f.f.owner, digest)
	if err != nil {
		t.Fatal(err)
	}
	set.Plans[0].OwnerSignature = hex.EncodeToString(sig.Serialize())
	digest, err = set.digest()
	if err != nil {
		t.Fatal(err)
	}
	sig, err = schnorr.Sign(f.f.owner, digest)
	if err != nil {
		t.Fatal(err)
	}
	set.OwnerSignature = hex.EncodeToString(sig.Serialize())
	spendingDelegationHTTP(t, e, "schedule", set, 200)
	// Older clients can still list their compatible Light operation; a new
	// context must not be misread as the original Light descriptor hash.
	legacy := delegationAPIList(t, f, "", now.Unix()+120)
	delegationAPIPost(t, handler, "list", legacy, 200)
}

func TestSpendingDelegationRejectsNewAuthorityWithoutCompleteAuthorization(t *testing.T) {
	e, c, set := spendingDelegationFixture(t, deployment.NetworkMainnet, "advanced", true)
	for name, mutate := range map[string]func(*spendingDelegationSetRequest){
		"different direct digest": func(r *spendingDelegationSetRequest) { r.Authorization.DirectSig = strings.Repeat("01", 64) },
		"different credential":    func(r *spendingDelegationSetRequest) { r.Authorization.CredentialID = "abcd" },
		"invalid assertion":       func(r *spendingDelegationSetRequest) { r.Authorization.Signature = "00" },
		"subset":                  func(r *spendingDelegationSetRequest) { r.Plans = r.Plans[:1] },
		"context":                 func(r *spendingDelegationSetRequest) { r.DescriptorHash = strings.Repeat("00", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			r := set
			authorization := *set.Authorization
			r.Authorization = &authorization
			mutate(&r)
			spendingDelegationHTTP(t, e, "schedule", r, 400)
			all, err := e.ledger.ListLightDelegations(t.Context())
			if err != nil || len(all) != 0 {
				t.Fatalf("rejected set persisted: %v", err)
			}
		})
	}
	// Rejections leave the original assertion usable for its exact bounded set.
	spendingDelegationHTTP(t, e, "schedule", set, 200)
	all, err := e.ledger.ListLightDelegations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p, err := delegationStoredPlanForContract(&all[0], c)
	if err != nil {
		t.Fatal(err)
	}
	keys := e.svc.keys.lightDelegation
	for name, mutate := range map[string]func(*renewalContract){
		"cooperative leaf": func(v *renewalContract) { v.Tree.SpendLeaf = []byte{txscript.OP_TRUE} },
		"control block":    func(v *renewalContract) { v.Tree.SpendControl = append(bytes.Clone(v.Tree.SpendControl), 0) },
		"recovery leaves":  func(v *renewalContract) { v.Tree.RevealedScripts = v.Tree.RevealedScripts[:2] },
		"scoped vault":     func(v *renewalContract) { v.KeyScope.vaultID = strings.Repeat("ef", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			tree := *c.Tree
			changed.Tree = &tree
			mutate(&changed)
			if _, err := keys.authorizeSpendingDelegation(t.Context(), changed, p, nil); err == nil {
				t.Fatal("mutated enrolled authority signed")
			}
		})
	}
}

func TestSpendingDelegationSetSizeRejectedBeforeEnrollmentOrVerification(t *testing.T) {
	// A bare service intentionally has no ledger, resolver, or keys. The count
	// bound must fail before any of those or the verification permit is used.
	for _, count := range []int{0, maxSpendingRenewalPlans + 1} {
		_, err := (&Service{}).scheduleSpendingDelegationSet(t.Context(), spendingDelegationSetRequest{Plans: make([]spendingDelegationInput, count)})
		if err == nil || err.Error() != "renewal set size" {
			t.Fatalf("size %d: %v", count, err)
		}
	}
}

func TestSpendingDelegationFinalizedRetryKeepsRecoveryOnStatusOnly(t *testing.T) {
	f, _, now := delegationAPI(t)
	e := f.f.env
	c, err := e.svc.delegationContract(f.p.Request.VaultID, false)
	if err != nil {
		t.Fatal(err)
	}
	request := f.p.Request
	set := spendingDelegationSetRequest{Program: c.Binding.Program, DescriptorHash: c.DescriptorHash, VaultID: c.Binding.VaultID, SetID: strings.Repeat("77", 16), Plans: []spendingDelegationInput{{OperationID: request.OperationID, Intent: request.Intent, ForfeitTxs: request.ForfeitTxs, DeleteIntent: request.DeleteIntent, ExpiresAt: request.ExpiresAt}}}
	sign := func(digest []byte, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := schnorr.Sign(f.f.owner, digest)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(sig.Serialize())
	}
	set.Plans[0].OwnerSignature = sign(set.planDigest(set.Plans[0]))
	set.OwnerSignature = sign(set.digest())
	spendingDelegationHTTP(t, e, "schedule", set, 200)
	saved, err := e.svc.getDelegation(t.Context(), set.VaultID, request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := delegationStoredPlanForContract(saved, c)
	if err != nil {
		t.Fatal(err)
	}
	// Use a real signed graph and the common final verifier; only the already
	// tested Operator transport is omitted from this response-size regression.
	final, err := e.svc.prepareSpendingDelegationFinal(t.Context(), p, c, lightDelegationPreparedTree{Tree: f.tree}, f.final.CommitmentPSBT, f.final.VtxoTree, f.final.Connectors)
	if err != nil {
		t.Fatal(err)
	}
	*now = time.Unix(p.ValidAt, 0)
	for _, phase := range []string{"claimed", "register_authorized", "register_dispatched", "register_result", "batch_started", "tree_prepared", "nonces_committed", "tree_signed", "final_authorized"} {
		payload := `{}`
		if phase == "final_authorized" {
			raw, err := json.Marshal(final)
			if err != nil {
				t.Fatal(err)
			}
			payload = string(raw)
		}
		if _, err := e.ledger.AdvanceLightDelegation(t.Context(), policy.LightDelegationEvent{OperationID: request.OperationID, Phase: phase, Evidence: payload}, c.Binding.SpendingPolicy.PeriodAllowanceSats); err != nil {
			t.Fatal(phase, err)
		}
	}
	var receipt spendingDelegationSetResponse
	if err := json.Unmarshal(spendingDelegationHTTP(t, e, "schedule", set, 200), &receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.Operations) != 1 || receipt.Operations[0].Recovery != nil || receipt.Operations[0].ReceiverTxid == "" {
		t.Fatal("schedule retry must retain verified identity without embedding recovery graph")
	}
	r := spendingDelegationReadRequest{Program: c.Binding.Program, DescriptorHash: c.DescriptorHash, VaultID: set.VaultID, OperationID: request.OperationID, ExpiresAt: now.Unix() + 120}
	r.OwnerSignature = sign(spendingDelegationDigest("status", struct {
		Program        string `json:"program"`
		DescriptorHash string `json:"descriptorHash"`
		VaultID        string `json:"vaultId"`
		OperationID    string `json:"operationId"`
		ExpiresAt      int64  `json:"expiresAt"`
	}{r.Program, r.DescriptorHash, r.VaultID, r.OperationID, r.ExpiresAt}))
	var status lightDelegationResponse
	if err := json.Unmarshal(spendingDelegationHTTP(t, e, "status", r, 200), &status); err != nil {
		t.Fatal(err)
	}
	if status.Recovery == nil || len(status.Recovery.VtxoTree) == 0 || status.ReceiverTxid != receipt.Operations[0].ReceiverTxid {
		t.Fatal("status lost the verified replacement graph")
	}
}
