package application

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/vault/savings"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type unavailableSigner struct{}

func (unavailableSigner) Sign(context.Context, *psbt.Packet) (*psbt.Packet, error) {
	return nil, errors.New("signer unavailable")
}

func TestSignTransitionRequiresClaimantSignature(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("cred-transition-auth"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignTransition(context.Background(), TransitionRequest{
		VaultID: start.VaultID, Purpose: "initiate", PSBT: "cHNidP8BAHECAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AQAAAAAAAAAA",
	}); err == nil {
		t.Fatal("signed a transition without a claimant signature")
	}
	st, err := svc.StatusFor(context.Background(), start.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if st.TemplateVersion != savings.Template {
		t.Fatalf("template %s", st.TemplateVersion)
	}
	if len(st.Warnings) == 0 {
		t.Fatal("expected recovery warnings on status")
	}
	if !strings.Contains(strings.Join(st.Warnings, " "), "cosigners") {
		t.Fatalf("warnings = %v", st.Warnings)
	}
}

func TestSignTransitionOnlyVerifiedClaimantsConsumeRateLimiter(t *testing.T) {
	e := newEnv(t)
	transitionRateMu.Lock()
	previous := transitionRateHits
	transitionRateHits = map[string][]time.Time{}
	transitionRateMu.Unlock()
	t.Cleanup(func() {
		transitionRateMu.Lock()
		transitionRateHits = previous
		transitionRateMu.Unlock()
	})

	for i := 0; i < 20; i++ {
		_, _ = e.svc.SignTransition(context.Background(), TransitionRequest{
			VaultID: fmt.Sprintf("unknown-vault-%d", i), Purpose: "initiate",
		})
	}
	transitionRateMu.Lock()
	if len(transitionRateHits) != 0 {
		t.Fatalf("unknown vault IDs entered rate state: %v", transitionRateHits)
	}
	transitionRateMu.Unlock()

	valid := hardwareInitiatePSBT(t, e.svc, e.externalOwner)
	unsigned, err := parsePSBT(valid)
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Inputs[0].TaprootScriptSpendSig = nil
	invalid, err := unsigned.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxTransitionsPerVaultPerMinute+1; i++ {
		if _, err := e.svc.SignTransition(context.Background(), TransitionRequest{
			VaultID: fixture.VaultID, Purpose: "initiate", PSBT: invalid,
		}); err == nil {
			t.Fatal("transition without a claimant signature unexpectedly signed")
		}
	}
	transitionRateMu.Lock()
	_, limited := transitionRateHits[fixture.VaultID]
	transitionRateMu.Unlock()
	if limited {
		t.Fatal("unverified requests consumed the enrolled vault rate limit")
	}

	response, err := e.svc.SignTransition(context.Background(), TransitionRequest{
		VaultID: fixture.VaultID, Purpose: "initiate", PSBT: valid,
	})
	if err != nil {
		t.Fatalf("verified claimant was blocked after invalid requests: %v", err)
	}
	if response == nil || response.SignedPSBT == "" {
		t.Fatalf("verified claimant response = %+v", response)
	}
	transitionRateMu.Lock()
	hits := len(transitionRateHits[fixture.VaultID])
	transitionRateMu.Unlock()
	if hits != 1 {
		t.Fatalf("verified claimant rate hits = %d, want 1", hits)
	}
}

func TestSignTransitionRetriesExactPendingRequestAfterRestart(t *testing.T) {
	e := newEnv(t)
	encoded := hardwareInitiatePSBT(t, e.svc, e.externalOwner)
	transition := TransitionRequest{VaultID: fixture.VaultID, Purpose: "initiate", PSBT: encoded}

	e.svc.keys = testKeys(t, e.master, unavailableSigner{})
	if _, err := e.svc.SignTransition(context.Background(), transition); err == nil || !strings.Contains(err.Error(), "signer unavailable") {
		t.Fatalf("first sign did not fail at the external signer: %v", err)
	}
	pending, err := e.ledger.GetRecoverySession(fixture.VaultID, transitionPrevTxID(t, encoded), 0, "initiate")
	if err != nil || pending == nil || len(pending.Signature) != 0 {
		t.Fatalf("pending session was not persisted: %+v %v", pending, err)
	}
	if err := e.ledger.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := policy.OpenLedger(e.dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	restarted := New(Deps{
		Stores: testStores(t, reopened), Deployment: e.svc.Deployment,
		IntegrityKey: append([]byte(nil), testCredentialIntegrityKey...),
		Keys:         testKeys(t, e.master, LocalSigner{Priv: e.operator}), VaultCosignerPub: e.master.PubKey(), ArkadeCosignerPub: e.operator.PubKey(),
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
		ArkResolver: e.svc.ArkResolver,
	})
	if err := restarted.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	response, err := restarted.SignTransition(context.Background(), transition)
	if err != nil {
		t.Fatalf("exact retry after restart: %v", err)
	}
	if response.SignedPSBT == "" || response.Replay {
		t.Fatalf("unexpected exact retry response: %+v", response)
	}
	replay, err := restarted.SignTransition(context.Background(), transition)
	if err != nil {
		t.Fatalf("signed replay after restart: %v", err)
	}
	if !replay.Replay || replay.SignedPSBT != response.SignedPSBT {
		t.Fatalf("signed replay changed the result: %+v", replay)
	}
}

func transitionPrevTxID(t *testing.T, encoded string) string {
	t.Helper()
	packet, err := parsePSBT(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return packet.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
}

func hardwareInitiatePSBT(t *testing.T, svc *Service, owner *btcec.PrivateKey) string {
	t.Helper()
	cred, err := svc.loadVerifiedCredentialFor(fixture.VaultID)
	if err != nil || cred == nil {
		t.Fatalf("credential: %+v %v", cred, err)
	}
	fam, err := svc.transitionFamily(cred)
	if err != nil {
		t.Fatal(err)
	}
	pair := fam.Initiate["hardware"]
	leaf, err := savings.Checksig(owner.PubKey(), pair.Vault, pair.Arkade)
	if err != nil {
		t.Fatal(err)
	}
	phone, err := btcec.ParsePubKey(cred.PhoneBIP340)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := savings.Checksig(phone, owner.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	phoneLeaf, err := savings.Checksig(phone, fam.Initiate["phone"].Vault, fam.Initiate["phone"].Arkade)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []txscript.TapLeaf{
		txscript.NewBaseTapLeaf(admin),
		txscript.NewBaseTapLeaf(phoneLeaf),
		txscript.NewBaseTapLeaf(leaf),
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	leafHash := leaves[2].TapHash()
	proofIndex, ok := tree.LeafProofIndex[leafHash]
	if !ok {
		t.Fatal("hardware initiate proof missing")
	}
	internal, err := savings.ContextInternalKeyTemplate(fixture.VaultID, "savings", "", savings.Template)
	if err != nil {
		t.Fatal(err)
	}
	control := tree.LeafMerkleProofs[proofIndex].ToControlBlock(internal)
	controlBytes, err := control.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	prev := wire.NewMsgTx(2)
	prev.AddTxIn(&wire.TxIn{Sequence: wire.MaxTxInSequenceNum})
	prev.AddTxOut(&wire.TxOut{Value: 100_000, PkScript: fam.Savings.PkScript})
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prev.TxHash(), Index: 0}, Sequence: savings.TransitionSequence})
	tx.AddTxOut(&wire.TxOut{Value: 98_760, PkScript: fam.Pending[savings.FamilyKey("hardware")].PkScript})
	tx.AddTxOut(&wire.TxOut{Value: savings.P2AValueSats, PkScript: mustDecode(t, savings.P2AScriptHex)})
	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: fam.InitiateAuth["savings-hardware"]})
	if err != nil {
		t.Fatal(err)
	}
	packetScript, err := (extension.Extension{emulatorPacket}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: packetScript})
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].WitnessUtxo = prev.TxOut[0]
	packet.Inputs[0].SighashType = txscript.SigHashDefault
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBytes, Script: leaf, LeafVersion: txscript.BaseLeafVersion,
	}}
	if err := txutils.SetArkPsbtField(packet, 0, arkade.PrevoutTxField, *prev); err != nil {
		t.Fatal(err)
	}
	claimantSig, err := signTapLeafAt(packet, 0, owner, leaf)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].TaprootScriptSpendSig = append(packet.Inputs[0].TaprootScriptSpendSig, claimantSig)
	encoded, err := packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
