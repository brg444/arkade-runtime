package application

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// This transport stand-in signs only input 0 with the fixture Emulator's
// program key. Real upstream HTTP/interpreter qualification is a separate gate.
type connectorTestSigner struct {
	key   *btcec.PrivateKey
	calls int
	fail  bool
}

func (s *connectorTestSigner) Sign(_ context.Context, p *psbt.Packet) (*psbt.Packet, error) {
	s.calls++
	if s.fail {
		return nil, errors.New("fixture emulator unavailable")
	}
	leaf := txscript.NewBaseTapLeaf(p.Inputs[0].TaprootLeafScript[0].Script)
	prev, err := requireConnectorPrevouts(p)
	if err != nil {
		return nil, err
	}
	sig, err := txscript.RawTxInTapscriptSignature(p.UnsignedTx, txscript.NewTxSigHashes(p.UnsignedTx, prev), 0, p.Inputs[0].WitnessUtxo.Value, p.Inputs[0].WitnessUtxo.PkScript, leaf, txscript.SigHashDefault, s.key)
	if err != nil {
		return nil, err
	}
	hash := leaf.TapHash()
	p.Inputs[0].TaprootScriptSpendSig = append(p.Inputs[0].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{XOnlyPubKey: schnorr.SerializePubKey(s.key.PubKey()), LeafHash: hash[:], Signature: sig, SigHash: txscript.SigHashDefault})
	return p, nil
}

type withdrawalChain struct {
	states      map[string]connectorOutpointState
	confirmed   map[string]bool
	unavailable bool
}

func (c *withdrawalChain) confirmedOutpoint(_ context.Context, id string, vout uint32) (connectorOutpointState, error) {
	if c.unavailable {
		return connectorOutpointState{}, errors.New("offline")
	}
	s, ok := c.states[id]
	if !ok || vout != 0 {
		return s, errors.New("missing")
	}
	return s, nil
}
func (c *withdrawalChain) confirmedTransaction(_ context.Context, id string) (string, int64, error) {
	if c.unavailable {
		return "", 0, errors.New("offline")
	}
	if !c.confirmed[id] {
		return "", 0, errConnectorTransactionUnconfirmed
	}
	return strings.Repeat("ab", 32), 100, nil
}

type withdrawalFixture struct {
	f            *connectorFixture
	id           string
	req          RegisterRequest
	pass, direct *ecdsa.PrivateKey
	phone        *btcec.PrivateKey
	raw          string
	txid         string
	chain        *withdrawalChain
	signer       *connectorTestSigner
}

func newWithdrawalFixture(t *testing.T) *withdrawalFixture {
	t.Helper()
	f := newConnectorFixture(t, deployment.NetworkMainnet)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	pass, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	req := connectorEnrollRequestForNetwork(t, f.network, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.NativeSegwit, false)
	req.WebAuthnP256 = hex.EncodeToString(webauthn.CompressedP256(pass))
	req.PhoneDirectP256 = hex.EncodeToString(webauthn.CompressedP256(direct))
	id, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x78}, 32)
	putConnectorInvite(t, f.led, token)
	req = enrollConnectorVault(t, f.svc, id, token, req)
	cred, err := f.svc.loadVerifiedCredentialFor(id)
	if err != nil {
		t.Fatal(err)
	}
	fam, err := f.svc.rebuildConnectorFamily(cred)
	if err != nil {
		t.Fatal(err)
	}
	a, b := wire.NewMsgTx(2), wire.NewMsgTx(2)
	a.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 99}, nil, nil))
	b.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 98}, nil, nil))
	a.AddTxOut(wire.NewTxOut(10000, cred.SavingsScript))
	b.AddTxOut(wire.NewTxOut(1000, fam.Rules.ConnectorScript))
	ap, bp := wire.OutPoint{Hash: a.TxHash()}, wire.OutPoint{Hash: b.TxHash()}
	guardian, err := btcec.ParsePubKey(cred.VaultCosignerBase)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := txscript.PayToTaprootScript(connectorKey(55).PubKey())
	if err != nil {
		t.Fatal(err)
	}
	draft, err := connector.Prepare(connector.Request{Rules: fam.Rules, Parents: connector.Parents{ap: a, bp: b}, Savings: ap, Connector: bp, SavingsScript: cred.SavingsScript, Leaf: fam.Leaf, Control: fam.Control, DestinationScript: dest, Phone: phone.PubKey(), GuardianBase: guardian, EmulatorBase: f.operator.PubKey(), Origin: connector.KeyOrigin{Type: connector.NativeSegwit, PublicKey: hardware.PubKey().SerializeCompressed(), Fingerprint: req.ConnectorFingerprint, Path: req.ConnectorPath}, AmountSats: 8000, FeeSats: 1000})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := draft.PSBT()
	if err != nil {
		t.Fatal(err)
	}
	signConnectorInputWithPhone(t, packet, phone, fam.Leaf)
	signer := &connectorTestSigner{key: arkade.ComputeArkadeScriptPrivateKey(f.operator, arkade.ArkadeScriptHash(fam.Program))}
	f.svc.keys.publicEmulator = &pinnedPublicEmulatorOperation{signer: signer}
	chain := &withdrawalChain{states: map[string]connectorOutpointState{ap.Hash.String(): {ValueSats: 10000, PkScript: cred.SavingsScript}, bp.Hash.String(): {ValueSats: 1000, PkScript: fam.Rules.ConnectorScript}}, confirmed: map[string]bool{}}
	f.svc.connectorChain = chain
	return &withdrawalFixture{f: f, id: id, req: req, pass: pass, direct: direct, phone: phone, raw: encodeConnectorStage(t, packet), txid: packet.UnsignedTx.TxHash().String(), chain: chain, signer: signer}
}
func (w *withdrawalFixture) assertion(t *testing.T, candidate string) SessionAssertionRequest {
	t.Helper()
	issued, err := w.f.svc.IssueConnectorWithdrawChallenge(t.Context(), w.id, candidate)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := hex.DecodeString(issued.Challenge)
	cred, _ := hex.DecodeString(w.req.CredentialID)
	assertion, err := webauthn.Synth(w.pass, cred, challenge, w.f.origin, w.f.rpid, true, true)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := webauthn.SignDigestLowS(w.direct, passkeySessionProofDigest(passkeyPurposeConnectorWithdraw, challenge, cred))
	if err != nil {
		t.Fatal(err)
	}
	return SessionAssertionRequest{ChallengeID: issued.ChallengeID, CredentialID: w.req.CredentialID, ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON), AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature), DirectProof: hex.EncodeToString(proof)}
}
func (w *withdrawalFixture) authorize(t *testing.T) (*ConnectorWithdrawResponse, error) {
	return w.f.svc.AuthorizeConnectorWithdrawal(t.Context(), ConnectorWithdrawRequest{VaultID: w.id, PSBT: w.raw, SessionAssertionRequest: w.assertion(t, w.txid)})
}
func TestConnectorWithdrawalStagesReplayAndConfirmation(t *testing.T) {
	w := newWithdrawalFixture(t)
	response, err := w.authorize(t)
	if err != nil {
		t.Fatal(err)
	}
	if response.Replay || w.signer.calls != 1 {
		t.Fatal("first authorization")
	}
	p := decodeConnectorStage(t, response.SignedPSBT)
	if len(p.Inputs[0].TaprootScriptSpendSig) != 3 {
		t.Fatal("incomplete Savings stage")
	}
	for id, state := range w.chain.states {
		state.Spent = true
		state.SpendingTxid = w.txid
		w.chain.states[id] = state
	}
	replay, err := w.authorize(t)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replay || replay.OperationID != response.OperationID || replay.SignedPSBT != response.SignedPSBT || w.signer.calls != 1 {
		t.Fatal("replay regenerated authority")
	}
	w.chain.confirmed[w.txid] = true
	view, err := w.f.svc.GetConnectorOperationView(t.Context(), w.id, response.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Verified || view.Resolution != policy.ConnectorResolutionConfirmed {
		t.Fatalf("confirmation: %+v", view)
	}
	w.chain.unavailable = true
	view, err = w.f.svc.GetConnectorOperationView(t.Context(), w.id, response.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Verified || view.Resolution != policy.ConnectorResolutionConfirmed {
		t.Fatal("outage trusted or erased confirmation")
	}
	spent, err := w.f.led.SpentInPeriod(t.Context(), w.id, w.f.led.PeriodStart())
	if err != nil || spent != 0 {
		t.Fatal("Savings debited Spending allowance", spent, err)
	}
}
func TestConnectorWithdrawalResumesEmulatorFailure(t *testing.T) {
	w := newWithdrawalFixture(t)
	w.signer.fail = true
	if _, err := w.authorize(t); err == nil {
		t.Fatal("expected emulator outage")
	}
	w.signer.fail = false
	response, err := w.authorize(t)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Replay || w.signer.calls != 2 {
		t.Fatal("failed candidate did not resume")
	}
}
func TestConnectorWithdrawalRejectsUnboundApproval(t *testing.T) {
	for _, mode := range []string{"candidate", "proof", "spent", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			w := newWithdrawalFixture(t)
			candidate := w.txid
			if mode == "candidate" {
				candidate = strings.Repeat("aa", 32)
			}
			assertion := w.assertion(t, candidate)
			if mode == "proof" {
				assertion.DirectProof = strings.Repeat("00", 64)
			}
			if mode == "spent" {
				for id, state := range w.chain.states {
					state.Spent = true
					state.SpendingTxid = strings.Repeat("ff", 32)
					w.chain.states[id] = state
				}
			}
			if mode == "unavailable" {
				w.chain.unavailable = true
			}
			if _, err := w.f.svc.AuthorizeConnectorWithdrawal(t.Context(), ConnectorWithdrawRequest{VaultID: w.id, PSBT: w.raw, SessionAssertionRequest: assertion}); err == nil {
				t.Fatal("unsafe authorization accepted")
			}
			if w.signer.calls != 0 {
				t.Fatal("signer called before authorization")
			}
		})
	}
}
func TestConnectorRecoveryBindingV5PreservesOrigin(t *testing.T) {
	w := newWithdrawalFixture(t)
	response, err := w.f.svc.BuildRecoveryBindingFor(w.id, RecoveryBindingRequest{EnvelopeNonce: strings.Repeat("11", 12), EnvelopeCiphertext: strings.Repeat("22", 48)})
	if err != nil {
		t.Fatal(err)
	}
	var binding recoveryBinding
	if err := json.Unmarshal([]byte(response.Binding), &binding); err != nil {
		t.Fatal(err)
	}
	st, err := w.f.svc.StatusFor(t.Context(), w.id)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Version != 5 || binding.ConnectorPub != w.req.ConnectorPub || binding.ConnectorFingerprint == nil || *binding.ConnectorFingerprint != w.req.ConnectorFingerprint || binding.ConnectorPath != connectorOriginPathString(w.req.ConnectorPath) || binding.ConnectorEnrollmentDigest != st.ConnectorEnrollment.EnrollmentDigest || binding.ConnectorDescriptorHash != w.req.DescriptorHash {
		t.Fatalf("binding mismatch: %+v", binding)
	}
	if bytes.Equal(recoveryBindingDigest(response.Binding), recoveryBindingDigestForDomain(recoveryBindingDomain, response.Binding)) {
		t.Fatal("connector used legacy domain")
	}
	if response.BindingDigest != hex.EncodeToString(recoveryBindingDigest(response.Binding)) {
		t.Fatal("wrong v5 digest")
	}
}

func TestConnectorWithdrawalReorgRetainsReservation(t *testing.T) {
	w := newWithdrawalFixture(t)
	response, err := w.authorize(t)
	if err != nil {
		t.Fatal(err)
	}
	for id, state := range w.chain.states {
		state.Spent = true
		state.SpendingTxid = w.txid
		w.chain.states[id] = state
	}
	w.chain.confirmed[w.txid] = true
	view, err := w.f.svc.GetConnectorOperationView(t.Context(), w.id, response.OperationID)
	if err != nil || view.Resolution != policy.ConnectorResolutionConfirmed {
		t.Fatal("confirmation", err)
	}
	delete(w.chain.confirmed, w.txid)
	for id, state := range w.chain.states {
		state.Spent = false
		state.SpendingTxid = ""
		w.chain.states[id] = state
	}
	view, err = w.f.svc.GetConnectorOperationView(t.Context(), w.id, response.OperationID)
	if err != nil || view.Resolution != policy.ConnectorResolutionNone {
		t.Fatal("reorg did not restore ownership", err)
	}
	replay, err := w.authorize(t)
	if err != nil || !replay.Replay || replay.OperationID != response.OperationID {
		t.Fatal("reorg lost candidate", err)
	}
}
