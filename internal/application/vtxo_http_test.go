package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/ports"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

type stubArkResolver struct {
	vtxos      []ports.ResolvedVtxo
	checkpoint []byte
	signer     []byte
	spentBy    string
	spentErr   error
}

func (s stubArkResolver) SpendableVtxos(context.Context, []byte) ([]ports.ResolvedVtxo, error) {
	return append([]ports.ResolvedVtxo(nil), s.vtxos...), nil
}

func (s stubArkResolver) ReservedSpentByArkTxid(_ context.Context, _ []byte, reserved []ports.ResolvedVtxo, arkTxid string) error {
	if s.spentErr != nil {
		return s.spentErr
	}
	if len(reserved) == 0 {
		return fmt.Errorf("reserved outpoints required")
	}
	if s.spentBy == "" || !strings.EqualFold(s.spentBy, arkTxid) {
		return fmt.Errorf("reserved outpoint not spent by ark txid")
	}
	return nil
}

func (s stubArkResolver) CheckpointTapscript() []byte { return append([]byte(nil), s.checkpoint...) }
func (s stubArkResolver) AdvertisedSignerPub() []byte { return append([]byte(nil), s.signer...) }
func (s stubArkResolver) Network() string             { return program.NetworkRegtest }

func vtxoTestEnv(t *testing.T) (*env, *stubArkResolver, *btcec.PrivateKey) {
	t.Helper()
	e := newEnv(t)
	if err := e.svc.Ledger.MigrateVtxoOperation(); err != nil {
		t.Fatal(err)
	}
	arkd, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver := &stubArkResolver{
		checkpoint: []byte{0xc0, 0x01},
		signer:     arkd.PubKey().SerializeCompressed(),
	}
	e.svc.ArkResolver = resolver
	return e, resolver, arkd
}

func mustTaprootDest(t *testing.T) string {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(k.PubKey()), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	return addr.EncodeAddress()
}

func mustArkadeDest(t *testing.T, operator *btcec.PrivateKey) string {
	t.Helper()
	destination, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := (&arklib.Address{
		Version: 0, HRP: arklib.BitcoinRegTest.Addr,
		Signer: operator.PubKey(), VtxoTapKey: destination.PubKey(),
	}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func mustOddYPrivateKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	for scalar := byte(1); scalar != 0; scalar++ {
		priv, _ := btcec.PrivKeyFromBytes([]byte{scalar})
		if priv.PubKey().SerializeCompressed()[0] == 0x03 {
			return priv
		}
	}
	t.Fatal("odd-Y private key not found")
	return nil
}

func TestDecodeVtxoDestAcceptsXOnlyOperatorWithOddY(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	operator := mustOddYPrivateKey(t)
	resolver.signer = operator.PubKey().SerializeCompressed()
	if _, _, err := e.svc.decodeVtxoDest(mustArkadeDest(t, operator)); err != nil {
		t.Fatalf("x-only Operator identity rejected: %v", err)
	}
}

func TestReserveSpendWithoutPackExitRejected(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	falseVal := false
	e.svc.vaultPolicyHasExit = &falseVal
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("ab", 32), Vout: 0, ValueSats: 40_000, Script: tree.PkScript,
	}}
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "REJECTED") {
		t.Fatalf("pack without exit = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReserveRejectsBoardPurpose(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"vaultId":"`+fixture.VaultID+`","purpose":"board","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "spend") {
		t.Fatalf("board purpose = %d %s", rec.Code, rec.Body.String())
	}
}

func TestBoardAuthorizeRouteRemoved(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/board/authorize", "application/json", fixture.Origin, `{"vaultId":"`+fixture.VaultID+`"}`)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("board route still present = %d %s", rec.Code, rec.Body.String())
	}
}

func TestVaultBoardV1StatusUsesDistinctStandardBoardingTree(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	status, err := e.svc.StatusFor(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if !status.VtxoBoardingActive || status.VtxoBoardingProgram != program.VaultBoardV1 {
		t.Fatalf("boarding status = %+v", status)
	}
	if status.VtxoBoardingExitDelay != program.VaultBoardV1ExitDelay ||
		status.VtxoBoardingExitDelayUnit != program.VaultBoardV1ExitDelayUnit {
		t.Fatalf("boarding delay = %d %s", status.VtxoBoardingExitDelay, status.VtxoBoardingExitDelayUnit)
	}
	if !strings.HasPrefix(status.VtxoBoardingAddress, "bcrt1p") || len(status.VtxoBoardingScript) != 68 {
		t.Fatalf("boarding descriptor = %s %s", status.VtxoBoardingAddress, status.VtxoBoardingScript)
	}
	if status.VtxoBoardingAddress == status.SpendingOnchainAddress ||
		status.VtxoBoardingScript == status.SpendingOnchainScript {
		t.Fatal("vault-board-v1 must be distinct from vault-policy-v1")
	}
}

func TestVaultBoardV1MatchesSDKVector(t *testing.T) {
	phone, _ := btcec.PrivKeyFromBytes(append(bytes.Repeat([]byte{0}, 31), 1))
	operator, _ := btcec.PrivKeyFromBytes(append(bytes.Repeat([]byte{0}, 31), 4))
	svc := &Service{
		Deployment:  deployment.Config{Network: deployment.NetworkMutinynet},
		ArkResolver: stubArkResolver{signer: operator.PubKey().SerializeCompressed()},
	}
	tree, err := svc.buildVtxoBoardTree(enrolledSnapshot{PhoneRoutineBIP340: phone.PubKey()})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tree.PkScript); got != "5120a077fad544f052d9730fb622fc1e737ef932eb7db907d2f1ee3792ce9e5d4d2c" {
		t.Fatalf("vault-board-v1 script = %s", got)
	}
	if tree.OnchainAddress != "tb1p5pml442y7pfdjuc0kc30c8nn0mun96mahyra9u0wx7fva8jaf5kqavcsgc" {
		t.Fatalf("vault-board-v1 address = %s", tree.OnchainAddress)
	}
}

func TestVaultBoardV1PrincipalIsAnInternalAllowanceTransfer(t *testing.T) {
	phone, _ := btcec.PrivKeyFromBytes(append(bytes.Repeat([]byte{0}, 31), 1))
	operator, _ := btcec.PrivKeyFromBytes(append(bytes.Repeat([]byte{0}, 31), 4))
	svc := &Service{
		Deployment:  deployment.Config{Network: deployment.NetworkMutinynet},
		ArkResolver: stubArkResolver{signer: operator.PubKey().SerializeCompressed()},
	}
	snap := enrolledSnapshot{PhoneRoutineBIP340: phone.PubKey()}
	tree, err := svc.buildVtxoBoardTree(snap)
	if err != nil {
		t.Fatal(err)
	}
	cl := &Classified{Recipient: &wire.TxOut{Value: 40_000, PkScript: tree.PkScript}, Fee: 1_500}
	if got, err := svc.routineRecipientDebit(snap, cl); err != nil || got != 0 {
		t.Fatalf("boarding principal debit = %d", got)
	}
	cl.Recipient.PkScript = append([]byte(nil), tree.PkScript...)
	cl.Recipient.PkScript[len(cl.Recipient.PkScript)-1] ^= 1
	if got, err := svc.routineRecipientDebit(snap, cl); err != nil || got != 40_000 {
		t.Fatalf("external recipient debit = %d", got)
	}
	if _, err := svc.routineRecipientDebit(snap, nil); err == nil {
		t.Fatal("missing classification did not fail closed")
	}
}

func TestReserveSpendHappyPathCanonicalDigest(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	low := strings.Repeat("01", 32)
	resolver.vtxos = []ports.ResolvedVtxo{
		{Txid: low, Vout: 1, ValueSats: 45_000, Script: tree.PkScript},
	}
	h := testAuthorizer(e.svc)
	dest := mustArkadeDest(t, arkd)
	raw := httpJSON(t, h, http.MethodPost, "/v1/vtxo/reserve", map[string]any{
		"vaultId": fixture.VaultID, "purpose": "spend", "destAddress": dest, "amountSats": 30_000,
	})
	var out VtxoReserveResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.OperationID == "" || len(out.BundleDigest) != 64 {
		t.Fatalf("reserve = %+v", out)
	}
	if _, err := hex.DecodeString(out.BundleDigest); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "unsigned") || strings.Contains(strings.ToLower(string(raw)), "psbt") {
		t.Fatal("reserve must not return an unsigned PSBT")
	}
	if out.CheckpointTapscript == "" {
		t.Fatal("spend reserve missing checkpoint tapscript")
	}
	digest, err := hex.DecodeString(out.BundleDigest)
	if err != nil {
		t.Fatal(err)
	}
	destScript, err := hex.DecodeString(out.DestScript)
	if err != nil {
		t.Fatal(err)
	}
	changeScript, err := hex.DecodeString(out.ChangeScript)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(changeScript, tree.PkScript) {
		t.Fatal("change must be vault-policy-v1")
	}
	op, err := e.svc.Ledger.GetVtxoOperation(context.Background(), out.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	swapped := []policy.VtxoBundleInput{
		{Txid: []byte(strings.ToUpper(low)), Vout: 1, ValueSats: 45_000},
	}
	again, err := policy.ComputeVtxoBundleDigest(policy.VtxoPurposeSpend, fixture.VaultID, destScript, changeScript, 30_000, out.FeeSats, swapped, op.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, again) {
		t.Fatal("bundle digest depends on input order")
	}
}

func TestReserveRejectsDuplicateOutpoints(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	txid := strings.Repeat("cd", 32)
	resolver.vtxos = []ports.ResolvedVtxo{
		{Txid: txid, Vout: 1, ValueSats: 20_000, Script: tree.PkScript},
		{Txid: strings.ToUpper(txid), Vout: 1, ValueSats: 21_000, Script: tree.PkScript},
	}
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+mustArkadeDest(t, arkd)+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "duplicate") {
		t.Fatalf("duplicate outpoints = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReserveRejectsBitcoinDestinationInRegularVtxoSlice(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Arkade address") {
		t.Fatalf("Bitcoin VTXO destination = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReserveRejectsArkadeDestinationForAnotherOperator(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	wrongOperator, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	destination, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := (&arklib.Address{
		Version: 0, HRP: arklib.BitcoinRegTest.Addr,
		Signer: wrongOperator.PubKey(), VtxoTapKey: destination.PubKey(),
	}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+addr+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Operator") {
		t.Fatalf("another Operator = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuthorizeSpendReplayRequiresFreshAuth(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	_, err := e.svc.AuthorizeVtxoSpend(context.Background(), VtxoAuthorizeRequest{
		VaultID: fixture.VaultID, OperationID: "missing", BundleDigest: strings.Repeat("00", 32),
	})
	if err == nil {
		t.Fatal("unsigned replay without reservation must fail")
	}
}

func TestAuthorizeSpendRejectsUnknownFieldsAndMissingGatewaySecret(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/authorize", "application/json", fixture.Origin, `{"vaultId":"x","extra":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d %s", rec.Code, rec.Body.String())
	}

	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	locked := AuthorizerHandler(e.svc)
	denied := httptest.NewRequest(http.MethodPost, "/v1/vtxo/authorize", strings.NewReader(`{"vaultId":"x"}`))
	denied.Header.Set("Content-Type", "application/json")
	denied.Header.Set("Origin", fixture.Origin)
	out := httptest.NewRecorder()
	locked.ServeHTTP(out, denied)
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("missing gateway secret = %d %s", out.Code, out.Body.String())
	}
}

func TestFinalizeRequiresSpentByArkTxid(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	now := e.svc.vtxoNow().Format(timeRFC3339)
	digest := bytes.Repeat([]byte{0x33}, 32)
	arkTxid := strings.Repeat("ab", 32)
	op := policy.VtxoOperation{
		OperationID:  "spend-final",
		VaultID:      fixture.VaultID,
		Purpose:      policy.VtxoPurposeSpend,
		BundleDigest: digest,
		State:        policy.VtxoStateSigned,
		AmountSats:   10_000,
		DestScript:   bytes.Repeat([]byte{0x51}, 34),
		ChangeScript: bytes.Clone(tree.PkScript),
		ArkTxid:      arkTxid,
		ExpiresAt:    e.svc.vtxoNow().Add(vtxoReserveAuthorizeTimeout).Format(timeRFC3339),
		CreatedAt:    now,
	}
	in := policy.VtxoOperationInput{
		Txid: bytes.Repeat([]byte{0x11}, 32), Vout: 0, ValueSats: 20_000, Script: bytes.Clone(tree.PkScript),
	}
	if err := e.svc.Ledger.ReserveVtxoOperation(context.Background(), policy.VtxoOperation{
		OperationID: op.OperationID, VaultID: op.VaultID, Purpose: op.Purpose, BundleDigest: op.BundleDigest,
		State: policy.VtxoStateReserved, AmountSats: op.AmountSats, DestScript: op.DestScript, ChangeScript: op.ChangeScript,
		ExpiresAt: op.ExpiresAt, CreatedAt: op.CreatedAt,
	}, []policy.VtxoOperationInput{in}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	stored, err := e.svc.Ledger.GetVtxoOperation(context.Background(), op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = policy.VtxoStateSubmitted
	stored.ArkTxid = arkTxid
	if err := e.svc.Ledger.PutVtxoOperation(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.FinalizeVtxo(context.Background(), VtxoFinalizeRequest{
		VaultID: fixture.VaultID, OperationID: op.OperationID, BundleDigest: hex.EncodeToString(digest), ArkTxid: arkTxid,
	})
	if err == nil || !strings.Contains(err.Error(), "spent by ark txid") {
		t.Fatalf("disappearance-only finalize = %v", err)
	}
	resolver.spentBy = arkTxid
	out, err := e.svc.FinalizeVtxo(context.Background(), VtxoFinalizeRequest{
		VaultID: fixture.VaultID, OperationID: op.OperationID, BundleDigest: hex.EncodeToString(digest), ArkTxid: arkTxid,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.State != policy.VtxoStateFinalized {
		t.Fatalf("finalize = %+v", out)
	}
}

const timeRFC3339 = "2006-01-02T15:04:05Z"
