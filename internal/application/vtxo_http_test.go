package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/ports"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
)

type stubArkResolver struct {
	vtxos        []ports.ResolvedVtxo
	checkpoint   []byte
	signer       []byte
	spentBy      string
	spentErr     error
	changeExists bool
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
	if s.spentBy == "" {
		return fmt.Errorf("reserved outpoints not spent")
	}
	if !strings.EqualFold(s.spentBy, arkTxid) {
		return fmt.Errorf("reserved outpoint not spent by ark txid")
	}
	return nil
}

func (s stubArkResolver) ChangeVtxoFromArkTx(_ context.Context, _ []byte, arkTxid string, vout uint32, _ uint64) error {
	if !s.changeExists || vout != 1 || !strings.EqualFold(s.spentBy, arkTxid) {
		return fmt.Errorf("change vtxo not yet projected")
	}
	return nil
}

func (s stubArkResolver) CheckpointTapscript() []byte { return append([]byte(nil), s.checkpoint...) }
func (s stubArkResolver) OperatorSignerPub() []byte   { return append([]byte(nil), s.signer...) }
func (s stubArkResolver) Network() string             { return program.NetworkMutinynet }

func vtxoTestEnv(t *testing.T) (*env, *stubArkResolver, *btcec.PrivateKey) {
	t.Helper()
	e := newEnv(t)
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
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(k.PubKey()), &arklib.MutinyNetSigNetParams)
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
		Version: 0, HRP: arklib.BitcoinMutinyNet.Addr,
		Signer: operator.PubKey(), VtxoTapKey: destination.PubKey(),
	}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func signedReserveRequest(t *testing.T, e *env, req VtxoReserveRequest) VtxoReserveRequest {
	t.Helper()
	destScript, _, err := e.svc.decodeVtxoDest(req.DestAddress)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := policy.ComputeVtxoReserveDigest(req.OperationID, req.VaultID, req.Purpose, destScript, req.AmountSats)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(e.hot, digest)
	if err != nil {
		t.Fatal(err)
	}
	req.PhoneSignature = hex.EncodeToString(sig.Serialize())
	return req
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
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"operationId":"`+strings.Repeat("01", 16)+`","vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "REJECTED") {
		t.Fatalf("pack without exit = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReserveRejectsBoardPurpose(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"operationId":"`+strings.Repeat("01", 16)+`","vaultId":"`+fixture.VaultID+`","purpose":"board","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
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
	if !strings.HasPrefix(status.VtxoBoardingAddress, "tb1p") || len(status.VtxoBoardingScript) != 68 {
		t.Fatalf("boarding descriptor = %s %s", status.VtxoBoardingAddress, status.VtxoBoardingScript)
	}
	policyTree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	if status.VtxoBoardingAddress == policyTree.OnchainAddress ||
		status.VtxoBoardingScript == hex.EncodeToString(policyTree.PkScript) {
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
	tree, err := svc.buildVtxoBoardTree(enrolledSnapshot{PhoneBIP340: phone.PubKey()})
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
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("01", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: dest, AmountSats: 30_000,
	})
	raw := httpJSON(t, h, http.MethodPost, "/v1/vtxo/reserve", req)
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

func TestReserveRequiresPhoneAuthenticationBeforePersisting(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("19", 32), Vout: 0, ValueSats: 45_000, Script: tree.PkScript,
	}}
	req := VtxoReserveRequest{
		OperationID: strings.Repeat("18", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	}
	if _, err := e.svc.ReserveVtxo(context.Background(), req); err == nil || !strings.Contains(err.Error(), "phoneSignature") {
		t.Fatalf("unauthenticated reserve = %v", err)
	}
	req = signedReserveRequest(t, e, req)
	req.AmountSats++
	if _, err := e.svc.ReserveVtxo(context.Background(), req); err == nil || !strings.Contains(err.Error(), "phoneSignature") {
		t.Fatalf("mutated authenticated reserve = %v", err)
	}
	ops, err := e.svc.Ledger.ListVtxoOperations(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 0 {
		t.Fatalf("rejected reserve persisted %d operations", len(ops))
	}
}

func TestReserveLostResponseReplaysExactReservation(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("21", 32), Vout: 2, ValueSats: 45_000, Script: tree.PkScript,
	}}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("22", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	})
	first, err := e.svc.ReserveVtxo(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// Discard first as if the HTTP response was lost, then retry the exact
	// durable request identifier.
	second, err := e.svc.ReserveVtxo(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("retry changed reservation:\nfirst=%+v\nsecond=%+v", first, second)
	}
	ops, err := e.svc.Ledger.ListVtxoOperations(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 {
		t.Fatalf("exact retry created %d operations", len(ops))
	}
}

func TestReserveOperationIDRejectsMutation(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("23", 32), Vout: 0, ValueSats: 45_000, Script: tree.PkScript,
	}}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("24", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	})
	if _, err := e.svc.ReserveVtxo(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.AmountSats++
	req = signedReserveRequest(t, e, req)
	if _, err := e.svc.ReserveVtxo(context.Background(), req); err == nil || !strings.Contains(err.Error(), "different reserve request") {
		t.Fatalf("mutated retry = %v", err)
	}
}

func TestConcurrentExactReserveHasOneDurableOperation(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("25", 32), Vout: 0, ValueSats: 45_000, Script: tree.PkScript,
	}}
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("26", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 30_000,
	})
	start := make(chan struct{})
	results := make(chan *VtxoReserveResponse, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out, err := e.svc.ReserveVtxo(context.Background(), req)
			results <- out
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first *VtxoReserveResponse
	for out := range results {
		if first == nil {
			first = out
		} else if !reflect.DeepEqual(first, out) {
			t.Fatalf("concurrent exact retry changed reservation: %+v != %+v", first, out)
		}
	}
	ops, err := e.svc.Ledger.ListVtxoOperations(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 {
		t.Fatalf("concurrent retry created %d operations", len(ops))
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
	req := signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("01", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 10_000,
	})
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, string(raw))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "duplicate") {
		t.Fatalf("duplicate outpoints = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReserveRejectsBitcoinDestinationInRegularVtxoSlice(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"operationId":"`+strings.Repeat("01", 16)+`","vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+mustTaprootDest(t)+`","amountSats":10000}`)
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
		Version: 0, HRP: arklib.BitcoinMutinyNet.Addr,
		Signer: wrongOperator.PubKey(), VtxoTapKey: destination.PubKey(),
	}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, `{"operationId":"`+strings.Repeat("01", 16)+`","vaultId":"`+fixture.VaultID+`","purpose":"spend","destAddress":"`+addr+`","amountSats":10000}`)
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
	stored, swapped, err := e.svc.Ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateReserved, func() policy.VtxoOperation {
		signed := stored
		signed.State = policy.VtxoStateSigned
		return signed
	}())
	if err != nil || !swapped {
		t.Fatalf("reserve -> signed: swapped=%v err=%v", swapped, err)
	}
	stored.State = policy.VtxoStateSubmitted
	stored.ArkTxid = arkTxid
	if _, swapped, err := e.svc.Ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateSigned, stored); err != nil || !swapped {
		t.Fatal(err)
	}
	_, err = e.svc.FinalizeVtxo(context.Background(), VtxoFinalizeRequest{
		VaultID: fixture.VaultID, OperationID: op.OperationID, BundleDigest: hex.EncodeToString(digest), ArkTxid: arkTxid,
	})
	if err == nil || !strings.Contains(err.Error(), "spent by ark txid") {
		t.Fatalf("disappearance-only finalize = %v", err)
	}
	resolver.spentBy = arkTxid
	_, err = e.svc.FinalizeVtxo(context.Background(), VtxoFinalizeRequest{
		VaultID: fixture.VaultID, OperationID: op.OperationID, BundleDigest: hex.EncodeToString(digest), ArkTxid: arkTxid,
	})
	if err == nil || !strings.Contains(err.Error(), "spent by ark txid") {
		t.Fatalf("accept-only spend treated as finalized: %v", err)
	}
	resolver.changeExists = true
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

func insertSubmittedSpend(t *testing.T, e *env, operationID, arkTxid string, treePkScript []byte) {
	t.Helper()
	now := e.svc.vtxoNow().Format(timeRFC3339)
	digest := bytes.Repeat([]byte{0x33}, 32)
	in := policy.VtxoOperationInput{
		Txid: bytes.Repeat([]byte{0x11}, 32), Vout: 0, ValueSats: 20_000, Script: bytes.Clone(treePkScript),
	}
	if err := e.svc.Ledger.ReserveVtxoOperation(context.Background(), policy.VtxoOperation{
		OperationID: operationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend, BundleDigest: digest,
		State: policy.VtxoStateReserved, AmountSats: 10_000, DestScript: bytes.Repeat([]byte{0x51}, 34), ChangeScript: bytes.Clone(treePkScript),
		ExpiresAt: e.svc.vtxoNow().Add(vtxoReserveAuthorizeTimeout).Format(timeRFC3339), CreatedAt: now,
	}, []policy.VtxoOperationInput{in}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	stored, err := e.svc.Ledger.GetVtxoOperation(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = policy.VtxoStateSubmitted
	stored.ArkTxid = arkTxid
	stored, swapped, err := e.svc.Ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateReserved, func() policy.VtxoOperation {
		signed := stored
		signed.State = policy.VtxoStateSigned
		return signed
	}())
	if err != nil || !swapped {
		t.Fatalf("reserve -> signed: swapped=%v err=%v", swapped, err)
	}
	stored.State = policy.VtxoStateSubmitted
	stored.ArkTxid = arkTxid
	if _, swapped, err := e.svc.Ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateSigned, stored); err != nil || !swapped {
		t.Fatal(err)
	}
}

func TestRequestedOperationReconcilesWhenIndexerShowsStoredArkTxid(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	arkTxid := strings.Repeat("ab", 32)
	insertSubmittedSpend(t, e, "spend-submitted", arkTxid, tree.PkScript)
	resolver.spentBy = arkTxid
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-submitted")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateSubmitted {
		t.Fatalf("accept-only spend was finalized: %s", view.State)
	}
	resolver.changeExists = true
	view, err = e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-submitted")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateFinalized {
		t.Fatalf("submitted was not reconciled: %s", view.State)
	}
}

func TestRequestedOperationDoesNotTrustADifferentArkTxid(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	storedTxid := strings.Repeat("ab", 32)
	insertSubmittedSpend(t, e, "spend-foreign", storedTxid, tree.PkScript)
	resolver.spentBy = strings.Repeat("cd", 32)
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-foreign")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateUnresolved {
		t.Fatalf("foreign spend was not quarantined: %s", view.State)
	}
	spent, err := e.svc.Ledger.SpentInPeriod(context.Background(), fixture.VaultID, "")
	if err != nil {
		t.Fatal(err)
	}
	if spent < 10_000 {
		t.Fatalf("unresolved spend released allowance: %d", spent)
	}
}

func TestGetVtxoOperationViewKeepsPendingSubmissionPending(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	arkTxid := strings.Repeat("ab", 32)
	insertSubmittedSpend(t, e, "spend-status", arkTxid, tree.PkScript)
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-status")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateSubmitted || view.ArkTxid != arkTxid {
		t.Fatalf("view = %+v", view)
	}
}

func TestGetVtxoOperationViewReturnsSignedPsbt(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	arkTxid := strings.Repeat("cd", 32)
	insertSubmittedSpend(t, e, "spend-signed", arkTxid, tree.PkScript)
	stored, err := e.svc.Ledger.GetVtxoOperation(context.Background(), "spend-signed")
	if err != nil {
		t.Fatal(err)
	}
	// The helper created a submitted operation. Use a separate current
	// reservation because state transitions are deliberately irreversible.
	stored.OperationID = "spend-signed-current"
	stored.State = policy.VtxoStateReserved
	stored.AuthorizedPSBT = "cHNidP9signed"
	stored.ArkTxid = arkTxid
	stored.IntegrityMAC = nil
	if err := e.svc.Ledger.ReserveVtxoOperation(context.Background(), stored, []policy.VtxoOperationInput{{
		Txid: bytes.Repeat([]byte{0x12}, 32), Vout: 0, ValueSats: 20_000, Script: bytes.Clone(tree.PkScript),
	}}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	stored, err = e.svc.Ledger.GetVtxoOperation(context.Background(), stored.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = policy.VtxoStateSigned
	if _, swapped, err := e.svc.Ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateReserved, stored); err != nil || !swapped {
		t.Fatalf("reserve -> signed: swapped=%v err=%v", swapped, err)
	}
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, stored.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateSigned || view.AuthorizedPsbt != "cHNidP9signed" || view.ArkTxid != arkTxid {
		t.Fatalf("signed view = %+v", view)
	}
	if len(view.CheckpointPsbts) != 0 {
		t.Fatalf("signed view leaked checkpoints: %+v", view.CheckpointPsbts)
	}
}

func TestGetVtxoOperationViewAbortsExpiredReservation(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	snap := e.svc.snapshot(fixture.VaultID)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	now := e.svc.vtxoNow()
	digest := bytes.Repeat([]byte{0x33}, 32)
	in := policy.VtxoOperationInput{
		Txid: bytes.Repeat([]byte{0x11}, 32), Vout: 0, ValueSats: 20_000, Script: bytes.Clone(tree.PkScript),
	}
	if err := e.svc.Ledger.ReserveVtxoOperation(context.Background(), policy.VtxoOperation{
		OperationID: "spend-expired", VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend, BundleDigest: digest,
		State: policy.VtxoStateReserved, AmountSats: 10_000, DestScript: bytes.Repeat([]byte{0x51}, 34), ChangeScript: bytes.Clone(tree.PkScript),
		ExpiresAt: now.Add(-time.Second).Format(timeRFC3339), CreatedAt: now.Add(-2 * time.Minute).Format(timeRFC3339),
	}, []policy.VtxoOperationInput{in}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "spend-expired")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateAborted {
		t.Fatalf("expired reservation = %+v", view)
	}
	stored, err := e.svc.Ledger.GetVtxoOperation(context.Background(), "spend-expired")
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != policy.VtxoStateAborted {
		t.Fatalf("expired reservation was not persisted aborted: %s", stored.State)
	}
}

const timeRFC3339 = "2006-01-02T15:04:05Z"
