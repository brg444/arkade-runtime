package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func delegationAPI(t *testing.T) (delegatedFixture, http.Handler, *time.Time) {
	t.Helper()
	f := newDelegatedFixture(t)
	now := f.now
	*now = time.Unix(f.p.ValidAt-60, 0)
	expiry := f.p.InputExpiresAt
	f.f.env.svc.ArkResolver = stubArkResolver{signer: f.f.tree.ArkdPub.SerializeCompressed(), network: f.f.descriptor.Network, vtxos: []ports.ResolvedVtxo{{Txid: f.p.Renewal.Txid, Vout: f.p.Renewal.Vout, ValueSats: uint64(f.p.Renewal.ValueSats), Script: f.f.tree.PkScript, ExpiresAt: &expiry, CommitmentTxids: []string{fmt.Sprintf("%064x", 1)}}}}
	if _, _, err := f.f.env.svc.delegationContext(f.f.descriptor.VaultID); err != nil {
		t.Fatalf("API fixture: %v", err)
	}
	return f, testAuthorizer(f.f.env.svc), now
}
func delegationAPIPost(t *testing.T, h http.Handler, route string, body any, want int) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/light/delegate/"+route, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", fixture.Origin)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != want {
		t.Fatalf("%s HTTP %d, want %d: %s", route, res.Code, want, res.Body.String())
	}
	return res.Body.Bytes()
}
func delegationAPISign(t *testing.T, f delegatedFixture, purpose string, body any) string {
	t.Helper()
	digest, err := delegationDigest(purpose, body)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(f.f.owner, digest)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sig.Serialize())
}
func delegationAPIRead(t *testing.T, f delegatedFixture, purpose string, expiry int64) lightDelegationReadRequest {
	t.Helper()
	r := lightDelegationReadRequest{VaultID: f.f.descriptor.VaultID, OperationID: f.p.Request.OperationID, ExpiresAt: expiry}
	r.OwnerSignature = delegationAPISign(t, f, purpose, struct {
		VaultID     string `json:"vaultId"`
		OperationID string `json:"operationId"`
		ExpiresAt   int64  `json:"expiresAt"`
	}{r.VaultID, r.OperationID, r.ExpiresAt})
	return r
}
func delegationAPIList(t *testing.T, f delegatedFixture, cursor string, expiry int64) lightDelegationListRequest {
	t.Helper()
	r := lightDelegationListRequest{VaultID: f.f.descriptor.VaultID, AfterOperationID: cursor, ExpiresAt: expiry}
	r.OwnerSignature = delegationAPISign(t, f, "list", struct {
		VaultID          string `json:"vaultId"`
		AfterOperationID string `json:"afterOperationId"`
		ExpiresAt        int64  `json:"expiresAt"`
	}{r.VaultID, r.AfterOperationID, r.ExpiresAt})
	return r
}
func TestLightDelegationAPIAuthenticationAndExactRetry(t *testing.T) {
	f, h, now := delegationAPI(t)
	var info struct {
		Enabled bool   `json:"enabled"`
		Pubkey  string `json:"pubkey"`
		Address string `json:"delegateAddress"`
	}
	raw := delegationAPIPost(t, h, "info", map[string]string{"vaultId": f.f.descriptor.VaultID}, 200)
	if err := json.Unmarshal(raw, &info); err != nil || !info.Enabled || info.Pubkey != "02"+f.f.descriptor.CosignerPub || info.Address != f.f.tree.ArkAddress {
		t.Fatalf("native identity: %s", raw)
	}
	var state lightDelegationResponse
	decode := func(raw []byte) {
		t.Helper()
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
	}
	decode(delegationAPIPost(t, h, "schedule", f.p.Request, 200))
	if state.State != "armed" || state.ReceiverSats != f.p.Renewal.ReceiverSats {
		t.Fatalf("schedule: %+v", state)
	}
	// An accepted request remains recoverable by exact retry without live indexer
	// access, even when the original owner authorization has since elapsed.
	*now = time.Unix(f.p.Request.ExpiresAt+60, 0)
	f.f.env.svc.ArkResolver = stubArkResolver{signer: f.f.tree.ArkdPub.SerializeCompressed(), network: f.f.descriptor.Network}
	decode(delegationAPIPost(t, h, "schedule", f.p.Request, 200))
	if state.State != "armed" {
		t.Fatalf("retry changed state: %+v", state)
	}
	changed := f.p.Request
	changed.OperationID = fmt.Sprintf("%032x", 999)
	delegationAPIPost(t, h, "schedule", changed, 400)
	auth := delegationAPIRead(t, f, "status", now.Unix()+120)
	decode(delegationAPIPost(t, h, "status", auth, 200))
	if state.OperationID != f.p.Request.OperationID {
		t.Fatal("status scope changed")
	}
	delegationAPIPost(t, h, "cancel", auth, 400)
	missing := auth
	missing.OwnerSignature = ""
	delegationAPIPost(t, h, "status", missing, 400)
	expired := delegationAPIRead(t, f, "status", now.Unix())
	delegationAPIPost(t, h, "status", expired, 400)
	long := delegationAPIRead(t, f, "status", now.Unix()+301)
	delegationAPIPost(t, h, "status", long, 400)
	cancel := delegationAPIRead(t, f, "cancel", now.Unix()+120)
	decode(delegationAPIPost(t, h, "cancel", cancel, 200))
	if state.State != "cancelled" {
		t.Fatalf("cancel: %+v", state)
	}
	decode(delegationAPIPost(t, h, "schedule", f.p.Request, 200))
	if state.State != "cancelled" {
		t.Fatal("retry resurrected cancellation")
	}
	f.f.env.svc.LightDelegationEnabled = false
	delegationAPIPost(t, h, "schedule", f.p.Request, 404)
}

func TestLightDelegationAPIListAuthenticatesCursorAndPaginatesHistory(t *testing.T) {
	f, h, now := delegationAPI(t)
	// Seed valid terminal history through the authoritative ledger. Repeated
	// cancelled authorizations for one unchanged input are legal and inexpensive.
	for i := 1; i <= 101; i++ {
		p := f.p
		p.Request.OperationID = fmt.Sprintf("%032x", i)
		p.Renewal.OperationID = p.Request.OperationID
		digest, err := lightDelegationRequestDigest(p.Request)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := schnorr.Sign(f.f.owner, digest)
		if err != nil {
			t.Fatal(err)
		}
		p.Request.OwnerSignature = hex.EncodeToString(sig.Serialize())
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.f.env.ledger.ScheduleLightDelegation(t.Context(), policy.LightDelegation{OperationID: p.Request.OperationID, VaultID: p.Request.VaultID, InputTxid: p.Renewal.Txid, InputVout: p.Renewal.Vout, ValidAt: p.ValidAt, ExpiresAt: p.Request.ExpiresAt, FeeSats: p.Renewal.FeeSats, PlanDigest: hex.EncodeToString(digest), Plan: string(raw)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.f.env.ledger.AdvanceLightDelegation(t.Context(), policy.LightDelegationEvent{OperationID: p.Request.OperationID, Phase: "cancelled", Evidence: `{}`}, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	read := delegationAPIList(t, f, "", now.Unix()+120)
	var page lightDelegationListResponse
	raw := delegationAPIPost(t, h, "list", read, 200)
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Operations) != 100 || page.NextCursor != fmt.Sprintf("%032x", 100) {
		t.Fatalf("first page: count=%d cursor=%s", len(page.Operations), page.NextCursor)
	}
	for i, o := range page.Operations {
		if o.OperationID != fmt.Sprintf("%032x", i+1) || o.Recovery != nil {
			t.Fatal("unordered or oversized list response")
		}
	}
	tampered := read
	tampered.AfterOperationID = page.NextCursor
	delegationAPIPost(t, h, "list", tampered, 400)
	raw = delegationAPIPost(t, h, "list", delegationAPIList(t, f, page.NextCursor, now.Unix()+120), 200)
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Operations) != 1 || page.Operations[0].OperationID != fmt.Sprintf("%032x", 101) || page.NextCursor != "" {
		t.Fatalf("last page: %+v", page)
	}
}
