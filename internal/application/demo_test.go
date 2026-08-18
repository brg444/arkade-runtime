package application

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
)

type fakeChain struct {
	fail bool
}

type demoTransport struct{}

func (*demoTransport) SubmitOnchainTx(context.Context, string) (string, error) {
	return "", context.Canceled
}

func demoRemoteSigner() *RemoteSigner {
	return &RemoteSigner{Client: &demoTransport{}}
}

func (f *fakeChain) GetNewAddress(context.Context) (string, error) {
	if f.fail {
		return "", context.Canceled
	}
	return "bcrt1qtest", nil
}
func (f *fakeChain) SendToAddress(context.Context, string, int64) (string, error) {
	return "", context.Canceled
}
func (f *fakeChain) GenerateToAddress(context.Context, int, string) error {
	return context.Canceled
}
func (f *fakeChain) GetRawTransaction(context.Context, string) ([]byte, error) {
	return nil, context.Canceled
}
func (f *fakeChain) TestMempoolAccept(context.Context, []byte) (bool, string, error) {
	return false, "disabled", nil
}
func (f *fakeChain) SendRawTransaction(context.Context, []byte) (string, error) {
	return "", context.Canceled
}
func (f *fakeChain) LookupTx(context.Context, string) (int64, bool, error) {
	return 0, false, context.Canceled
}

func TestDemoRoutesAbsentWhenDisabled(t *testing.T) {
	handler := Handler(nil, "")
	for _, path := range []string{
		"/v1/demo/info",
		"/v1/demo/fund",
		"/v1/demo/mine",
		"/v1/demo/submit",
		"/v1/demo/owner-draft",
		"/v1/demo/owner-complete",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", fixture.Origin)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404", path, rec.Code)
		}
	}
}

func TestDemoOwnerRoutesAbsentWhenEnabled(t *testing.T) {
	svc := &Service{VaultSigner: demoRemoteSigner()}
	d, err := NewDemo(svc, &fakeChain{})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(svc, "", d)
	for _, path := range []string{
		"/v1/demo/owner-draft",
		"/v1/demo/owner-complete",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", fixture.Origin)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404", path, rec.Code)
		}
	}
}

func TestNewDemoRejectsLocalSignerOrNil(t *testing.T) {
	chain := &fakeChain{}
	if _, err := NewDemo(nil, chain); err == nil {
		t.Fatal("nil service accepted")
	}
	if _, err := NewDemo(&Service{VaultSigner: demoRemoteSigner()}, nil); err == nil {
		t.Fatal("nil chain accepted")
	}
	if _, err := NewDemo(&Service{}, chain); err == nil {
		t.Fatal("nil signer accepted")
	}
	if _, err := NewDemo(&Service{VaultSigner: LocalSigner{}}, chain); err == nil {
		t.Fatal("LocalSigner accepted")
	}
	var typedNil *RemoteSigner
	if _, err := NewDemo(&Service{VaultSigner: typedNil}, chain); err == nil {
		t.Fatal("typed-nil RemoteSigner accepted")
	}
	if _, err := NewDemo(&Service{VaultSigner: &RemoteSigner{}}, chain); err == nil {
		t.Fatal("RemoteSigner without a transport client accepted")
	}
	var typedNilClient *demoTransport
	if _, err := NewDemo(&Service{VaultSigner: &RemoteSigner{Client: typedNilClient}}, chain); err == nil {
		t.Fatal("RemoteSigner with a typed-nil transport client accepted")
	}
	if _, err := NewDemo(&Service{VaultSigner: demoRemoteSigner()}, chain); err != nil {
		t.Fatalf("non-nil RemoteSigner rejected: %v", err)
	}
}

func TestDemoFundFailsClosedWithoutEnrollment(t *testing.T) {
	svc := &Service{VaultSigner: demoRemoteSigner()}
	d, err := NewDemo(svc, &fakeChain{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.fund(context.Background(), 0); err == nil {
		t.Fatal("fund without enrollment accepted")
	}
	handler := NewHandler(svc, "", d)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/demo/info", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("demo info: %d", rec.Code)
	}
	var info demoInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil || !info.Demo || info.SignerMode != "remote" || info.RemoteSignerSuccesses != 0 {
		t.Fatalf("demo info body: %+v %v", info, err)
	}
	fundRec := httptest.NewRecorder()
	fundReq := httptest.NewRequest(http.MethodPost, "/v1/demo/fund", strings.NewReader(`{"amount":0}`))
	fundReq.Header.Set("Content-Type", "application/json")
	fundReq.Header.Set("Origin", fixture.Origin)
	handler.ServeHTTP(fundRec, fundReq)
	if fundRec.Code != http.StatusBadRequest {
		t.Fatalf("fund without enrollment: got %d, want 400", fundRec.Code)
	}
	if !strings.Contains(fundRec.Body.String(), "not enrolled") {
		t.Fatalf("fund without enrollment body: %s", fundRec.Body.String())
	}
}
