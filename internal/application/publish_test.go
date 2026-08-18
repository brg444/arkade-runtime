package application

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	_ "modernc.org/sqlite"
)

type recordingBroadcast struct {
	mu        sync.Mutex
	calls     int
	looked    []string
	lookup    map[string]int64
	lookupFn  func(txid string) (int64, bool, error)
	broadcast func([]byte) (string, error)
}

func (r *recordingBroadcast) Broadcast(_ context.Context, raw []byte) (string, error) {
	r.mu.Lock()
	r.calls++
	fn := r.broadcast
	r.mu.Unlock()
	if fn != nil {
		return fn(raw)
	}
	txid, err := rawTxid(raw)
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	if r.lookup == nil {
		r.lookup = map[string]int64{}
	}
	r.lookup[txid] = 0
	r.mu.Unlock()
	return txid, nil
}

func (r *recordingBroadcast) Lookup(_ context.Context, txid string) (int64, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.looked = append(r.looked, txid)
	if r.lookupFn != nil {
		return r.lookupFn(txid)
	}
	if r.lookup == nil {
		return 0, false, nil
	}
	conf, ok := r.lookup[txid]
	return conf, ok, nil
}

func (r *recordingBroadcast) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *recordingBroadcast) lookedIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.looked))
	copy(out, r.looked)
	return out
}

func TestPublishUnknownAndIncompleteChallengeNeverCallsChain(t *testing.T) {
	e := newBoundaryEnv(t)
	rec := &recordingBroadcast{}
	e.service.Broadcaster = rec

	if _, err := e.service.Publish(context.Background(), hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))); err == nil || !strings.Contains(err.Error(), "unknown or incomplete") {
		t.Fatalf("unknown challenge: %v", err)
	}
	if rec.callCount() != 0 {
		t.Fatal("unknown challenge called chain")
	}

	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	req, _ := e.requestFor(t, draft, e.passkeyPriv)
	e.countingSigner.mu.Lock()
	e.countingSigner.err = errors.New("injected")
	e.countingSigner.mu.Unlock()
	if _, _, err := e.service.Authorize(context.Background(), req); err == nil {
		t.Fatal("injected signer failure accepted")
	}
	ch, err := vault.Challenge(mustParsePSBT(t, req.PSBT), e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.service.Publish(context.Background(), hex.EncodeToString(ch)); err == nil || !strings.Contains(err.Error(), "unknown or incomplete") {
		t.Fatalf("reserved challenge: %v", err)
	}
	if rec.callCount() != 0 {
		t.Fatal("incomplete challenge called chain")
	}
}

func TestPublishRejectsCorruptedAndInvalidStoredPSBT(t *testing.T) {
	e := newBoundaryEnv(t)
	rec := &recordingBroadcast{}
	e.service.Broadcaster = rec
	ch := completeCanonical(t, e)

	overwriteSignedPSBT(t, e.dbPath, ch, "not-a-psbt")
	if _, err := e.service.Publish(context.Background(), hex.EncodeToString(ch)); err == nil {
		t.Fatal("corrupted stored PSBT accepted")
	}
	if rec.callCount() != 0 {
		t.Fatal("corrupted PSBT called chain")
	}

	e2 := newBoundaryEnv(t)
	rec2 := &recordingBroadcast{}
	e2.service.Broadcaster = rec2
	ch2 := completeCanonical(t, e2)
	stored, ok, err := e2.ledger.Completed(context.Background(), fixture.VaultID, ch2)
	if err != nil || !ok {
		t.Fatalf("completed: %v ok=%v", err, ok)
	}
	ptx := mustParsePSBT(t, stored)
	ptx.Inputs[0].TaprootScriptSpendSig = append(ptx.Inputs[0].TaprootScriptSpendSig, ptx.Inputs[0].TaprootScriptSpendSig[0])
	raw, err := ptx.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	overwriteSignedPSBT(t, e2.dbPath, ch2, raw)
	if _, err := e2.service.Publish(context.Background(), hex.EncodeToString(ch2)); err == nil {
		t.Fatal("duplicate stored signature accepted")
	}
	if rec2.callCount() != 0 {
		t.Fatal("duplicate sig called chain")
	}

	e3 := newBoundaryEnv(t)
	rec3 := &recordingBroadcast{}
	e3.service.Broadcaster = rec3
	ch3 := completeCanonical(t, e3)
	stored, ok, err = e3.ledger.Completed(context.Background(), fixture.VaultID, ch3)
	if err != nil || !ok {
		t.Fatal(err)
	}
	ptx = mustParsePSBT(t, stored)
	ptx.Inputs[0].TaprootScriptSpendSig[0].Signature = bytes.Repeat([]byte{0xff}, 64)
	raw, err = ptx.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	overwriteSignedPSBT(t, e3.dbPath, ch3, raw)
	if _, err := e3.service.Publish(context.Background(), hex.EncodeToString(ch3)); err == nil {
		t.Fatal("invalid stored signature accepted")
	}
	if rec3.callCount() != 0 {
		t.Fatal("invalid sig called chain")
	}

	for _, role := range []string{"hot", "private provider", "public arkade"} {
		t.Run("missing "+role, func(t *testing.T) {
			env := newBoundaryEnv(t)
			chain := &recordingBroadcast{}
			env.service.Broadcaster = chain
			challenge := completeCanonical(t, env)
			stored, ok, err := env.ledger.Completed(context.Background(), fixture.VaultID, challenge)
			if err != nil || !ok {
				t.Fatalf("completed: ok=%v err=%v", ok, err)
			}
			packet := mustParsePSBT(t, stored)
			var missing []byte
			switch role {
			case "hot":
				missing = schnorr.SerializePubKey(env.hotPriv.PubKey())
			case "private provider":
				missing = schnorr.SerializePubKey(env.service.Operational.TweakedVaultCosigner)
			case "public arkade":
				missing = schnorr.SerializePubKey(env.service.Operational.TweakedArkadeCosigner)
			}
			kept := packet.Inputs[0].TaprootScriptSpendSig[:0]
			for _, sig := range packet.Inputs[0].TaprootScriptSpendSig {
				if !bytes.Equal(sig.XOnlyPubKey, missing) {
					kept = append(kept, sig)
				}
			}
			packet.Inputs[0].TaprootScriptSpendSig = kept
			encoded, err := packet.B64Encode()
			if err != nil {
				t.Fatal(err)
			}
			overwriteSignedPSBT(t, env.dbPath, challenge, encoded)
			if _, err := env.service.Publish(context.Background(), hex.EncodeToString(challenge)); err == nil {
				t.Fatalf("stored completion without %s signature was published", role)
			}
			if chain.callCount() != 0 {
				t.Fatalf("missing %s signature reached the chain", role)
			}
		})
	}
}

func TestPublishExactCompletionIsIdempotentAndResolvesTimeoutByTxid(t *testing.T) {
	e := newBoundaryEnv(t)
	rec := &recordingBroadcast{lookup: map[string]int64{}}
	e.service.Broadcaster = rec
	ch := completeCanonical(t, e)

	first, err := e.service.Publish(context.Background(), hex.EncodeToString(ch))
	if err != nil || first.Txid == "" || first.Confirmations != 0 {
		t.Fatalf("first publish: %+v %v", first, err)
	}
	if rec.callCount() != 1 {
		t.Fatalf("broadcasts after first publish: %d", rec.callCount())
	}
	second, err := e.service.Publish(context.Background(), hex.EncodeToString(ch))
	if err != nil || second.Txid != first.Txid {
		t.Fatalf("idempotent publish: %+v %v", second, err)
	}
	if rec.callCount() != 1 {
		t.Fatalf("idempotent publish rebroadcast: %d", rec.callCount())
	}

	e2 := newBoundaryEnv(t)
	var sent []byte
	rec2 := &recordingBroadcast{
		broadcast: func(raw []byte) (string, error) {
			sent = append([]byte(nil), raw...)
			return "", context.DeadlineExceeded
		},
	}
	e2.service.Broadcaster = rec2
	ch2 := completeCanonical(t, e2)
	// First attempt: broadcast times out; nothing in lookup yet.
	if _, err := e2.service.Publish(context.Background(), hex.EncodeToString(ch2)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout without node accept: %v", err)
	}
	txid, err := rawTxid(sent)
	if err != nil {
		t.Fatal(err)
	}
	rec2.mu.Lock()
	rec2.lookup = map[string]int64{txid: 0}
	rec2.broadcast = func([]byte) (string, error) { return "", context.DeadlineExceeded }
	rec2.mu.Unlock()
	got, err := e2.service.Publish(context.Background(), hex.EncodeToString(ch2))
	if err != nil || got.Txid != txid {
		t.Fatalf("timeout after node accept: %+v %v", got, err)
	}

	rec2.mu.Lock()
	rec2.lookup[txid] = 1
	rec2.mu.Unlock()
	st, err := e2.service.PublicationStatus(context.Background(), hex.EncodeToString(ch2))
	if err != nil || st.Confirmations != 1 || st.Txid != txid {
		t.Fatalf("mempool to confirmed: %+v %v", st, err)
	}
}

func completeCanonical(t *testing.T, e *boundaryEnv) []byte {
	t.Helper()
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	req, _ := e.requestFor(t, draft, e.passkeyPriv)
	if _, _, err := e.service.Authorize(context.Background(), req); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	ch, err := vault.Challenge(mustParsePSBT(t, req.PSBT), e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func mustParsePSBT(t *testing.T, raw string) *psbt.Packet {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		t.Fatal(err)
	}
	return ptx
}

func overwriteSignedPSBT(t *testing.T, dbPath string, digest []byte, signed string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE issuance SET signed_psbt = ? WHERE vault_id = ? AND arkade_sighash = ?`,
		signed, fixture.VaultID, digest)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		t.Fatalf("overwrite rows = %d", n)
	}
}

func TestHTTPPublishIsChallengeOnly(t *testing.T) {
	e := newBoundaryEnv(t)
	e.service.Broadcaster = &recordingBroadcast{}
	handler := NewHandler(e.service, "", nil)
	rec := postJSON(t, handler, "/v1/publish", `{"psbt":"cHNidP8BAH0="}`)
	if rec.Code == 200 {
		t.Fatal("publish accepted a PSBT body")
	}
	ch := completeCanonical(t, e)
	rec = postJSON(t, handler, "/v1/publish", `{"challenge":"`+hex.EncodeToString(ch)+`"}`)
	if rec.Code != 200 {
		t.Fatalf("challenge publish: %d %s", rec.Code, rec.Body.String())
	}
}

func TestDispatchPublicationMismatchedReturnedTxid(t *testing.T) {
	e := newBoundaryEnv(t)
	foreign := strings.Repeat("cd", 32)
	rec := &recordingBroadcast{
		broadcast: func([]byte) (string, error) {
			return foreign, nil
		},
	}
	e.service.Broadcaster = rec
	ch := completeCanonical(t, e)
	if _, err := e.service.Publish(context.Background(), hex.EncodeToString(ch)); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("mismatch: %v", err)
	}
	for _, id := range rec.lookedIDs() {
		if id == foreign {
			t.Fatal("looked up RPC-returned foreign txid")
		}
	}
}

func TestDispatchPublicationLookupOutage(t *testing.T) {
	e := newBoundaryEnv(t)
	outage := errors.New("lookup outage")
	rec := &recordingBroadcast{
		lookupFn: func(string) (int64, bool, error) {
			return 0, false, outage
		},
		broadcast: func([]byte) (string, error) {
			t.Fatal("lookup outage broadcast")
			return "", nil
		},
	}
	e.service.Broadcaster = rec
	ch := completeCanonical(t, e)
	if _, err := e.service.Publish(context.Background(), hex.EncodeToString(ch)); !errors.Is(err, outage) {
		t.Fatalf("pre-send outage: %v", err)
	}
	if rec.callCount() != 0 {
		t.Fatal("broadcast after lookup outage")
	}

	e2 := newBoundaryEnv(t)
	looks := 0
	rec2 := &recordingBroadcast{
		lookupFn: func(string) (int64, bool, error) {
			looks++
			if looks == 1 {
				return 0, false, nil
			}
			return 0, false, outage
		},
		broadcast: func(raw []byte) (string, error) {
			return rawTxid(raw)
		},
	}
	e2.service.Broadcaster = rec2
	ch2 := completeCanonical(t, e2)
	if _, err := e2.service.Publish(context.Background(), hex.EncodeToString(ch2)); !errors.Is(err, outage) {
		t.Fatalf("post-send outage: %v", err)
	}
}

func TestDispatchPublicationAmbiguousAcceptedSend(t *testing.T) {
	e := newBoundaryEnv(t)
	rec := &recordingBroadcast{lookup: map[string]int64{}}
	rec.broadcast = func(raw []byte) (string, error) {
		txid, err := rawTxid(raw)
		if err != nil {
			return "", err
		}
		rec.mu.Lock()
		rec.lookup[txid] = 0
		rec.mu.Unlock()
		return "", context.DeadlineExceeded
	}
	e.service.Broadcaster = rec
	ch := completeCanonical(t, e)
	got, err := e.service.Publish(context.Background(), hex.EncodeToString(ch))
	if err != nil || got.Txid == "" || got.Confirmations != 0 {
		t.Fatalf("ambiguous accepted send: %+v %v", got, err)
	}

	e2 := newBoundaryEnv(t)
	outage := errors.New("lookup outage")
	looks := 0
	rec2 := &recordingBroadcast{
		lookupFn: func(string) (int64, bool, error) {
			looks++
			if looks == 1 {
				return 0, false, nil
			}
			return 0, false, outage
		},
		broadcast: func([]byte) (string, error) {
			return "", context.DeadlineExceeded
		},
	}
	e2.service.Broadcaster = rec2
	ch2 := completeCanonical(t, e2)
	if _, err := e2.service.Publish(context.Background(), hex.EncodeToString(ch2)); !errors.Is(err, outage) {
		t.Fatalf("ambiguous send lookup outage: %v", err)
	}
}

func TestPublicationStatusRejectsUnrelatedTxid(t *testing.T) {
	e := newBoundaryEnv(t)
	rec := &recordingBroadcast{}
	e.service.Broadcaster = rec
	ch := completeCanonical(t, e)
	pub, err := e.service.Publish(context.Background(), hex.EncodeToString(ch))
	if err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	before := len(rec.looked)
	rec.lookupFn = func(txid string) (int64, bool, error) {
		t.Fatalf("unrelated txid reached chain: %s", txid)
		return 0, false, nil
	}
	rec.mu.Unlock()
	if _, err := e.service.PublicationStatus(context.Background(), pub.Txid); err == nil || !strings.Contains(err.Error(), "unknown or incomplete") {
		t.Fatalf("txid as challenge: %v", err)
	}
	if _, err := e.service.PublicationStatus(context.Background(), hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))); err == nil || !strings.Contains(err.Error(), "unknown or incomplete") {
		t.Fatalf("unrelated digest: %v", err)
	}
	if got := rec.lookedIDs(); len(got) != before {
		t.Fatalf("unrelated status queried chain: %v", got)
	}
}

func TestPublicationStatusIsChallengeBased(t *testing.T) {
	e := newBoundaryEnv(t)
	rec := &recordingBroadcast{}
	e.service.Broadcaster = rec
	ch := completeCanonical(t, e)
	pub, err := e.service.Publish(context.Background(), hex.EncodeToString(ch))
	if err != nil {
		t.Fatal(err)
	}
	st, err := e.service.PublicationStatus(context.Background(), hex.EncodeToString(ch))
	if err != nil || st.Txid != pub.Txid || st.Confirmations != 0 {
		t.Fatalf("challenge status: %+v %v", st, err)
	}
}

func TestHTTPPublicationStatusIsChallengeOnly(t *testing.T) {
	e := newBoundaryEnv(t)
	e.service.Broadcaster = &recordingBroadcast{}
	handler := NewHandler(e.service, "", nil)
	ch := completeCanonical(t, e)
	pubRec := postJSON(t, handler, "/v1/publish", `{"challenge":"`+hex.EncodeToString(ch)+`"}`)
	if pubRec.Code != 200 {
		t.Fatalf("publish: %d %s", pubRec.Code, pubRec.Body.String())
	}
	var pub PublishResult
	if err := json.NewDecoder(pubRec.Body).Decode(&pub); err != nil || pub.Txid == "" {
		t.Fatalf("publish body: %v", err)
	}

	txidRec := httptest.NewRecorder()
	handler.ServeHTTP(txidRec, httptest.NewRequest(http.MethodGet, "/v1/tx?txid="+pub.Txid, nil))
	if txidRec.Code == 200 {
		t.Fatal("status accepted a raw txid")
	}

	chRec := httptest.NewRecorder()
	handler.ServeHTTP(chRec, httptest.NewRequest(http.MethodGet, "/v1/tx?challenge="+hex.EncodeToString(ch), nil))
	if chRec.Code != 200 {
		t.Fatalf("challenge status: %d %s", chRec.Code, chRec.Body.String())
	}
	var st PublishResult
	if err := json.NewDecoder(chRec.Body).Decode(&st); err != nil || st.Txid != pub.Txid || st.Confirmations != 0 {
		t.Fatalf("challenge status body: %+v %v", st, err)
	}
}

func postJSON(t *testing.T, handler http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", fixture.Origin)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
