package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

type rollingReceiptStoreFixture struct {
	records []policy.RollingSnapshot
	err     error
}

func (s *rollingReceiptStoreFixture) RollingOperations(context.Context, string) ([]policy.RollingSnapshot, error) {
	return s.records, s.err
}

type rollingResolverFixture struct {
	ports.ArkResolver
	c        *rolling.Contract
	err      error
	verified int
}

func (r *rollingResolverFixture) Network() string             { return "mainnet" }
func (r *rollingResolverFixture) CheckpointTapscript() []byte { return r.c.Parameters.CheckpointExit }
func (r *rollingResolverFixture) OperatorSignerPub() []byte {
	return r.c.Keys.Operator.SerializeCompressed()
}
func (r *rollingResolverFixture) verifyRollingOutcome(context.Context, *rolling.Contract, policy.RollingSnapshot) error {
	r.verified++
	return r.err
}

func TestRollingReceiptSourceUsesOnlyPersistedFinalization(t *testing.T) {
	c, p, err := fixture.RollingPayment()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := rolling.EncodeDescriptor(c)
	if err != nil {
		t.Fatal(err)
	}
	vault := strings.Repeat("ab", 32)
	observed := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)
	record := policy.RollingSnapshot{Enrollment: policy.RollingEnrollment{VaultID: vault, Descriptor: string(descriptor)}, Operation: policy.RollingOperation{OperationID: p.Transaction.TxHash().String(), VaultID: vault, Proposal: p, CreatedAt: observed.Add(-time.Hour).Format(time.RFC3339)}, Events: map[string]policy.RollingEvent{}}
	store := &rollingReceiptStoreFixture{records: []policy.RollingSnapshot{record}}
	resolver := &rollingResolverFixture{c: c}
	source, err := NewRollingReceiptSource(store, vault, c, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.FinalizedOperation(t.Context(), c.Parameters.ControllerID, 0); err == nil {
		t.Fatal("pending operation yielded receipt")
	}
	store.records[0].Events["finalized"] = policy.RollingEvent{Phase: "finalized", OutcomeTxid: p.Transaction.TxHash().String(), CreatedAt: observed.Format(time.RFC3339)}
	finalized, err := source.FinalizedOperation(t.Context(), c.Parameters.ControllerID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if finalized.ObservedAt != observed || resolver.verified != 1 {
		t.Fatal("receipt observation or verification mismatch")
	}
	resolver.err = errors.New("independent projection is pending")
	if _, err = source.FinalizedOperation(t.Context(), c.Parameters.ControllerID, 0); err == nil {
		t.Fatal("journal assertion bypassed independent projection")
	}
	resolver.err = nil
	store.err = errors.New("MAC mismatch")
	if _, err = source.FinalizedOperation(t.Context(), c.Parameters.ControllerID, 0); err == nil {
		t.Fatal("corrupt journal yielded receipt")
	}
}

func TestRollingReceiptSourceRejectsAmbiguousSequenceAndEnrollment(t *testing.T) {
	c, p, err := fixture.RollingPayment()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _ := rolling.EncodeDescriptor(c)
	at := time.Now().UTC().Format(time.RFC3339)
	record := policy.RollingSnapshot{Enrollment: policy.RollingEnrollment{Descriptor: string(descriptor)}, Operation: policy.RollingOperation{Proposal: p, CreatedAt: at}, Events: map[string]policy.RollingEvent{"finalized": {OutcomeTxid: p.Transaction.TxHash().String(), CreatedAt: at}}}
	store := &rollingReceiptStoreFixture{records: []policy.RollingSnapshot{record, record}}
	source, err := NewRollingReceiptSource(store, "vault", c, &rollingResolverFixture{c: c})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.FinalizedOperation(t.Context(), c.Parameters.ControllerID, 0); err == nil {
		t.Fatal("duplicate sequence accepted")
	}
	store.records = store.records[:1]
	changed := *c
	changed.Parameters.Budget--
	changed.Parameters.RecipientCap = 1000
	raw, err := rolling.EncodeDescriptor(&changed)
	if err != nil {
		t.Fatal(err)
	}
	store.records[0].Enrollment.Descriptor = string(raw)
	if _, err = source.FinalizedOperation(t.Context(), c.Parameters.ControllerID, 0); err == nil {
		t.Fatal("other policy accepted")
	}
}

func TestRollingFinalizationRequiresExactOperatorProjection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]map[string]any) []map[string]any
		want   bool
	}{
		{"finalized", nil, true},
		{"historical controller", func(v []map[string]any) []map[string]any { v[2]["isSpent"] = true; return v }, true},
		{"accepted but not finalized", func(v []map[string]any) []map[string]any { return v[:2] }, false},
		{"unspent source", func(v []map[string]any) []map[string]any { v[0]["isSpent"] = false; return v }, false},
		{"conflicting payment", func(v []map[string]any) []map[string]any { v[0]["arkTxid"] = strings.Repeat("cc", 32); return v }, false},
		{"controller amount", func(v []map[string]any) []map[string]any { v[2]["amount"] = "331"; return v }, false},
		{"controller script", func(v []map[string]any) []map[string]any {
			v[2]["script"] = "5120" + strings.Repeat("11", 32)
			return v
		}, false},
		{"duplicate controller", func(v []map[string]any) []map[string]any { return append(v, v[2]) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, p, err := fixture.RollingPayment()
			if err != nil {
				t.Fatal(err)
			}
			id := p.Transaction.TxHash().String()
			at := time.Now().UTC().Format(time.RFC3339)
			record := policy.RollingSnapshot{Operation: policy.RollingOperation{OperationID: id, Proposal: p, CreatedAt: at}, Events: map[string]policy.RollingEvent{"finalized": {OutcomeTxid: id, CreatedAt: at}}}
			views := []map[string]any{}
			for _, source := range p.Sources {
				views = append(views, map[string]any{"outpoint": map[string]any{"txid": source.Previous.TxHash().String(), "vout": source.Index}, "isSpent": true, "arkTxid": id, "spentBy": strings.Repeat("ef", 32)})
			}
			views = append(views, map[string]any{"outpoint": map[string]any{"txid": id, "vout": 0}, "amount": "330", "script": hex.EncodeToString(c.PkScript), "createdAt": "100", "expiresAt": nil, "isSwept": false, "commitmentTxids": []string{strings.Repeat("cd", 32)}})
			if tc.mutate != nil {
				views = tc.mutate(views)
			}
			payload, err := json.Marshal(map[string]any{"vtxos": views, "page": map[string]int{"current": 1, "next": 1, "total": 1}})
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			resolver := &arkResolver{origin: "https://operator.example", hc: rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Path != "/v1/indexer/vtxos" || len(req.URL.Query()["outpoints"]) != 3 || req.URL.Query().Has("spendableOnly") {
					t.Fatalf("unbounded finalization lookup: %s", req.URL)
				}
				return jsonResponse(http.StatusOK, string(payload)), nil
			})}
			err = resolver.verifyRollingOutcome(t.Context(), c, record)
			if (err == nil) != tc.want {
				t.Fatalf("verified=%v want=%v: %v", err == nil, tc.want, err)
			}
			if requests != 1 {
				t.Fatalf("finalization used %d snapshots", requests)
			}
		})
	}
}
