package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

func (r *rollingResolverFixture) verifyRollingRenewalInputs(context.Context, *rolling.Contract, rolling.Proposal, int64) error {
	r.verified++
	return r.err
}

func TestRollingAutomaticRenewalRequiresImmutableGrant(t *testing.T) {
	for _, granted := range []bool{false, true} {
		e, manager, keys, resolver, id := rollingRenewalApplicationFixtureWithGrant(t, granted)
		resolver.err = errors.New("source expiry unavailable")
		if _, err := e.svc.authorizeAutomaticRollingRenewal(t.Context(), manager, id); err == nil {
			t.Fatal("unresolved expiry authorized renewal")
		}
		resolver.err = nil
		first, err := e.svc.authorizeAutomaticRollingRenewal(t.Context(), manager, id)
		if !granted {
			if err == nil {
				t.Fatal("missing grant authorized renewal")
			}
			if _, err = e.ledger.CommitRollingRenewalAuthorization(t.Context(), policy.RollingEvent{OperationID: id, Phase: "authorized", Evidence: `{}`}); err == nil {
				t.Fatal("journal bypassed missing grant")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		before := resolver.verified
		resolver.err = errors.New("sources now spent")
		keys.wipe()
		retry, err := e.svc.authorizeAutomaticRollingRenewal(t.Context(), manager, id)
		if err != nil || !reflect.DeepEqual(first, retry) || resolver.verified != before {
			t.Fatal("lost response retry used new authority", err)
		}
		record, err := manager.operation(t.Context(), id)
		if err != nil || len(record.Events) != 1 || record.Events["authorized"].Evidence == "" {
			t.Fatal("unattended signature not retained", err)
		}
		changed := record.Enrollment
		changed.AutomaticRenewal = false
		if _, err = e.ledger.EnrollRolling(t.Context(), changed); err == nil {
			t.Fatal("enrollment grant mutated in place")
		}
	}
}

func TestRollingAutomaticGrantCannotAuthorizePayment(t *testing.T) {
	e, manager, keys, _, payment := rollingApplicationFixtureWithGrant(t, true)
	record, err := manager.Reserve(t.Context(), payment)
	if err != nil {
		t.Fatal(err)
	}
	id := record.Operation.OperationID
	if _, err = e.svc.authorizeAutomaticRollingRenewal(t.Context(), manager, id); err == nil {
		t.Fatal("unattended payment authorized")
	}
	if _, err = keys.authorizeRollingRenewal(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("renewal key capability signed payment")
	}
	if _, err = e.ledger.CommitRollingRenewalAuthorization(t.Context(), policy.RollingEvent{OperationID: id, Phase: "authorized", Evidence: `{}`}); err == nil {
		t.Fatal("journal accepted unattended payment")
	}
}

func TestRollingAutomaticRenewalResolvesEverySourceWindow(t *testing.T) {
	_, manager, _, _, id := rollingRenewalApplicationFixtureWithGrant(t, true)
	record, err := manager.operation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	now := manager.store.NowUTC().Unix()
	for _, tc := range []struct {
		name   string
		expiry any
		want   bool
	}{
		{"open", strconv.FormatInt(now+1200, 10), true},
		{"missing", nil, false},
		{"expired", strconv.FormatInt(now, 10), false},
		{"too early", strconv.FormatInt(now+manager.contract.Parameters.RenewalWindow, 10), false},
		{"registration outlives source", strconv.FormatInt(now+30, 10), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views := []map[string]any{}
			for i, source := range record.Operation.Proposal.Sources {
				expiry := any(strconv.FormatInt(now+1200, 10))
				if i == len(record.Operation.Proposal.Sources)-1 {
					expiry = tc.expiry
				}
				views = append(views, map[string]any{"outpoint": map[string]any{"txid": source.Previous.TxHash().String(), "vout": source.Index}, "amount": strconv.FormatInt(source.Previous.TxOut[source.Index].Value, 10), "script": hex.EncodeToString(manager.contract.PkScript), "createdAt": "100", "expiresAt": expiry, "isSpent": false, "isSwept": false, "commitmentTxids": []string{strings.Repeat("cd", 32)}})
			}
			payload, err := json.Marshal(map[string]any{"vtxos": views, "page": map[string]int{"current": 1, "next": 1, "total": 1}})
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			resolver := &arkResolver{origin: "https://operator.example", hc: rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Path != "/v1/indexer/vtxos" || len(req.URL.Query()["outpoints"]) != len(views) {
					t.Fatalf("unbounded renewal lookup: %s", req.URL)
				}
				return jsonResponse(http.StatusOK, string(payload)), nil
			})}
			err = resolver.verifyRollingRenewalInputs(t.Context(), manager.contract, record.Operation.Proposal, now)
			if (err == nil) != tc.want || requests != 1 {
				t.Fatalf("renewal expiry validation: %v; snapshots %d", err, requests)
			}
		})
	}
}
