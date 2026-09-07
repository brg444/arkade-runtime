package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// These shared expected hashes were generated independently with encoding/json
// and SHA256, then checked by the wallet's canonical encoder. This test invokes
// the actual typed server digest and read-verification paths. Existing plan
// signatures are retained only as serialization data, not new authorization.
func TestSpendingRenewalOpaqueWalletDigests(t *testing.T) {
	read := func(name string, dst any) {
		t.Helper()
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}
	var expected map[string]string
	read("renewal-opaque-go-digests.json", &expected)
	var contexts []struct {
		Context spendingRenewalBinding `json:"context"`
	}
	read("renewal-context-v1.json", &contexts)
	b := contexts[1].Context
	b.VaultID = "vault<>&\u2028\u2029é"
	hash, err := b.digest()
	if err != nil || hash != expected["vaulted-vtxo/renewal-context/v1"] {
		t.Fatalf("opaque context digest: %s %v", hash, err)
	}
	var vector struct {
		Set spendingDelegationSetRequest `json:"set"`
	}
	read("renewal-set-v1.json", &vector)
	set := vector.Set
	set.VaultID, set.DescriptorHash = b.VaultID, hash
	check := func(domain string, digest []byte, err error) {
		t.Helper()
		if err != nil || hex.EncodeToString(digest) != expected[domain] {
			t.Fatalf("%s digest: %x %v", domain, digest, err)
		}
	}
	digest, err := set.planDigest(set.Plans[0])
	check("vaulted-vtxo/delegate-schedule/v1", digest, err)
	digest, err = set.digest()
	check("vaulted-vtxo/delegate-schedule-set/v1", digest, err)
	owner, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	defer owner.Key.Zero()
	for _, purpose := range []string{"status", "cancel", "list"} {
		r := spendingDelegationReadRequest{Program: b.Program, DescriptorHash: hash, VaultID: b.VaultID, ExpiresAt: 1788739200}
		if purpose != "list" {
			r.OperationID = strings.Repeat("12", 16)
		}
		want, err := hex.DecodeString(expected["vaulted-vtxo/delegate-"+purpose+"/v1"])
		if err != nil {
			t.Fatal(err)
		}
		signature, err := schnorr.Sign(owner, want)
		if err != nil {
			t.Fatal(err)
		}
		r.OwnerSignature = hex.EncodeToString(signature.Serialize())
		svc := &Service{SessionNow: func() time.Time { return time.Unix(r.ExpiresAt-120, 0) }}
		c := renewalContract{spendingRenewalContext: spendingRenewalContext{Binding: b, DescriptorHash: hash}}
		if err := svc.verifySpendingDelegationRead(t.Context(), c, r, purpose); err != nil {
			t.Fatalf("opaque %s typed digest: %v", purpose, err)
		}
	}
}
