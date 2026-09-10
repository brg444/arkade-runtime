package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Public deterministic keys only. This fixture is also consumed by the wallet
// to verify identical enrollment bytes, scripts and addresses across languages.
func TestSharedSpendingEnrollmentVector(t *testing.T) {
	ledger, err := policy.OpenLedger(filepath.Join(t.TempDir(), "vector.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	svc := enrollService(t, ledger)
	svc.LightEnabled = true
	master, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{11}, 32))
	owner, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	board, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{9}, 32))
	svc.VaultCosignerPub = master.PubKey()
	svc.keys = testKeys(t, master, LocalSigner{Priv: master})
	svc.ArkResolver = stubArkResolver{signer: mustDecode(t, "03301078808e4f7bc0dadfe29e34b1df8eaf0108ef06b1722274075ebc107a127a")}
	direct, err := hex.DecodeString("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, hash, err := svc.spendingEnrollmentDescriptor("abababababababababababababababab", parsedRegisterRequest{
		phone: owner.PubKey(), phoneDirectP256: direct, protectionTier: program.ProtectionTierLight,
		spendingPolicy: program.DefaultSpendingPolicy(), boardPub: board.PubKey(), boardingProgram: program.VaultBoardV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(struct {
		Descriptor spendingEnrollmentDescriptor `json:"descriptor"`
		Hash       string                       `json:"hash"`
	}{descriptor, hash}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "fixture", "shared-spending-enrollment.json")
	if os.Getenv("UPDATE_SHARED_SPENDING_VECTOR") == "1" {
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatal("shared Spending enrollment vector changed")
	}
}
