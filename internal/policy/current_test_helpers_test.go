package policy

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"
)

func testIntegrityKey() []byte {
	return bytes.Repeat([]byte{0x5a}, sha256.Size)
}

func openPolicyTestLedger(t testing.TB, clock Clock) *Ledger {
	t.Helper()
	led, err := OpenLedger(filepath.Join(t.TempDir(), "policy.sqlite"), clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		led.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	return led
}

func createPolicyTestVault(t testing.TB, led *Ledger, vaultID string, tag byte) {
	t.Helper()
	now := led.NowUTC()
	tokenHash := bytes.Repeat([]byte{tag}, sha256.Size)
	if err := led.PutInvite(tokenHash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	in := policyTestVaultInput(t, vaultID, tag, tokenHash)
	if err := led.CreateVault(in); err != nil {
		t.Fatal(err)
	}
}

func policyTestVaultInput(t testing.TB, vaultID string, tag byte, tokenHash []byte) CreateVaultInput {
	t.Helper()
	key := testIntegrityKey()
	keyBytes := bytes.Repeat([]byte{tag}, 33)
	keyBytes[0] = 0x02
	record := VaultRecord{
		VaultID: vaultID, TemplateVersion: "vault-v2-test", PolicyVersion: "vault-policy-v1",
		ProtectionTier: "advanced",
		Network:        "mainnet", RPID: "vault.example", Origin: "https://vault.example",
		PhoneBIP340: keyBytes, PhoneDirectP256: keyBytes, ExternalOwnerWallet: keyBytes,
		RecoveryKey: keyBytes, VaultCosignerBase: keyBytes,
		ArkadeCosignerBase:   keyBytes,
		ArkadeCosignerOrigin: "https://operator.example", ArkadeCosignerVersion: "test",
		CosignerMode:   CosignerModeHKDFSHA256V1,
		SavingsAddress: "savings", SavingsScript: []byte{0x52},
		RecipientDustSats: 330, TxRecipientCapSats: 50_000, PeriodAllowanceSats: 100_000,
		AbsoluteFeeCapSats: 10_000, FeerateCapSatPerV: 100,
	}
	credential := VaultCredential{
		CredentialID: []byte{tag, tag + 1}, VaultID: vaultID,
		WebAuthnP256: keyBytes, UserHandle: []byte(vaultID), Resident: true,
	}
	if err := SealVaultRecord(&record, key); err != nil {
		t.Fatal(err)
	}
	if err := SealVaultCredential(&credential, key); err != nil {
		t.Fatal(err)
	}
	return CreateVaultInput{
		Record: record, Credential: credential, TokenHash: tokenHash,
	}
}
