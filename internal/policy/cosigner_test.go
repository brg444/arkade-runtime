package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func testMaster(t *testing.T, tag byte) *btcec.PrivateKey {
	t.Helper()
	priv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{tag}, 32))
	if priv == nil {
		t.Fatal("test master scalar rejected")
	}
	return priv
}

func TestLegacyDirectV0IsExactMasterCopy(t *testing.T) {
	master := testMaster(t, 0x21)
	got, err := DeriveVaultCosignerScalar(master, LegacyFirstVaultID, CosignerModeLegacyDirectV0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Serialize(), master.Serialize()) {
		t.Fatal("legacy-direct-v0 changed the master scalar")
	}
	if !bytes.Equal(got.PubKey().SerializeCompressed(), master.PubKey().SerializeCompressed()) {
		t.Fatal("legacy-direct-v0 changed the master pubkey")
	}
}

func TestLegacyDirectV0RejectedForOtherVaults(t *testing.T) {
	master := testMaster(t, 0x21)
	if _, err := DeriveVaultCosignerScalar(master, "tenant-b", CosignerModeLegacyDirectV0); err == nil {
		t.Fatal("legacy-direct-v0 accepted for a non-first vault")
	}
	if _, err := DeriveVaultCosignerScalar(master, LegacyFirstVaultID, CosignerModeHKDFSHA256V1); err == nil {
		t.Fatal("hkdf-sha256-v1 accepted for the first vault")
	}
}

func TestHKDFSHA256V1MatchesRFC5869OneBlockExpand(t *testing.T) {
	master := testMaster(t, 0x21)
	vaultID := "tenant-example"
	got, err := DeriveVaultCosignerScalar(master, vaultID, CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}

	ikm := master.Serialize()
	extract := hmac.New(sha256.New, []byte(vaultCosignerHKDFSalt))
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)
	info := append([]byte(nil), vaultCosignerHKDFInfo...)
	info = append(info, 0)
	info = append(info, vaultID...)
	info = append(info, 0, 0) // counter 0
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write(info)
	_, _ = expand.Write([]byte{1})
	wantOKM := expand.Sum(nil)
	if !scalarInRange(wantOKM, btcec.S256().N) {
		t.Fatal("test vector counter 0 is not a valid scalar; spec lock would hide a retry")
	}
	if !bytes.Equal(got.Serialize(), wantOKM) {
		t.Fatalf("hkdf-sha256-v1 scalar = %x, want RFC 5869 OKM %x", got.Serialize(), wantOKM)
	}

	again, err := DeriveVaultCosignerScalar(master, vaultID, CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Serialize(), got.Serialize()) {
		t.Fatal("hkdf-sha256-v1 is not deterministic")
	}
	other, err := DeriveVaultCosignerScalar(master, "tenant-other", CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.Serialize(), got.Serialize()) {
		t.Fatal("distinct vault ids derived the same cosigner scalar")
	}
}

func TestVaultIDIsOpaqueUTF8NotUUIDBytes(t *testing.T) {
	master := testMaster(t, 0x21)
	text := "550e8400-e29b-41d4-a716-446655440000"
	raw, err := hex.DecodeString("550e8400e29b41d4a716446655440000")
	if err != nil {
		t.Fatal(err)
	}
	fromText, err := DeriveVaultCosignerScalar(master, text, CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	fromRaw, err := DeriveVaultCosignerScalar(master, string(raw), CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fromText.Serialize(), fromRaw.Serialize()) {
		t.Fatal("UTF-8 UUID string and 16 raw UUID bytes must not collide")
	}
}

func TestCheckedInHKDFAndLegacyGoldens(t *testing.T) {
	type hkdfFile struct {
		Mode                   string `json:"mode"`
		Salt                   string `json:"salt"`
		InfoPrefix             string `json:"infoPrefix"`
		MasterScalarHex        string `json:"masterScalarHex"`
		MasterCompressedPubHex string `json:"masterCompressedPubHex"`
		Vectors                []struct {
			VaultID          string `json:"vaultId"`
			Counter          int    `json:"counter"`
			OKMHex           string `json:"okmHex"`
			CompressedPubHex string `json:"compressedPubHex"`
		} `json:"vectors"`
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "hkdf-sha256-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file hkdfFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Mode != CosignerModeHKDFSHA256V1 || file.Salt != vaultCosignerHKDFSalt || file.InfoPrefix != vaultCosignerHKDFInfo {
		t.Fatal("hkdf golden header drifted from the protocol constants")
	}
	masterRaw, err := hex.DecodeString(file.MasterScalarHex)
	if err != nil {
		t.Fatal(err)
	}
	master, _ := btcec.PrivKeyFromBytes(masterRaw)
	if hex.EncodeToString(master.PubKey().SerializeCompressed()) != file.MasterCompressedPubHex {
		t.Fatal("hkdf golden master pub mismatch")
	}
	for _, vec := range file.Vectors {
		got, err := DeriveVaultCosignerScalar(master, vec.VaultID, CosignerModeHKDFSHA256V1)
		if err != nil {
			t.Fatalf("%s: %v", vec.VaultID, err)
		}
		if hex.EncodeToString(got.Serialize()) != vec.OKMHex {
			t.Fatalf("%s okm drifted from checked-in golden", vec.VaultID)
		}
		if hex.EncodeToString(got.PubKey().SerializeCompressed()) != vec.CompressedPubHex {
			t.Fatalf("%s pub drifted from checked-in golden", vec.VaultID)
		}
	}

	legacyRaw, err := os.ReadFile(filepath.Join("testdata", "legacy-direct-v0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		Mode             string `json:"mode"`
		VaultID          string `json:"vaultId"`
		MasterScalarHex  string `json:"masterScalarHex"`
		CompressedPubHex string `json:"compressedPubHex"`
	}
	if err := json.Unmarshal(legacyRaw, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Mode != CosignerModeLegacyDirectV0 || legacy.VaultID != LegacyFirstVaultID {
		t.Fatal("legacy golden header drifted")
	}
	legacyMaster, _ := btcec.PrivKeyFromBytes(mustDecodeHex(t, legacy.MasterScalarHex))
	got, err := DeriveVaultCosignerScalar(legacyMaster, legacy.VaultID, CosignerModeLegacyDirectV0)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got.PubKey().SerializeCompressed()) != legacy.CompressedPubHex {
		t.Fatal("legacy-direct-v0 golden pub drifted")
	}
}

func mustDecodeHex(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyVaultCosignerPubMatchesPersistedCompressedKey(t *testing.T) {
	master := testMaster(t, 0x21)
	rec := VaultRecord{
		VaultID:           LegacyFirstVaultID,
		CosignerMode:      CosignerModeLegacyDirectV0,
		VaultCosignerBase: master.PubKey().SerializeCompressed(),
	}
	if err := VerifyVaultCosignerPub(master, rec); err != nil {
		t.Fatal(err)
	}
	rec.VaultCosignerBase[0] ^= 1
	if err := VerifyVaultCosignerPub(master, rec); err == nil {
		t.Fatal("parity-flipped cosigner pub accepted")
	}
}
