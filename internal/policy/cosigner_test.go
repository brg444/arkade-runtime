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

func TestHKDFSHA256V1MatchesRFC5869OneBlockExpand(t *testing.T) {
	master := testMaster(t, 0x21)
	vaultID := "tenant-example"
	got, err := DeriveVaultCosignerScalar(master, vaultID, CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}

	extract := hmac.New(sha256.New, []byte(vaultCosignerHKDFSalt))
	_, _ = extract.Write(master.Serialize())
	prk := extract.Sum(nil)
	info := append([]byte(nil), vaultCosignerHKDFInfo...)
	info = append(info, 0)
	info = append(info, vaultID...)
	info = append(info, 0, 0)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write(info)
	_, _ = expand.Write([]byte{1})
	want := expand.Sum(nil)
	if !scalarInRange(want) {
		t.Fatal("test vector did not produce a scalar")
	}
	if !bytes.Equal(got.Serialize(), want) {
		t.Fatalf("derived scalar = %x, want %x", got.Serialize(), want)
	}

	again, err := DeriveVaultCosignerScalar(master, vaultID, CosignerModeHKDFSHA256V1)
	if err != nil || !bytes.Equal(again.Serialize(), got.Serialize()) {
		t.Fatalf("derivation is not deterministic: %v", err)
	}
	other, err := DeriveVaultCosignerScalar(master, "tenant-other", CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.Serialize(), got.Serialize()) {
		t.Fatal("different vault ids derived the same scalar")
	}
}

func TestVaultIDIsOpaqueUTF8(t *testing.T) {
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
		t.Fatal("UTF-8 UUID text collided with raw UUID bytes")
	}
}

func TestCheckedInHKDFGolden(t *testing.T) {
	var file struct {
		Mode                   string `json:"mode"`
		Salt                   string `json:"salt"`
		InfoPrefix             string `json:"infoPrefix"`
		MasterScalarHex        string `json:"masterScalarHex"`
		MasterCompressedPubHex string `json:"masterCompressedPubHex"`
		Vectors                []struct {
			VaultID          string `json:"vaultId"`
			OKMHex           string `json:"okmHex"`
			CompressedPubHex string `json:"compressedPubHex"`
		} `json:"vectors"`
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "hkdf-sha256-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Mode != CosignerModeHKDFSHA256V1 || file.Salt != vaultCosignerHKDFSalt || file.InfoPrefix != vaultCosignerHKDFInfo {
		t.Fatal("HKDF golden header drifted")
	}
	masterRaw, err := hex.DecodeString(file.MasterScalarHex)
	if err != nil {
		t.Fatal(err)
	}
	master, _ := btcec.PrivKeyFromBytes(masterRaw)
	if hex.EncodeToString(master.PubKey().SerializeCompressed()) != file.MasterCompressedPubHex {
		t.Fatal("HKDF golden master pubkey drifted")
	}
	for _, vector := range file.Vectors {
		got, err := DeriveVaultCosignerScalar(master, vector.VaultID, CosignerModeHKDFSHA256V1)
		if err != nil {
			t.Fatalf("%s: %v", vector.VaultID, err)
		}
		if hex.EncodeToString(got.Serialize()) != vector.OKMHex ||
			hex.EncodeToString(got.PubKey().SerializeCompressed()) != vector.CompressedPubHex {
			t.Fatalf("%s drifted from checked-in golden", vector.VaultID)
		}
	}
}

func TestVerifyVaultCosignerPubMatchesPersistedKey(t *testing.T) {
	master := testMaster(t, 0x21)
	child, err := DeriveVaultCosignerScalar(master, "vault-a", CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	rec := VaultRecord{
		VaultID: "vault-a", CosignerMode: CosignerModeHKDFSHA256V1,
		VaultCosignerBase: child.PubKey().SerializeCompressed(),
	}
	if err := VerifyVaultCosignerPub(master, rec); err != nil {
		t.Fatal(err)
	}
	rec.VaultCosignerBase[0] ^= 1
	if err := VerifyVaultCosignerPub(master, rec); err == nil {
		t.Fatal("parity-flipped cosigner pubkey accepted")
	}
}
