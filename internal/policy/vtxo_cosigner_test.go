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

	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
)

func testAdvertisedServerPub(t *testing.T) []byte {
	t.Helper()
	priv := testMaster(t, 0x07)
	return priv.PubKey().SerializeCompressed()
}

func TestVtxoHKDFSHA256V1MatchesRFC5869OneBlockExpand(t *testing.T) {
	master := testMaster(t, 0x21)
	vaultID := "tenant-example"
	advertised := testAdvertisedServerPub(t)
	got, err := DeriveVtxoVaultCosignerScalar(master, vaultID, program.VaultPolicyV1, program.NetworkMutinynet, advertised)
	if err != nil {
		t.Fatal(err)
	}

	ikm := master.Serialize()
	extract := hmac.New(sha256.New, []byte(vtxoVaultCosignerHKDFSalt))
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)
	info := append([]byte(nil), vtxoVaultCosignerHKDFInfo...)
	info = append(info, 0)
	info = append(info, vaultID...)
	info = append(info, 0)
	info = append(info, program.VaultPolicyV1...)
	info = append(info, 0)
	info = append(info, program.NetworkMutinynet...)
	info = append(info, 0)
	info = append(info, advertised...)
	info = append(info, 0, 0)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write(info)
	_, _ = expand.Write([]byte{1})
	rawOKM := expand.Sum(nil)
	if !scalarInRange(rawOKM, btcec.S256().N) {
		t.Fatal("test vector counter 0 is not a valid scalar; spec lock would hide a retry")
	}
	rawPriv, _ := btcec.PrivKeyFromBytes(rawOKM)
	want := evenYPrivateKey(rawPriv)
	if !bytes.Equal(got.Serialize(), want.Serialize()) {
		t.Fatalf("vtxo-hkdf-sha256-v1 scalar = %x, want RFC 5869 even-Y %x", got.Serialize(), want.Serialize())
	}

	again, err := DeriveVtxoVaultCosignerScalar(master, vaultID, program.VaultPolicyV1, program.NetworkMutinynet, advertised)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Serialize(), got.Serialize()) {
		t.Fatal("vtxo-hkdf-sha256-v1 is not deterministic")
	}
}

func TestVtxoHKDFPreimageGolden(t *testing.T) {
	advertised := testAdvertisedServerPub(t)
	info := vtxoVaultCosignerInfo("tenant-example", program.VaultPolicyV1, program.NetworkMutinynet, advertised, 0)
	const want = "7674786f2d7661756c742d636f7369676e65722f76310074656e616e742d6578616d706c65007661756c742d706f6c6963792d7631006d7574696e796e65740002989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f0000"
	if hex.EncodeToString(info) != want {
		t.Fatalf("vtxo preimage = %x, want %s", info, want)
	}
	if bytes.Contains(info, []byte("ArkScriptHash")) {
		t.Fatal("vtxo preimage must not include ArkScriptHash")
	}
}

func TestVtxoPairwiseIndependence(t *testing.T) {
	master := testMaster(t, 0x21)
	vaultID := "tenant-example"
	advertised := testAdvertisedServerPub(t)
	vtxo, err := DeriveVtxoVaultCosignerScalar(master, vaultID, program.VaultPolicyV1, program.NetworkMutinynet, advertised)
	if err != nil {
		t.Fatal(err)
	}
	l1, err := DeriveVaultCosignerScalar(master, vaultID, CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(vtxo.Serialize(), l1.Serialize()) {
		t.Fatal("VTXO scalar collided with L1 DeriveVaultCosignerScalar")
	}
	got := vtxo.PubKey().SerializeCompressed()
	kernel, err := hex.DecodeString(deployment.MutinynetArkadeCosignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	g, err := hex.DecodeString(program.UnsafeGeneratorG)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := hex.DecodeString(program.UnsafeGenerator2G)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []struct {
		name string
		pub  []byte
	}{
		{"l1", l1.PubKey().SerializeCompressed()},
		{"advertised-arkd", advertised},
		{"kernel-base", kernel},
		{"G", g},
		{"2G", g2},
	}
	for _, item := range forbidden {
		if bytes.Equal(got, item.pub) {
			t.Fatalf("VTXO pub collided with %s", item.name)
		}
		if bytes.Equal(got[1:], item.pub[1:]) {
			t.Fatalf("VTXO x-only collided with %s", item.name)
		}
	}

	otherVault, err := DeriveVtxoVaultCosignerScalar(master, "tenant-other", program.VaultPolicyV1, program.NetworkMutinynet, advertised)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(otherVault.Serialize(), vtxo.Serialize()) {
		t.Fatal("distinct vault ids derived the same VTXO scalar")
	}
	otherNet, err := DeriveVtxoVaultCosignerScalar(master, vaultID, program.VaultPolicyV1, program.NetworkMainnet, advertised)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(otherNet.Serialize(), vtxo.Serialize()) {
		t.Fatal("distinct networks derived the same VTXO scalar")
	}
	otherPolicy, err := DeriveVtxoVaultCosignerScalar(master, vaultID, "other-policy", program.NetworkMutinynet, advertised)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(otherPolicy.Serialize(), vtxo.Serialize()) {
		t.Fatal("distinct policy versions derived the same VTXO scalar")
	}
	otherPub := testMaster(t, 0x08).PubKey().SerializeCompressed()
	otherAdv, err := DeriveVtxoVaultCosignerScalar(master, vaultID, program.VaultPolicyV1, program.NetworkMutinynet, otherPub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(otherAdv.Serialize(), vtxo.Serialize()) {
		t.Fatal("distinct advertised server pubs derived the same VTXO scalar")
	}
}

func TestVtxoEvenYSerialization(t *testing.T) {
	master := testMaster(t, 0x21)
	advertised := testAdvertisedServerPub(t)
	foundOdd := false
	for i := 0; i < 256; i++ {
		vaultID := "odd-y-" + string(rune('a'+i%26)) + hex.EncodeToString([]byte{byte(i)})
		got, err := DeriveVtxoVaultCosignerScalar(master, vaultID, program.VaultPolicyV1, program.NetworkMutinynet, advertised)
		if err != nil {
			t.Fatal(err)
		}
		compressed := got.PubKey().SerializeCompressed()
		if compressed[0] != 0x02 {
			t.Fatalf("VTXO pub %x is not even-Y compressed", compressed)
		}
		ikm := master.Serialize()
		extract := hmac.New(sha256.New, []byte(vtxoVaultCosignerHKDFSalt))
		_, _ = extract.Write(ikm)
		prk := extract.Sum(nil)
		info := vtxoVaultCosignerInfo(vaultID, program.VaultPolicyV1, program.NetworkMutinynet, advertised, 0)
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{1})
		rawOKM := expand.Sum(nil)
		if !scalarInRange(rawOKM, btcec.S256().N) {
			continue
		}
		rawPriv, _ := btcec.PrivKeyFromBytes(rawOKM)
		rawPub := rawPriv.PubKey().SerializeCompressed()
		if rawPub[0] == 0x03 {
			foundOdd = true
			negated := evenYPrivateKey(rawPriv)
			if !bytes.Equal(got.Serialize(), negated.Serialize()) {
				t.Fatal("odd-Y raw scalar was not negated")
			}
			if bytes.Equal(got.Serialize(), rawPriv.Serialize()) {
				t.Fatal("odd-Y raw scalar was returned unchanged")
			}
			if negated.PubKey().SerializeCompressed()[0] != 0x02 {
				t.Fatal("negated scalar is still odd-Y")
			}
			break
		}
	}
	if !foundOdd {
		t.Fatal("no odd-Y raw OKM found to lock the even-Y rule")
	}
}

func TestVtxoRejectsInvalidInputs(t *testing.T) {
	master := testMaster(t, 0x21)
	advertised := testAdvertisedServerPub(t)
	if _, err := DeriveVtxoVaultCosignerScalar(nil, "tenant-example", program.VaultPolicyV1, program.NetworkMutinynet, advertised); err == nil {
		t.Fatal("nil master accepted")
	}
	if _, err := DeriveVtxoVaultCosignerScalar(master, "", program.VaultPolicyV1, program.NetworkMutinynet, advertised); err == nil {
		t.Fatal("empty vault id accepted")
	}
	if _, err := DeriveVtxoVaultCosignerScalar(master, "tenant-example", "", program.NetworkMutinynet, advertised); err == nil {
		t.Fatal("empty policy version accepted")
	}
	if _, err := DeriveVtxoVaultCosignerScalar(master, "tenant-example", program.VaultPolicyV1, "signet", advertised); err == nil {
		t.Fatal("unsupported network accepted")
	}
	if _, err := DeriveVtxoVaultCosignerScalar(master, "tenant-example", program.VaultPolicyV1, program.NetworkMutinynet, advertised[:32]); err == nil {
		t.Fatal("32-byte advertised pub accepted")
	}
	uncompressed := append([]byte{0x04}, bytes.Repeat([]byte{0x11}, 64)...)
	if _, err := DeriveVtxoVaultCosignerScalar(master, "tenant-example", program.VaultPolicyV1, program.NetworkMutinynet, uncompressed); err == nil {
		t.Fatal("uncompressed advertised pub accepted")
	}
}

func TestCheckedInVtxoHKDFGoldens(t *testing.T) {
	type vtxoFile struct {
		Mode                   string `json:"mode"`
		Salt                   string `json:"salt"`
		InfoPrefix             string `json:"infoPrefix"`
		PolicyVersion          string `json:"policyVersion"`
		Network                string `json:"network"`
		AdvertisedServerPubHex string `json:"advertisedServerPubHex"`
		MasterScalarHex        string `json:"masterScalarHex"`
		MasterCompressedPubHex string `json:"masterCompressedPubHex"`
		Vectors                []struct {
			VaultID          string `json:"vaultId"`
			Counter          int    `json:"counter"`
			PreimageHex      string `json:"preimageHex"`
			RawOKMHex        string `json:"rawOkmHex"`
			OKMHex           string `json:"okmHex"`
			CompressedPubHex string `json:"compressedPubHex"`
		} `json:"vectors"`
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "vtxo-hkdf-sha256-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file vtxoFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Mode != CosignerModeVtxoHKDFSHA256V1 || file.Salt != vtxoVaultCosignerHKDFSalt || file.InfoPrefix != vtxoVaultCosignerHKDFInfo {
		t.Fatal("vtxo hkdf golden header drifted from the protocol constants")
	}
	if file.PolicyVersion != program.VaultPolicyV1 || file.Network != program.NetworkMutinynet {
		t.Fatal("vtxo hkdf golden policy/network drifted")
	}
	if file.Salt == vaultCosignerHKDFSalt {
		t.Fatal("vtxo domain reused the L1 vault-cosigner salt")
	}
	masterRaw, err := hex.DecodeString(file.MasterScalarHex)
	if err != nil {
		t.Fatal(err)
	}
	master, _ := btcec.PrivKeyFromBytes(masterRaw)
	if hex.EncodeToString(master.PubKey().SerializeCompressed()) != file.MasterCompressedPubHex {
		t.Fatal("vtxo hkdf golden master pub mismatch")
	}
	advertised, err := hex.DecodeString(file.AdvertisedServerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, vec := range file.Vectors {
		info := vtxoVaultCosignerInfo(vec.VaultID, file.PolicyVersion, file.Network, advertised, byte(vec.Counter))
		if hex.EncodeToString(info) != vec.PreimageHex {
			t.Fatalf("%s preimage drifted from checked-in golden", vec.VaultID)
		}
		ikm := master.Serialize()
		extract := hmac.New(sha256.New, []byte(vtxoVaultCosignerHKDFSalt))
		_, _ = extract.Write(ikm)
		prk := extract.Sum(nil)
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{1})
		if hex.EncodeToString(expand.Sum(nil)) != vec.RawOKMHex {
			t.Fatalf("%s raw OKM drifted from checked-in golden", vec.VaultID)
		}
		got, err := DeriveVtxoVaultCosignerScalar(master, vec.VaultID, file.PolicyVersion, file.Network, advertised)
		if err != nil {
			t.Fatalf("%s: %v", vec.VaultID, err)
		}
		if hex.EncodeToString(got.Serialize()) != vec.OKMHex {
			t.Fatalf("%s okm drifted from checked-in golden", vec.VaultID)
		}
		if hex.EncodeToString(got.PubKey().SerializeCompressed()) != vec.CompressedPubHex {
			t.Fatalf("%s pub drifted from checked-in golden", vec.VaultID)
		}
		if vec.CompressedPubHex[:2] != "02" {
			t.Fatalf("%s pub is not even-Y", vec.VaultID)
		}
	}
	sawNegation := false
	for _, vec := range file.Vectors {
		if vec.RawOKMHex != vec.OKMHex {
			sawNegation = true
			break
		}
	}
	if !sawNegation {
		t.Fatal("vtxo goldens must include an odd-Y vector that negates")
	}
}
