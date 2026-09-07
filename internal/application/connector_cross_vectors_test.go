package application

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
)

// The wallet consumes these exact public fixtures. They were generated through
// previewConnectorEnrollmentDescriptor, not by the TypeScript implementation.
// Both repositories reconstruct the complete commitment, including boarding
// and the public mainnet signer identity, from the same fixed input facts.
func TestConnectorEnrollmentCrossLanguageVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/connector-enrollment-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name  string
		Input struct {
			VaultID, Network, ProtectionTier                                   string
			PhonePub, PhoneDirectP256, RecoveryPub                             string
			VaultCosignerBase, ArkadeCosignerBase, ArkadeOrigin, ArkadeVersion string
			SpendingPolicy                                                     program.SpendingPolicy
			Origin                                                             struct {
				ConnectorPub, ConnectorType string
				ConnectorFingerprint        uint32
				ConnectorPath               []uint32
			}
			Boarding vaultBoardPublicDescriptor
		}
		Proposed struct {
			VaultID, DescriptorHash string
			Descriptor              connectorBoardCompositeDescriptor
		}
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 12 {
		t.Fatalf("expected12 qualified combinations, got %d", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			key := func(s string) *btcec.PublicKey {
				if s == "" {
					return nil
				}
				b, e := hex.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				p, e := btcec.ParsePubKey(b)
				if e != nil {
					t.Fatal(e)
				}
				return p
			}
			direct, e := hex.DecodeString(c.Input.PhoneDirectP256)
			if e != nil {
				t.Fatal(e)
			}
			in := savings.FamilyInput{VaultID: c.Input.VaultID, Network: c.Input.Network, ProtectionTier: c.Input.ProtectionTier,
				Phone: key(c.Input.PhonePub), Hardware: key(c.Input.Origin.ConnectorPub), Recovery: key(c.Input.RecoveryPub),
				PhoneDirectP256: direct, VaultCosignerBase: key(c.Input.VaultCosignerBase), ArkadeCosignerBase: key(c.Input.ArkadeCosignerBase),
				SpendingPolicy: c.Input.SpendingPolicy, TemplateVersion: connector.Template, ServerFreeClawback: true}
			kind := connector.Kind(c.Input.Origin.ConnectorType)
			family, e := connector.BuildFamily(in, kind)
			if e != nil {
				t.Fatal(e)
			}
			digest, e := connector.EnrollmentDigest(in, connector.KeyOrigin{Type: kind, PublicKey: in.Hardware.SerializeCompressed(), Fingerprint: c.Input.Origin.ConnectorFingerprint, Path: c.Input.Origin.ConnectorPath})
			if e != nil {
				t.Fatal(e)
			}
			if digest != c.Proposed.Descriptor.Connector.EnrollmentDigest {
				t.Fatal("connector origin/family commitment changed")
			}
			if hex.EncodeToString(family.Recovery.Savings.PkScript) != c.Proposed.Descriptor.Connector.SavingsScript || family.Recovery.Savings.Address != c.Proposed.Descriptor.Connector.SavingsAddress {
				t.Fatal("actual Savings tree changed")
			}
			descriptor, e := connectorSavingsPublicDescriptor(in, c.Input.ArkadeOrigin, c.Input.ArkadeVersion, family)
			if e != nil {
				t.Fatal(e)
			}
			boardHash, e := hashVaultBoardComposite(vaultBoardCompositeDescriptor{Schema: vaultBoardEnrollmentSchema, VaultID: in.VaultID, Savings: descriptor, Boarding: c.Input.Boarding})
			if e != nil {
				t.Fatal(e)
			}
			combined, e := hashConnectorBoardComposite(digest, boardHash)
			if e != nil {
				t.Fatal(e)
			}
			if combined != c.Proposed.DescriptorHash {
				t.Fatalf("combined enrollment hash changed: %s", combined)
			}
		})
	}
}
