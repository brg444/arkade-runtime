package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestSpendingRenewalContextWalletVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/renewal-context-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name           string                 `json:"name"`
		Status         Status                 `json:"status"`
		Context        spendingRenewalBinding `json:"context"`
		DescriptorHash string                 `json:"descriptorHash"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 10 {
		t.Fatalf("expected ten cross-language vectors, got %d", len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			b := v.Context
			got, err := b.digest()
			if err != nil || got != v.DescriptorHash {
				t.Fatalf("context digest %s: %v", got, err)
			}
			// Rebuild with Go's contract implementation, independently of the
			// TypeScript script builder that produced the vector's output script.
			var script []byte
			if b.Program == light.Program {
				if v.Status.LightDescriptor == nil {
					t.Fatal("missing Light descriptor")
				}
				pins, _ := deployment.IdentityFor(b.Network)
				tree, err := buildLightPolicyTree(*v.Status.LightDescriptor, mustDecodeRenewalHex(pins.OperatorSignerPubHex), map[string]string{"mainnet": "ark", "mutinynet": "tark"}[b.Network])
				if err != nil {
					t.Fatal(err)
				}
				script = tree.PkScript
			} else {
				xonly := func(encoded string) []byte {
					raw, err := hex.DecodeString(encoded)
					if err != nil {
						t.Fatal(err)
					}
					if len(raw) == 32 {
						return raw
					}
					pub, err := btcec.ParsePubKey(raw)
					if err != nil {
						t.Fatal(err)
					}
					return schnorr.SerializePubKey(pub)
				}
				pins, err := program.PinsFor(b.Network)
				if err != nil {
					t.Fatal(err)
				}
				params := policy.VaultPolicyV1Params{Network: b.Network, UserPub: xonly(b.OwnerPub), VtxoVaultCosignerPub: xonly(b.CosignerPub), ArkdServerPub: xonly(b.OperatorPub), DelegatePub: xonly(pins.DelegatePub), ExitDevicePub: xonly(b.OwnerPub), ExitHardwarePub: xonly(v.Status.ExternalOwnerWalletPub)}
				if v.Status.RecoveryKeyPub != "" {
					params.ExitRecoveryPub = xonly(v.Status.RecoveryKeyPub)
				}
				tree, err := policy.BuildVaultPolicyV1Tree(params)
				if err != nil {
					t.Fatal(err)
				}
				script = tree.PkScript
			}
			if hex.EncodeToString(script) != b.ScriptPubKey {
				t.Fatal("Go and wallet enrolled scripts differ")
			}
			changed := b
			changed.Program = "vaulted-light-v1"
			if _, err := changed.digest(); err == nil {
				t.Fatal("profile accepted as program")
			}
			changed = b
			changed.OperatorPub = b.OwnerPub
			if _, err := changed.digest(); err == nil {
				t.Fatal("Operator substitution accepted")
			}
			changed = b
			changed.VaultID = strings.Repeat("ef", 32)
			other, err := changed.digest()
			if err != nil || other == got {
				t.Fatal("vault identity is not committed")
			}
		})
	}
}

func TestSpendingRenewalContextUsesEnrolledKeyScope(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		for _, tier := range []string{"standard", "advanced"} {
			t.Run(network+"/"+tier, func(t *testing.T) {
				f := newConnectorFixture(t, network)
				phone, _ := btcec.NewPrivateKey()
				hardware, _ := btcec.NewPrivateKey()
				boarding, _ := btcec.NewPrivateKey()
				var recovery *btcec.PrivateKey
				if tier == "advanced" {
					recovery, _ = btcec.NewPrivateKey()
				}
				id := strings.Repeat("12", 32)
				if tier == "advanced" {
					id = "550e8400-e29b-41d4-a716-446655440000"
				}
				token := bytes.Repeat([]byte{0x13}, 32)
				putConnectorInvite(t, f.led, token)
				req := connectorEnrollRequestForNetwork(t, network, phone, hardware, boarding, tier, recovery, connector.Taproot, false)
				enrollConnectorVault(t, f.svc, id, token, req)
				ctx, err := f.svc.spendingRenewalContext(id)
				if err != nil {
					t.Fatal(err)
				}
				if ctx.Binding.Program != program.VaultPolicyV1 || ctx.Binding.ProtectionTier != tier || ctx.KeyScope.lightProfile || ctx.Binding.VaultID != id || ctx.KeyScope.vaultID != id {
					t.Fatal("Vault authority substituted")
				}
				if ctx.Tree.DelegatePub == nil || len(ctx.Tree.RevealedScripts) <= 2 {
					t.Fatal("full Vault tree lost")
				}
				if _, err := f.svc.spendingRenewalContext(strings.Repeat("ab", 32)); err == nil {
					t.Fatal("unenrolled vault accepted")
				}
			})
		}
	}

	f := newLightRenewalProofFixture(t)
	ctx, err := f.env.svc.spendingRenewalContext(f.descriptor.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Binding.Program != light.Program || ctx.Binding.ProtectionTier != "light" || !ctx.KeyScope.lightProfile || ctx.Tree.DelegatePub != nil {
		t.Fatal("Light authority substituted")
	}
}
