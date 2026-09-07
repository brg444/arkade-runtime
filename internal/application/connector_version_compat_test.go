package application

import (
	"bytes"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Seed the pre-upgrade contract through its unchanged builders and authenticated
// ledger. New enrollment endpoints must never select this template.
func seedV1Connector(t *testing.T, f *connectorFixture, id string, token []byte, req RegisterRequest) RegisterRequest {
	t.Helper()
	parsed, err := f.svc.parseRegisterRequestIndependent(req)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = f.svc.applyVaultBoardEnrollmentRequest(parsed, req)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = applyConnectorEnrollmentRequest(parsed, req, f.network)
	if err != nil {
		t.Fatal(err)
	}
	child, err := f.svc.keys.enrollmentPublic(id)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, snapshot, _, origin, err := f.svc.mintConnectorCredential(id, parsed, child, connector.Template)
	if err != nil {
		t.Fatal(err)
	}
	record := vaultRecordFromDescriptor(descriptor)
	credential := policy.VaultCredential{CredentialID: descriptor.ID, VaultID: id, WebAuthnP256: descriptor.WebAuthnP256, UserHandle: []byte(id), Resident: true}
	if err = policy.SealVaultRecord(&record, f.integrityKey); err != nil {
		t.Fatal(err)
	}
	if err = policy.SealVaultCredential(&credential, f.integrityKey); err != nil {
		t.Fatal(err)
	}
	if err = policy.SealConnectorEnrollment(&origin, f.integrityKey); err != nil {
		t.Fatal(err)
	}
	board, boardSnapshot, err := f.svc.mintVaultBoardEnrollment(id, parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.led.CreateVaultWithBoard(policy.CreateVaultInput{Record: record, Credential: credential, TokenHash: token, Connector: &origin}, *board); err != nil {
		t.Fatal(err)
	}
	f.svc.publishEnrollmentAt(id, descriptor.ID, parsed.phone, snapshot, boardSnapshot)
	preview, err := f.svc.previewConnectorEnrollmentDescriptor(id, req, connector.Template)
	if err != nil {
		t.Fatal(err)
	}
	req.DescriptorHash = preview.DescriptorHash
	return req
}

func TestConnectorV1UpgradePreservesEnrollmentAndRecovery(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		for _, kind := range []connector.Kind{connector.Taproot, connector.NativeSegwit} {
			for _, tier := range []string{program.ProtectionTierStandard, program.ProtectionTierAdvanced} {
				t.Run(network+"/"+string(kind)+"/"+tier, func(t *testing.T) {
					f := newConnectorFixture(t, network)
					phone, _ := btcec.NewPrivateKey()
					hardware, _ := btcec.NewPrivateKey()
					board, _ := btcec.NewPrivateKey()
					var recovery *btcec.PrivateKey
					if tier == program.ProtectionTierAdvanced {
						recovery, _ = btcec.NewPrivateKey()
					}
					id, err := newOpaqueVaultID()
					if err != nil {
						t.Fatal(err)
					}
					token := bytes.Repeat([]byte{0x91}, 32)
					putConnectorInvite(t, f.led, token)
					req := connectorEnrollRequestForNetwork(t, network, phone, hardware, board, tier, recovery, kind, false)
					req = seedV1Connector(t, f, id, token, req)
					before := mustConnectorCred(t, f.svc, id)
					f.reopen(t)
					st, ok := f.svc.acceptDuplicateFinish(id, req)
					if !ok || st.SavingsAddr != before.SavingsAddress {
						t.Fatal("v1 duplicate finish changed or refused after upgrade")
					}
					cred := mustConnectorCred(t, f.svc, id)
					if cred.TemplateVersion != connector.Template || !bytes.Equal(cred.SavingsScript, before.SavingsScript) {
						t.Fatal("enrolled v1 contract changed")
					}
					family, err := f.svc.transitionFamily(cred)
					if err != nil || family.Savings.Address != before.SavingsAddress {
						t.Fatal("v1 recovery changed", err)
					}
					binding, err := f.svc.BuildRecoveryBindingFor(id, RecoveryBindingRequest{EnvelopeNonce: "111111111111111111111111", EnvelopeCiphertext: "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"})
					if err != nil || binding.Binding == "" {
						t.Fatal("v1 recovery binding unavailable", err)
					}
					changed := req
					changed.ConnectorFingerprint++
					if _, ok := f.svc.acceptDuplicateFinish(id, changed); ok {
						t.Fatal("changed origin accepted as duplicate")
					}
				})
			}
		}
	}
}

func TestConnectorOldUnfinishedPreviewRequiresNewProposal(t *testing.T) {
	f := newConnectorFixture(t, deployment.NetworkMainnet)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	board, _ := btcec.NewPrivateKey()
	id, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x92}, 32)
	putConnectorInvite(t, f.led, token)
	req := connectorEnrollRequestForNetwork(t, f.network, phone, hardware, board, program.ProtectionTierStandard, nil, connector.Taproot, false)
	old, err := f.svc.previewConnectorEnrollmentDescriptor(id, req, connector.Template)
	if err != nil {
		t.Fatal(err)
	}
	req.DescriptorHash = old.DescriptorHash
	if err = f.svc.CreateTenantVault(id, token, req); err == nil {
		t.Fatal("old preview silently converted into v2")
	}
	req = enrollConnectorVault(t, f.svc, id, token, req)
	if mustConnectorCred(t, f.svc, id).TemplateVersion != connector.DualTemplate {
		t.Fatal("new proposal did not select v2")
	}
	if _, ok := f.svc.acceptDuplicateFinish(id, req); !ok {
		t.Fatal("v2 exact retry refused")
	}
}
