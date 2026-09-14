package application

import (
	"reflect"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

func TestDirectHardwareEnrollmentRejectedWithoutConsumingInvite(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		for _, advanced := range []bool{false, true} {
			tier := program.ProtectionTierStandard
			if advanced {
				tier = program.ProtectionTierAdvanced
			}
			t.Run(network+"/"+tier, func(t *testing.T) {
				f := ledgerEnrollmentReadyForNetwork(t, advanced, network)
				retired := f.request
				retired.LedgerSavings = nil
				if _, err := f.svc.ProposeEnrollment(f.token, retired); err == nil {
					t.Fatal("direct-hardware proposal accepted")
				}
				if _, err := f.svc.FinishEnrollment(t.Context(), f.token, retired); err == nil {
					t.Fatal("direct-hardware enrollment accepted")
				}
				view, err := f.svc.InviteStatus(f.token)
				if err != nil || !view.CanEnroll || view.VaultID != nil {
					t.Fatalf("rejected enrollment consumed invite: %+v %v", view, err)
				}
				f.finish(t)
				credential, err := f.svc.loadVerifiedCredentialFor(f.start.VaultID)
				if err != nil {
					t.Fatal(err)
				}
				credential.TemplateVersion = "phone-hww-recovery-savings-v1"
				if err := f.svc.requireCompatible(credential); err == nil {
					t.Fatal("discarded template accepted for restore")
				}
				if _, _, _, _, _, _, err := f.svc.rebuildFromCredential(credential); err == nil {
					t.Fatal("discarded template rebuilt")
				}
				transition := f.transition(t, "initiate", "hardware", "")
				transition.LedgerSavings = nil
				if _, err := f.svc.SignTransition(t.Context(), transition); err == nil {
					t.Fatal("recovery dispatch accepted implicit direct-hardware family")
				}
			})
		}
	}
}

func TestPublicEnrollmentOffersOnlyQualifiedRetainedSetups(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			f := ledgerEnrollmentReadyForNetwork(t, false, network)
			f.svc.LightEnabled = true
			status, err := f.svc.PublicStatus()
			if err != nil {
				t.Fatal(err)
			}
			if status.TemplateVersion != program.SpendingOnlyTemplate || !reflect.DeepEqual(status.SupportedSetups, []string{"light", "standard", "advanced"}) || status.LedgerSavingsCapability == nil || status.LedgerSavingsCapability.TemplateVersion != savings.LedgerNativeTemplate {
				t.Fatalf("retained setups: %+v", status)
			}
			f.svc.LedgerSavingsEnabled = false
			status, err = f.svc.PublicStatus()
			if err != nil || !reflect.DeepEqual(status.SupportedSetups, []string{"light"}) || status.LedgerSavingsCapability != nil {
				t.Fatalf("unqualified protected setup offered: %+v %v", status, err)
			}
			if _, err := f.svc.StartEnrollment(f.token, EnrollStartRequest{ProtectionTier: f.start.ProtectionTier, SpendingPolicy: f.start.SpendingPolicy, SpendingPolicyDigest: f.start.SpendingPolicyDigest}); err == nil {
				t.Fatal("unqualified protected ceremony started")
			}
		})
	}
}
