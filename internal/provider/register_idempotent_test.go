package provider

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestConcurrentExactRegisterAndStatusKeepRuntimeKeysImmutable(t *testing.T) {
	svc, req := newRegisterableService(t)
	if err := svc.Register(req); err != nil {
		t.Fatal(err)
	}
	wantOffline, wantProvider := svc.RecoveryKey, svc.VaultCosignerPub
	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 20; i++ {
				if worker%2 == 0 {
					if err := svc.Register(req); err != nil {
						errs <- err
						return
					}
					continue
				}
				status, err := svc.Status(context.Background())
				if err != nil {
					errs <- err
					return
				}
				if status.ExternalOwnerWalletPub == "" || status.VaultCosignerBasePub == "" || status.OperationalAddr == "" {
					errs <- fmt.Errorf("partial status during idempotent registration: %+v", status)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if svc.RecoveryKey != wantOffline || svc.VaultCosignerPub != wantProvider {
		t.Fatal("idempotent registration rewrote immutable runtime keys")
	}
}

func TestRegisterExactRetryAcceptedAndMismatchesStayLocked(t *testing.T) {
	svc, req := newRegisterableService(t)
	if err := svc.Register(req); err != nil {
		t.Fatalf("first register: %v", err)
	}
	wantAddr := svc.Operational.Address

	retry := req
	retry.CredentialID = strings.ToUpper(req.CredentialID)
	retry.WebAuthnP256 = strings.ToUpper(req.WebAuthnP256)
	retry.PhoneDirectP256 = strings.ToUpper(req.PhoneDirectP256)
	retry.PhoneRoutineBIP340Pub = strings.ToUpper(req.PhoneRoutineBIP340Pub)
	if err := svc.Register(retry); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	if svc.Operational.Address != wantAddr {
		t.Fatal("exact retry changed the enrolled operational address")
	}

	if err := svc.Register(RegisterRequest{
		CredentialID:          "zz",
		WebAuthnP256:          req.WebAuthnP256,
		PhoneDirectP256:       req.PhoneDirectP256,
		PhoneRoutineBIP340Pub: req.PhoneRoutineBIP340Pub,
	}); err == nil || !strings.Contains(err.Error(), "hex") {
		t.Fatalf("malformed retry before compare: %v", err)
	}

	mismatches := []struct {
		name string
		mut  func(*RegisterRequest)
	}{
		{"credential id", func(r *RegisterRequest) { r.CredentialID = hex.EncodeToString([]byte{0x99}) }},
		{"webauthn p256", func(r *RegisterRequest) { r.WebAuthnP256 = otherP256(t) }},
		{"direct p256", func(r *RegisterRequest) { r.PhoneDirectP256 = otherP256(t) }},
		{"hot pub", func(r *RegisterRequest) { r.PhoneRoutineBIP340Pub = otherHot(t) }},
	}
	for _, test := range mismatches {
		t.Run(test.name, func(t *testing.T) {
			bad := req
			test.mut(&bad)
			err := svc.Register(bad)
			if err == nil || !strings.Contains(err.Error(), "enrollment locked") {
				t.Fatalf("mismatch %s: %v", test.name, err)
			}
		})
	}
}

func newRegisterableService(t *testing.T) (*Service, RegisterRequest) {
	t.Helper()
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offline, err := btcec.NewPrivateKey()
	_ = offline
	if err != nil {
		t.Fatal(err)
	}
	prov, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	passkey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "register.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	svc := &Service{
		Ledger:              led,
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerPub:    prov.PubKey(),
		ArkadeCosignerPub:   arkadeKey.PubKey(),
		VaultSigner:         LocalSigner{Priv: prov},
		ArkadeCosignerSigner: LocalSigner{
			Priv: arkadeKey,
		},
	}
	req := RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("enroll-credential")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}
	return svc, req
}

func otherP256(t *testing.T) string {
	t.Helper()
	key, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(webauthn.CompressedP256(key))
}

func TestRegisterSameTupleDifferentRuntimeRaceDoesNotPublishLoser(t *testing.T) {
	t.Run("different provider", func(t *testing.T) {
		runSameTupleRuntimeRace(t, true, false)
	})
	t.Run("different offline", func(t *testing.T) {
		t.Skip("v4 trees no longer commit a recovery key, so offline runtime identity is not a race axis")
		runSameTupleRuntimeRace(t, false, true)
	})
}

func runSameTupleRuntimeRace(t *testing.T, differentProvider, differentOffline bool) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "same-tuple-race.sqlite")
	ledgers := make([]*policy.Ledger, 2)
	for i := range ledgers {
		led, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatalf("open ledger %d: %v", i, err)
		}
		ledgers[i] = led
		t.Cleanup(func() { _ = led.Close() })
	}

	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	passkey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	externalOwner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offlineA, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offlineB := offlineA
	_ = offlineB
	if differentOffline {
		offlineB, err = btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
	}
	provA, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	provB := provA
	if differentProvider {
		provB, err = btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	req := RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("shared-credential")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}
	type handle struct {
		svc *Service
		err error
	}
	handles := []handle{
		{svc: &Service{
			Ledger:              ledgers[0],
			ExternalOwnerWallet: externalOwner.PubKey(),
			VaultCosignerPub:    provA.PubKey(),
			ArkadeCosignerPub:   arkadeKey.PubKey(),
			VaultSigner:         LocalSigner{Priv: provA},
			ArkadeCosignerSigner: LocalSigner{
				Priv: arkadeKey,
			},
		}},
		{svc: &Service{
			Ledger:              ledgers[1],
			ExternalOwnerWallet: externalOwner.PubKey(),
			VaultCosignerPub:    provB.PubKey(),
			ArkadeCosignerPub:   arkadeKey.PubKey(),
			VaultSigner:         LocalSigner{Priv: provB},
			ArkadeCosignerSigner: LocalSigner{
				Priv: arkadeKey,
			},
		}},
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range handles {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			handles[i].err = handles[i].svc.Register(req)
		}(i)
	}
	close(start)
	wg.Wait()

	var winner, loser int
	switch {
	case handles[0].err == nil && handles[1].err != nil:
		winner, loser = 0, 1
	case handles[1].err == nil && handles[0].err != nil:
		winner, loser = 1, 0
	default:
		t.Fatalf("want exactly one success: err0=%v err1=%v", handles[0].err, handles[1].err)
	}
	lost := handles[loser].svc
	if lost.PhoneRoutineBIP340 != nil || lost.Operational != nil || lost.Savings != nil {
		t.Fatal("losing handle published vault state")
	}
	if snap := lost.enrolled(); snap.PhoneRoutineBIP340 != nil || snap.Operational != nil || snap.Savings != nil {
		t.Fatal("losing handle published an enrollment snapshot")
	}

	persisted, err := ledgers[0].GetCredential()
	if err != nil || persisted == nil {
		t.Fatalf("persisted enrollment: %v", err)
	}
	wantProv := handles[winner].svc.VaultCosignerPub.SerializeCompressed()
	if !bytes.Equal(persisted.VaultCosignerBase, wantProv) {
		t.Fatal("persisted descriptor is not the winner's runtime keys")
	}
	if handles[winner].svc.Operational == nil ||
		handles[winner].svc.Operational.Address != persisted.OperationalAddress {
		t.Fatal("winner did not publish the persisted operational vault")
	}
	if bytes.Equal(lost.VaultCosignerPub.SerializeCompressed(), persisted.VaultCosignerBase) {
		t.Fatal("test setup failed: loser runtime matches persisted descriptor")
	}
}

func otherHot(t *testing.T) string {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key.PubKey().SerializeCompressed())
}
