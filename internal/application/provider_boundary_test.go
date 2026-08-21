package application

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// boundaryEnv keeps every key explicit. In particular, externalOwnerPriv and
// recoveryPriv never enter Service: only their public keys are part of the
// vault descriptor.
type boundaryEnv struct {
	service           *Service
	ledger            *policy.Ledger
	dbPath            string
	hotPriv           *btcec.PrivateKey
	externalOwnerPriv *btcec.PrivateKey
	recoveryPriv      *btcec.PrivateKey
	providerPriv      *btcec.PrivateKey
	arkadePriv        *btcec.PrivateKey
	credentialID      []byte
	passkeyPriv       *ecdsa.PrivateKey
	directPriv        *ecdsa.PrivateKey
	countingSigner    *boundaryCountingSigner
	arkadeSigner      *boundaryCountingSigner
}

type boundaryCountingSigner struct {
	mu       sync.Mutex
	calls    int
	delegate Signer
	err      error
	delay    time.Duration
	inspect  func(*psbt.Packet) error
}

type boundaryTransport struct {
	submit func(context.Context, string) (string, error)
}

func (t *boundaryTransport) SubmitOnchainTx(ctx context.Context, encoded string) (string, error) {
	return t.submit(ctx, encoded)
}

func (s *boundaryCountingSigner) Sign(ctx context.Context, ptx *psbt.Packet) (*psbt.Packet, error) {
	s.mu.Lock()
	s.calls++
	err := s.err
	delay := s.delay
	inspect := s.inspect
	delegate := s.delegate
	s.mu.Unlock()

	if inspect != nil {
		if inspectErr := inspect(ptx); inspectErr != nil {
			return nil, inspectErr
		}
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err != nil {
		return nil, err
	}
	if delegate == nil {
		return ptx, nil
	}
	return delegate.Sign(ctx, ptx)
}

func (s *boundaryCountingSigner) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestProviderBoundaryConcurrentFirstRegistrationPersistsOneVault(t *testing.T) {
	// Two provider processes do not share Service.mu. SQLite must therefore be
	// the enrollment authority, and a losing process must not publish the trees
	// it constructed speculatively before INSERT.
	dbPath := filepath.Join(t.TempDir(), "registration.sqlite")
	ledgers := make([]*policy.Ledger, 2)
	for i := range ledgers {
		ledger, err := policy.OpenLedger(dbPath, nil)
		if err != nil {
			t.Fatalf("open ledger %d: %v", i, err)
		}
		ledgers[i] = ledger
		t.Cleanup(func() { _ = ledger.Close() })
	}
	offline, err := btcec.NewPrivateKey()
	_ = offline
	if err != nil {
		t.Fatal(err)
	}
	providerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	type candidate struct {
		id      []byte
		hot     *btcec.PrivateKey
		passkey *ecdsa.PrivateKey
		direct  *ecdsa.PrivateKey
		svc     *Service
		err     error
	}
	candidates := make([]candidate, 2)
	for i := range candidates {
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
		candidates[i] = candidate{
			id:      []byte(fmt.Sprintf("racing-credential-%d", i)),
			hot:     hot,
			passkey: passkey,
			direct:  direct,
			svc: &Service{
				Ledger:              ledgers[i],
				ExternalOwnerWallet: externalOwner.PubKey(),
				VaultCosignerPub:    providerKey.PubKey(),
				ArkadeCosignerPub:   arkadeKey.PubKey(),
				VaultSigner:         LocalSigner{Priv: providerKey},
				ArkadeCosignerSigner: LocalSigner{
					Priv: arkadeKey,
				},
			},
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			c := &candidates[i]
			c.err = c.svc.Register(RegisterRequest{
				CredentialID:          hex.EncodeToString(c.id),
				WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(c.passkey)),
				PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(c.direct)),
				PhoneRoutineBIP340Pub: hex.EncodeToString(c.hot.PubKey().SerializeCompressed()),
			})
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	winner := -1
	for i := range candidates {
		if candidates[i].err == nil {
			successes++
			winner = i
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent registration successes: got %d, want 1 (errors: %v, %v)", successes, candidates[0].err, candidates[1].err)
	}
	loser := 1 - winner
	if candidates[loser].svc.PhoneRoutineBIP340 != nil || candidates[loser].svc.Operational != nil || candidates[loser].svc.Savings != nil {
		t.Fatal("losing registration leaked speculative hot key or vault trees into service memory")
	}

	persisted, err := ledgers[0].GetCredential()
	if err != nil {
		t.Fatalf("read enrollment winner: %v", err)
	}
	if persisted == nil {
		t.Fatal("winning credential was not persisted")
	}
	want := candidates[winner]
	if !bytes.Equal(persisted.ID, want.id) ||
		!bytes.Equal(persisted.WebAuthnP256, webauthn.CompressedP256(want.passkey)) ||
		!bytes.Equal(persisted.PhoneDirectP256, webauthn.CompressedP256(want.direct)) ||
		!bytes.Equal(persisted.PhoneRoutineBIP340, want.hot.PubKey().SerializeCompressed()) {
		t.Fatal("persisted credential fields do not all belong to the registration winner")
	}
	if want.svc.Operational == nil || want.svc.Savings == nil || want.svc.PhoneRoutineBIP340 == nil {
		t.Fatal("winning service did not publish its enrolled vault trees")
	}

	// A fresh provider process starts without any hot key configuration. It
	// must rebuild exactly the same addresses solely from durable enrollment.
	restartLedger, err := policy.OpenLedger(dbPath, nil)
	if err != nil {
		t.Fatalf("open restart ledger: %v", err)
	}
	t.Cleanup(func() { _ = restartLedger.Close() })
	restarted := &Service{
		Ledger:              restartLedger,
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerPub:    providerKey.PubKey(),
		ArkadeCosignerPub:   arkadeKey.PubKey(),
		VaultSigner:         LocalSigner{Priv: providerKey},
		ArkadeCosignerSigner: LocalSigner{
			Priv: arkadeKey,
		},
	}
	if err := restarted.LoadVaults(); err != nil {
		t.Fatalf("load persisted vaults: %v", err)
	}
	if restarted.PhoneRoutineBIP340 == nil || !bytes.Equal(restarted.PhoneRoutineBIP340.SerializeCompressed(), persisted.PhoneRoutineBIP340) {
		t.Fatal("restart did not restore the persisted browser hot public key")
	}
	if restarted.Operational.Address != want.svc.Operational.Address ||
		restarted.Savings.Address != want.svc.Savings.Address {
		t.Fatalf(
			"vault addresses changed after restart: operational %s != %s, savings %s != %s",
			restarted.Operational.Address, want.svc.Operational.Address,
			restarted.Savings.Address, want.svc.Savings.Address,
		)
	}
}

func TestProviderBoundaryConcurrentEnrollmentAndEndpointReads(t *testing.T) {
	ledger, err := policy.OpenLedger(filepath.Join(t.TempDir(), "endpoint-race.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offline, err := btcec.NewPrivateKey()
	_ = offline
	if err != nil {
		t.Fatal(err)
	}
	providerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwner, err := btcec.NewPrivateKey()
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
	svc := &Service{
		Ledger:              ledger,
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerPub:    providerKey.PubKey(),
		ArkadeCosignerPub:   arkadeKey.PubKey(),
		VaultSigner:         LocalSigner{Priv: providerKey},
		ArkadeCosignerSigner: LocalSigner{
			Priv: arkadeKey,
		},
	}

	const readers = 8
	start := make(chan struct{})
	started := make(chan struct{}, readers)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			started <- struct{}{}
			minimalAssertion := AuthorizeRequest{
				PSBT:              "",
				CredentialID:      "00",
				ClientDataJSON:    "00",
				AuthenticatorData: "00",
				Signature:         "00",
			}
			for {
				select {
				case <-stop:
					return
				default:
					// These public endpoint methods read the immutable enrolled
					// vault snapshot. Errors are expected before enrollment.
					_, _ = svc.Status(context.Background())
					_, _ = svc.Preflight("")
					_, _ = svc.Draft(DraftRequest{})
					_, _ = svc.Bind(BindRequest{})
					_, _, _ = svc.Authorize(context.Background(), minimalAssertion)
				}
			}
		}()
	}
	close(start)
	for i := 0; i < readers; i++ {
		<-started
	}
	runtime.Gosched()
	err = svc.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("endpoint-race-credential")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	})
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("register while endpoints read state: %v", err)
	}
}

func newBoundaryEnv(t *testing.T) *boundaryEnv {
	t.Helper()

	hotPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwnerPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recoveryPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	providerPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadePriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	passkeyPriv, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	directPriv, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(t.TempDir(), "provider.sqlite")
	ledger, err := policy.OpenLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ledger.Close(); err != nil {
			t.Errorf("close ledger: %v", err)
		}
	})

	counting := &boundaryCountingSigner{
		delegate: LocalSigner{Priv: providerPriv},
	}
	arkadeCounting := &boundaryCountingSigner{
		delegate: LocalSigner{Priv: arkadePriv},
	}
	service := &Service{
		Ledger:               ledger,
		ExternalOwnerWallet:  externalOwnerPriv.PubKey(),
		VaultCosignerPub:     providerPriv.PubKey(),
		ArkadeCosignerPub:    arkadePriv.PubKey(),
		VaultSigner:          counting,
		ArkadeCosignerSigner: arkadeCounting,
		SignTimeout:          250 * time.Millisecond,
	}
	credentialID := []byte("auditable-poc-credential")
	if err := service.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString(credentialID),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passkeyPriv)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(directPriv)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hotPriv.PubKey().SerializeCompressed()),
	}); err != nil {
		t.Fatalf("register fixture credential: %v", err)
	}

	return &boundaryEnv{
		service:           service,
		ledger:            ledger,
		dbPath:            dbPath,
		hotPriv:           hotPriv,
		externalOwnerPriv: externalOwnerPriv,
		recoveryPriv:      recoveryPriv,
		providerPriv:      providerPriv,
		arkadePriv:        arkadePriv,
		credentialID:      credentialID,
		passkeyPriv:       passkeyPriv,
		directPriv:        directPriv,
		countingSigner:    counting,
		arkadeSigner:      arkadeCounting,
	}
}

func (e *boundaryEnv) canonicalDraft(t *testing.T, inputValue, recipient, fee int64) *psbt.Packet {
	t.Helper()

	prevTx := wire.NewMsgTx(2)
	// This input only makes the fixture transaction have a stable, non-zero txid.
	prevTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)},
		SignatureScript:  []byte{0x01},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	prevTx.AddTxOut(&wire.TxOut{Value: inputValue, PkScript: e.service.Operational.PkScript})
	outpoint := wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	destinationKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	destination, err := txscript.PayToTaprootScript(destinationKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	built, err := vault.BuildRoutineSpend(vault.SpendParams{
		Vault:           e.service.Operational,
		PrevTx:          prevTx,
		PrevOutPoint:    outpoint,
		RecipientScript: destination,
		RecipientAmount: recipient,
		Fee:             fee,
	})
	if err != nil {
		t.Fatalf("build canonical spend: %v", err)
	}
	return built.Packet
}

func TestProviderBoundaryDraftRejectsArithmeticOverflow(t *testing.T) {
	e := newBoundaryEnv(t)

	prevTx := wire.NewMsgTx(2)
	prevTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)},
		SignatureScript:  []byte{0x01},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	prevTx.AddTxOut(&wire.TxOut{
		Value:    90_000,
		PkScript: append([]byte(nil), e.service.Operational.PkScript...),
	})
	var raw bytes.Buffer
	if err := prevTx.Serialize(&raw); err != nil {
		t.Fatal(err)
	}
	destinationKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	destination, err := txscript.PayToTaprootScript(destinationKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}

	// 90_000 - MaxInt64 - MaxInt64 wraps to a small positive change value
	// unless the builder validates the monetary domain before subtraction.
	if _, err := e.service.Draft(DraftRequest{
		PrevTxHex:       hex.EncodeToString(raw.Bytes()),
		Vout:            0,
		RecipientScript: hex.EncodeToString(destination),
		RecipientAmount: math.MaxInt64,
		Fee:             math.MaxInt64,
	}); err == nil {
		t.Fatal("draft accepted out-of-range recipient and fee whose subtraction wraps int64")
	}
}

func boundaryDraftRequest(t *testing.T, ptx *psbt.Packet, recipient, fee int64) DraftRequest {
	t.Helper()
	fields, err := txutils.GetArkPsbtFields(ptx, 0, arkade.PrevoutTxField)
	if err != nil || len(fields) != 1 {
		t.Fatalf("fixture prevout: fields=%d err=%v", len(fields), err)
	}
	var raw bytes.Buffer
	if err := fields[0].Serialize(&raw); err != nil {
		t.Fatal(err)
	}
	return DraftRequest{
		PrevTxHex:       hex.EncodeToString(raw.Bytes()),
		Vout:            ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Index,
		RecipientScript: hex.EncodeToString(ptx.UnsignedTx.TxOut[0].PkScript),
		RecipientAmount: recipient,
		Fee:             fee,
	}
}

func boundaryClonePSBT(t *testing.T, ptx *psbt.Packet) *psbt.Packet {
	t.Helper()
	encoded, err := ptx.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	clone, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
	if err != nil {
		t.Fatal(err)
	}
	return clone
}

func (e *boundaryEnv) requestFor(
	t *testing.T, draft *psbt.Packet, passkey *ecdsa.PrivateKey,
) (AuthorizeRequest, []byte) {
	t.Helper()

	ptx := boundaryClonePSBT(t, draft)
	challenge, err := vault.Challenge(ptx, e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := webauthn.Synth(
		passkey, e.credentialID, challenge, fixture.Origin, fixture.RPID, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	directSig, err := webauthn.SignDigestLowS(e.directPriv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SetPacketWitness(ptx.UnsignedTx, wire.TxWitness{directSig}); err != nil {
		t.Fatal(err)
	}

	prev := ptx.Inputs[0].WitnessUtxo
	hotSig, err := vault.SignLeaf(
		ptx.UnsignedTx, prev, e.service.Operational.Leaves.Routine.Script, e.hotPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	vault.AddPartialSig(
		ptx,
		e.hotPriv.PubKey(),
		e.service.Operational.Leaves.Routine.Hash,
		hotSig,
	)
	encoded, err := ptx.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	return AuthorizeRequest{
		PSBT:              encoded,
		CredentialID:      hex.EncodeToString(e.credentialID),
		ClientDataJSON:    hex.EncodeToString(assertion.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData),
		Signature:         hex.EncodeToString(assertion.DERSignature),
	}, challenge
}

func TestProviderBoundaryHappyPathAndExactRetry(t *testing.T) {
	e := newBoundaryEnv(t)
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)

	firstRequest, firstDigest := e.requestFor(t, draft, e.passkeyPriv)
	firstResponse, replay, err := e.service.Authorize(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("first authorization: %v", err)
	}
	if replay {
		t.Fatal("first authorization incorrectly reported as replay")
	}
	if firstResponse == "" {
		t.Fatal("first authorization returned an empty signed PSBT")
	}
	if got := e.countingSigner.callCount(); got != 1 {
		t.Fatalf("signer calls after first authorization: got %d, want 1", got)
	}

	// A retry may carry fresh WebAuthn, PhoneDirectP256 and phone-routine
	// signatures for the same challenge. The service verifies the fresh request
	// and then reuses the first integrity-protected exact PSBT; newly generated
	// signature bytes never replace the transaction presented to the signers.
	retryRequest, retryDigest := e.requestFor(t, draft, e.passkeyPriv)
	if !bytes.Equal(firstDigest, retryDigest) {
		t.Fatalf("masked digest changed across assertion retry: %x != %x", firstDigest, retryDigest)
	}
	retryResponse, replay, err := e.service.Authorize(context.Background(), retryRequest)
	if err != nil || !replay || retryResponse != firstResponse {
		t.Fatalf("fresh same-challenge retry: replay=%v response_bytes=%d err=%v", replay, len(retryResponse), err)
	}
	if got := e.countingSigner.callCount(); got != 1 {
		t.Fatalf("fresh same-challenge retry called signer: got %d calls, want 1", got)
	}
	spent, err := e.ledger.SpentInPeriod(
		context.Background(), fixture.VaultID, e.ledger.PeriodStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if spent != 20_500 {
		t.Fatalf("retry double-debited allowance: got %d, want 20500", spent)
	}
}

func TestProviderBoundaryPublicTimeoutResumesPersistedProviderStage(t *testing.T) {
	e := newBoundaryEnv(t)
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	request, _ := e.requestFor(t, draft, e.passkeyPriv)

	e.arkadeSigner.mu.Lock()
	e.arkadeSigner.err = errors.New("ambiguous public signer timeout")
	e.arkadeSigner.mu.Unlock()
	if _, _, err := e.service.Authorize(context.Background(), request); err == nil || !strings.Contains(err.Error(), "public signer timeout") {
		t.Fatalf("first public failure = %v", err)
	}
	if got := e.countingSigner.callCount(); got != 1 {
		t.Fatalf("private signer calls after public timeout = %d, want 1", got)
	}
	if got := e.arkadeSigner.callCount(); got != 1 {
		t.Fatalf("public signer calls after timeout = %d, want 1", got)
	}

	e.arkadeSigner.mu.Lock()
	e.arkadeSigner.err = nil
	e.arkadeSigner.mu.Unlock()
	signed, replay, err := e.service.Authorize(context.Background(), request)
	if err != nil || replay || signed == "" {
		t.Fatalf("exact resume after public timeout: signed=%d replay=%v err=%v", len(signed), replay, err)
	}
	if got := e.countingSigner.callCount(); got != 1 {
		t.Fatalf("public-stage resume reinvoked private signer: %d calls", got)
	}
	if got := e.arkadeSigner.callCount(); got != 2 {
		t.Fatalf("public signer calls after resume = %d, want 2", got)
	}

	replayed, replay, err := e.service.Authorize(context.Background(), request)
	if err != nil || !replay || replayed != signed {
		t.Fatalf("completed exact replay: replay=%v err=%v", replay, err)
	}
	if e.countingSigner.callCount() != 1 || e.arkadeSigner.callCount() != 2 {
		t.Fatal("completed replay reached a signer")
	}
}

func TestProviderBoundaryReplayRequiresCryptographicallyValidAssertion(t *testing.T) {
	e := newBoundaryEnv(t)
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	firstRequest, _ := e.requestFor(t, draft, e.passkeyPriv)
	if _, _, err := e.service.Authorize(context.Background(), firstRequest); err != nil {
		t.Fatalf("seed completed issuance: %v", err)
	}

	wrongPasskey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	forgedRetry, _ := e.requestFor(t, draft, wrongPasskey)
	if response, replay, err := e.service.Authorize(context.Background(), forgedRetry); err == nil {
		t.Fatalf(
			"wrong-P256 assertion retrieved committed signature: replay=%v response_bytes=%d",
			replay, len(response),
		)
	}
	if got := e.countingSigner.callCount(); got != 1 {
		t.Fatalf("invalid replay reached signer: got %d calls, want 1 total", got)
	}
}

func TestProviderBoundaryBindRejectsPRFMaterial(t *testing.T) {
	e := newBoundaryEnv(t)
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	challenge, err := vault.Challenge(draft, e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	base, err := webauthn.Synth(
		e.passkeyPriv, e.credentialID, challenge, fixture.Origin, fixture.RPID, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientData := []byte(
		`{"type":"webauthn.get","challenge":"` + webauthn.EncodeChallenge(challenge) +
			`","origin":"` + fixture.Origin + `","crossOrigin":false,"prf":{"results":{"first":"must-never-cross-provider"}}}`,
	)
	digest := webauthn.Digest(base.AuthenticatorData, clientData)
	r, s, err := ecdsa.Sign(rand.Reader, e.passkeyPriv, digest)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := draft.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.service.Bind(BindRequest{
		PSBT:              raw,
		CredentialID:      hex.EncodeToString(e.credentialID),
		ClientDataJSON:    hex.EncodeToString(clientData),
		AuthenticatorData: hex.EncodeToString(base.AuthenticatorData),
		Signature:         hex.EncodeToString(der),
	})
	if err == nil {
		t.Fatal("Bind accepted cryptographically valid clientDataJSON containing PRF material")
	}
}

func TestProviderBoundarySignerFailureRemainsReserved(t *testing.T) {
	e := newBoundaryEnv(t)
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	request, _ := e.requestFor(t, draft, e.passkeyPriv)

	e.countingSigner.mu.Lock()
	e.countingSigner.err = errors.New("injected signer failure")
	e.countingSigner.mu.Unlock()
	if _, _, err := e.service.Authorize(context.Background(), request); err == nil {
		t.Fatal("injected signer failure was accepted")
	}
	spent, err := e.ledger.SpentInPeriod(
		context.Background(), fixture.VaultID, e.ledger.PeriodStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if spent != 20_500 {
		t.Fatalf("post-submit signer failure reserved %d, want 20500", spent)
	}

	e.countingSigner.mu.Lock()
	e.countingSigner.err = nil
	e.countingSigner.mu.Unlock()
	if _, replay, err := e.service.Authorize(context.Background(), request); err != nil || replay {
		t.Fatalf("exact reserved private-stage retry failed: replay=%v err=%v", replay, err)
	}
	if got := e.countingSigner.callCount(); got != 2 {
		t.Fatalf("private signer calls: got %d, want one failed and one exact retry", got)
	}
}

func TestProviderBoundarySignerDeadlineRemainsReserved(t *testing.T) {
	e := newBoundaryEnv(t)
	e.service.SignTimeout = 20 * time.Millisecond
	e.countingSigner.mu.Lock()
	e.countingSigner.delay = time.Second
	e.countingSigner.mu.Unlock()

	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	request, _ := e.requestFor(t, draft, e.passkeyPriv)
	if _, _, err := e.service.Authorize(context.Background(), request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline result: got %v, want context deadline exceeded", err)
	}
	spent, err := e.ledger.SpentInPeriod(
		context.Background(), fixture.VaultID, e.ledger.PeriodStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if spent != 20_500 {
		t.Fatalf("ambiguous deadline reserved %d, want 20500", spent)
	}
	if _, _, err := e.service.Authorize(context.Background(), request); err == nil {
		t.Fatal("ambiguous deadline allowed same-digest re-sign")
	}
}

func TestProviderBoundaryRequiresClientFinalPacketAndHotSignature(t *testing.T) {
	e := newBoundaryEnv(t)
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	challenge, err := vault.Challenge(draft, e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := webauthn.Synth(
		e.passkeyPriv, e.credentialID, challenge, fixture.Origin, fixture.RPID, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := draft.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizeRequest{
		PSBT:              encoded,
		CredentialID:      hex.EncodeToString(e.credentialID),
		ClientDataJSON:    hex.EncodeToString(assertion.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData),
		Signature:         hex.EncodeToString(assertion.DERSignature),
	}
	if _, _, err := e.service.Authorize(context.Background(), request); err == nil {
		t.Fatal("provider accepted an empty packet witness and missing hot signature")
	}
	if got := e.countingSigner.callCount(); got != 0 {
		t.Fatalf("incomplete client request reached signer: got %d calls", got)
	}
}

func TestProviderBoundaryRejectsNonCanonicalClientSignatureSet(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *boundaryEnv, *psbt.Packet)
	}{
		{
			name: "second signature for hot key on unrelated leaf",
			mutate: func(t *testing.T, e *boundaryEnv, ptx *psbt.Packet) {
				t.Helper()
				original := ptx.Inputs[0].TaprootScriptSpendSig[0]
				wrongLeaf := append([]byte(nil), original.LeafHash...)
				wrongLeaf[0] ^= 0x01
				ptx.Inputs[0].TaprootScriptSpendSig = append(
					ptx.Inputs[0].TaprootScriptSpendSig,
					&psbt.TaprootScriptSpendSig{
						XOnlyPubKey: schnorr.SerializePubKey(e.hotPriv.PubKey()),
						LeafHash:    wrongLeaf,
						Signature:   bytes.Repeat([]byte{0x7f}, 64),
						SigHash:     txscript.SigHashDefault,
					},
				)
			},
		},
		{
			name: "unrelated extra taproot signature",
			mutate: func(t *testing.T, _ *boundaryEnv, ptx *psbt.Packet) {
				t.Helper()
				unrelated, err := btcec.NewPrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				original := ptx.Inputs[0].TaprootScriptSpendSig[0]
				ptx.Inputs[0].TaprootScriptSpendSig = append(
					ptx.Inputs[0].TaprootScriptSpendSig,
					&psbt.TaprootScriptSpendSig{
						XOnlyPubKey: schnorr.SerializePubKey(unrelated.PubKey()),
						LeafHash:    append([]byte(nil), original.LeafHash...),
						Signature:   bytes.Repeat([]byte{0x6f}, 64),
						SigHash:     txscript.SigHashDefault,
					},
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := newBoundaryEnv(t)
			draft := e.canonicalDraft(t, 90_000, 20_000, 500)
			request, _ := e.requestFor(t, draft, e.passkeyPriv)
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(request.PSBT), true)
			if err != nil {
				t.Fatal(err)
			}
			if len(ptx.Inputs[0].TaprootScriptSpendSig) != 1 {
				t.Fatalf("client-final fixture signatures: got %d, want 1", len(ptx.Inputs[0].TaprootScriptSpendSig))
			}
			test.mutate(t, e, ptx)
			request.PSBT, err = ptx.B64Encode()
			if err != nil {
				t.Fatal(err)
			}

			if _, _, err := e.service.Authorize(context.Background(), request); err == nil {
				t.Fatalf("provider accepted client PSBT with %s", test.name)
			}
			if got := e.countingSigner.callCount(); got != 0 {
				t.Fatalf("non-canonical client signature set reached signer %d times", got)
			}
			spent, err := e.ledger.SpentInPeriod(
				context.Background(), fixture.VaultID, e.ledger.PeriodStart(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if spent != 0 {
				t.Fatalf("non-canonical client signature set consumed %d sats", spent)
			}
		})
	}
}

func TestProviderBoundaryClassifyCanonicalShape(t *testing.T) {
	e := newBoundaryEnv(t)
	canonical := e.canonicalDraft(t, 90_000, 20_000, 500)
	if _, err := classify(canonical, e.service.Operational); err != nil {
		t.Fatalf("canonical packet rejected: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*psbt.Packet)
	}{
		{
			name: "non-canonical transaction version",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.Version = 1
			},
		},
		{
			name: "non-zero locktime",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.LockTime = 1
			},
		},
		{
			name: "non-canonical collaborative sequence",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 1
			},
		},
		{
			name: "extra input",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
				p.Inputs = append(p.Inputs, psbt.PInput{})
			},
		},
		{
			name: "SIGHASH_ALL",
			mutate: func(p *psbt.Packet) {
				p.Inputs[0].SighashType = txscript.SigHashAll
			},
		},
		{
			name: "missing PrevoutTxField",
			mutate: func(p *psbt.Packet) {
				p.Inputs[0].Unknowns = nil
			},
		},
		{
			name: "wrong prevout hash",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.TxIn[0].PreviousOutPoint.Hash[0] ^= 0x01
			},
		},
		{
			name: "out-of-range prevout index",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 1
			},
		},
		{
			name: "WitnessUtxo value mismatch",
			mutate: func(p *psbt.Packet) {
				p.Inputs[0].WitnessUtxo.Value++
			},
		},
		{
			name: "wrong collaborative leaf",
			mutate: func(p *psbt.Packet) {
				p.Inputs[0].TaprootLeafScript[0].Script = append([]byte(nil), e.service.Operational.Leaves.Admin.Script...)
			},
		},
		{
			name: "wrong control block",
			mutate: func(p *psbt.Packet) {
				p.Inputs[0].TaprootLeafScript[0].ControlBlock[0] ^= 0x01
			},
		},
		{
			name: "second recipient",
			mutate: func(p *psbt.Packet) {
				copyOfRecipient := *p.UnsignedTx.TxOut[0]
				copyOfRecipient.PkScript = append([]byte(nil), copyOfRecipient.PkScript...)
				p.UnsignedTx.AddTxOut(&copyOfRecipient)
			},
		},
		{
			name: "second change",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.AddTxOut(&wire.TxOut{
					Value:    fixture.DustSats,
					PkScript: append([]byte(nil), e.service.Operational.PkScript...),
				})
			},
		},
		{
			name: "dust recipient",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.TxOut[0].Value = fixture.DustSats - 1
			},
		},
		{
			name: "P2A anchor as recipient",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.TxOut[0].PkScript = append([]byte(nil), txutils.AnchorOutput().PkScript...)
			},
		},
		{
			name: "dust change",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.TxOut[1].Value = fixture.DustSats - 1
			},
		},
		{
			name: "non-zero extension value",
			mutate: func(p *psbt.Packet) {
				boundaryExtensionOutput(t, p).Value = 1
			},
		},
		{
			name: "unknown OP_RETURN",
			mutate: func(p *psbt.Packet) {
				p.UnsignedTx.AddTxOut(&wire.TxOut{PkScript: []byte{txscript.OP_RETURN, txscript.OP_0}})
			},
		},
		{
			name: "co-located extra ARK packet",
			mutate: func(p *psbt.Packet) {
				emulatorPacket, err := arkade.FindEmulatorPacket(p.UnsignedTx)
				if err != nil {
					t.Fatal(err)
				}
				ext := extension.Extension{
					emulatorPacket,
					extension.UnknownPacket{PacketType: 0x7f, Data: []byte("not allowed")},
				}
				out, err := ext.TxOut()
				if err != nil {
					t.Fatal(err)
				}
				*boundaryExtensionOutput(t, p) = *out
			},
		},
	}

	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			candidate := boundaryClonePSBT(t, canonical)
			test.mutate(candidate)
			if _, err := classify(candidate, e.service.Operational); err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
		})
	}
}

func boundaryExtensionOutput(t *testing.T, ptx *psbt.Packet) *wire.TxOut {
	t.Helper()
	for _, out := range ptx.UnsignedTx.TxOut {
		if extension.IsExtension(out.PkScript) {
			return out
		}
	}
	t.Fatal("fixture has no extension output")
	return nil
}

func TestProviderBoundaryRejectsValuesOutsideBitcoinMoneyRange(t *testing.T) {
	e := newBoundaryEnv(t)

	t.Run("input above MAX_MONEY", func(t *testing.T) {
		candidate := e.canonicalDraft(t, 90_000, 20_000, 500)
		fields, err := txutils.GetArkPsbtFields(candidate, 0, arkade.PrevoutTxField)
		if err != nil || len(fields) != 1 {
			t.Fatalf("load canonical prevout: fields=%d err=%v", len(fields), err)
		}
		prev := fields[0]
		prev.TxOut[0].Value = btcutil.MaxSatoshi + 1
		candidate.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prev.TxHash()
		candidate.Inputs[0].WitnessUtxo.Value = prev.TxOut[0].Value
		candidate.Inputs[0].Unknowns = nil
		if err := txutils.SetArkPsbtField(candidate, 0, arkade.PrevoutTxField, prev); err != nil {
			t.Fatalf("replace canonical prevout: %v", err)
		}
		if _, err := classify(candidate, e.service.Operational); err == nil {
			t.Fatal("input above Bitcoin MAX_MONEY was accepted")
		}
	})

	t.Run("output sum overflows int64", func(t *testing.T) {
		candidate := e.canonicalDraft(t, 90_000, 20_000, 500)
		candidate.UnsignedTx.TxOut[0].Value = math.MaxInt64
		candidate.UnsignedTx.TxOut[1].Value = math.MaxInt64
		if _, err := classify(candidate, e.service.Operational); err == nil {
			t.Fatal("overflowing output sum was accepted")
		}
	})
}

func TestEstimatedVBytesMatchesSerializedFinalWitness(t *testing.T) {
	e := newBoundaryEnv(t)
	base := e.canonicalDraft(t, 90_000, 20_000, 500)
	leaf := e.service.Operational.Leaves.Routine
	if got := estimatedWitnessBytes(e.service.Operational); got != int(vault.RoutineWitnessBytes) {
		t.Fatalf("collaborative witness size = %d, Arkade policy commits to %d", got, vault.RoutineWitnessBytes)
	}

	// Vary stripped-size residue modulo four. A missing witness-stack-count byte
	// can otherwise be hidden by vbyte rounding for one particular fixture.
	for scriptLen := 1; scriptLen <= 4; scriptLen++ {
		t.Run(fmt.Sprintf("recipient_script_%d_bytes", scriptLen), func(t *testing.T) {
			candidate := boundaryClonePSBT(t, base)
			candidate.UnsignedTx.TxOut[0].PkScript = bytes.Repeat([]byte{txscript.OP_TRUE}, scriptLen)
			finalTx := candidate.UnsignedTx.Copy()
			finalTx.TxIn[0].Witness = wire.TxWitness{
				bytes.Repeat([]byte{0x11}, 64),
				bytes.Repeat([]byte{0x22}, 64),
				bytes.Repeat([]byte{0x33}, 64),
				append([]byte(nil), leaf.Script...),
				append([]byte(nil), leaf.ControlBlock...),
			}
			stripped := finalTx.SerializeSizeStripped()
			full := finalTx.SerializeSize()
			weight := stripped*3 + full
			if got := estimatedFullSize(candidate.UnsignedTx, e.service.Operational); got != full {
				t.Fatalf("estimated full size: got %d, want serialized %d (stripped=%d)", got, full, stripped)
			}
			if got := estimatedWeight(candidate.UnsignedTx, e.service.Operational); got != weight {
				t.Fatalf("estimated weight: got %d, want serialized %d", got, weight)
			}
			wantVBytes := int64((weight + 3) / 4)
			if got := estimatedVBytes(candidate.UnsignedTx, e.service.Operational); got != wantVBytes {
				t.Fatalf("estimated vbytes: got %d, want exact serialized %d", got, wantVBytes)
			}
		})
	}
}

func boundarySetFee(t *testing.T, ptx *psbt.Packet, op *vault.Built, target int64) {
	t.Helper()
	var change *wire.TxOut
	var total int64
	for _, out := range ptx.UnsignedTx.TxOut {
		total += out.Value
		if bytes.Equal(out.PkScript, op.PkScript) {
			change = out
		}
	}
	if change == nil {
		t.Fatal("fixture has no operational change output")
	}
	current := ptx.Inputs[0].WitnessUtxo.Value - total
	change.Value -= target - current
	if change.Value < fixture.DustSats {
		t.Fatalf("test fee %d would consume change", target)
	}
}

func TestProviderBoundaryExactFeerateLimit(t *testing.T) {
	e := newBoundaryEnv(t)
	base := e.canonicalDraft(t, 1_000_000, 20_000, 0)
	vbytes := estimatedVBytes(base.UnsignedTx, e.service.Operational)
	limit := fixture.FeerateCeilingSatPerV * vbytes

	atLimit := boundaryClonePSBT(t, base)
	boundarySetFee(t, atLimit, e.service.Operational, limit)
	classified, err := classify(atLimit, e.service.Operational)
	if err != nil {
		t.Fatalf("fee exactly at %d sat/vB ceiling rejected: %v", fixture.FeerateCeilingSatPerV, err)
	}
	if classified.Fee != limit {
		t.Fatalf("classified boundary fee: got %d, want %d", classified.Fee, limit)
	}
	if err := enforceStaticPolicy(classified, configuredAuthorizationPolicy()); err != nil {
		t.Fatalf("exact %d sat/vB ceiling rejected: %v", fixture.FeerateCeilingSatPerV, err)
	}

	oneSatOver := boundaryClonePSBT(t, base)
	boundarySetFee(t, oneSatOver, e.service.Operational, limit+1)
	over, err := classify(oneSatOver, e.service.Operational)
	if err != nil {
		t.Fatalf("structural classify rejected fee one sat over ceiling: %v", err)
	}
	if err := enforceStaticPolicy(over, configuredAuthorizationPolicy()); err == nil {
		t.Fatalf("fee one sat above exact %d sat/vB boundary was accepted", fixture.FeerateCeilingSatPerV)
	}
}

func TestProviderBoundaryFeeCeilingsRejectRateAndAbsoluteLimits(t *testing.T) {
	e := newBoundaryEnv(t)
	base := e.canonicalDraft(t, 1_000_000, 20_000, 0)
	smallVBytes := estimatedVBytes(base.UnsignedTx, e.service.Operational)
	rateOnlyFee := fixture.FeerateCeilingSatPerV*smallVBytes + 1
	if rateOnlyFee > fixture.AbsoluteFeeCeiling {
		t.Fatalf(
			"feerate policy is unreachable before absolute ceiling for the minimal canonical spend: first rate violation %d sats, absolute ceiling %d sats",
			rateOnlyFee, fixture.AbsoluteFeeCeiling,
		)
	}
	rateOnly := boundaryClonePSBT(t, base)
	boundarySetFee(t, rateOnly, e.service.Operational, rateOnlyFee)
	rateCl, err := classify(rateOnly, e.service.Operational)
	if err != nil {
		t.Fatalf("structural classify rejected rate-only fee: %v", err)
	}
	if err := enforceStaticPolicy(rateCl, configuredAuthorizationPolicy()); err == nil {
		t.Fatalf("rate-only fee %d was accepted", rateOnlyFee)
	}

	// The native-Segwit recipient constraint deliberately rules out inflating
	// stripped size with an arbitrary spendable script. Bind a real PhoneDirectP256
	// signature and prove that the absolute cap is still checked before any
	// signer call; this candidate may also exceed the feerate cap.
	absOnly := boundaryClonePSBT(t, base)
	absOnlyFee := fixture.AbsoluteFeeCeiling + 1
	boundarySetFee(t, absOnly, e.service.Operational, absOnlyFee)
	challenge, err := vault.Challenge(absOnly, e.service.Operational)
	if err != nil {
		t.Fatalf("challenge for absolute-fee fixture: %v", err)
	}
	directSig, err := webauthn.SignDigestLowS(e.directPriv, challenge)
	if err != nil {
		t.Fatalf("sign PhoneDirectP256 challenge: %v", err)
	}
	if err := vault.SetPacketWitness(absOnly.UnsignedTx, wire.TxWitness{directSig}); err != nil {
		t.Fatalf("set PhoneDirectP256 packet witness: %v", err)
	}
	pkt, err := arkade.FindEmulatorPacket(absOnly.UnsignedTx)
	if err != nil || len(pkt) != 1 || len(pkt[0].Witness) != 1 || len(pkt[0].Witness[0]) != 64 {
		t.Fatalf("absolute-fee fixture packet is not one PhoneDirectP256 signature: %#v err=%v", pkt, err)
	}
	absCl, err := classify(absOnly, e.service.Operational)
	if err != nil {
		t.Fatalf("absolute-fee fixture was incorrectly rejected by structural classify: %v", err)
	}
	if err := enforceStaticPolicy(absCl, configuredAuthorizationPolicy()); err == nil {
		t.Fatalf("absolute fee %d was accepted", absOnlyFee)
	}
	raw, err := absOnly.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.service.Authorize(context.Background(), AuthorizeRequest{PSBT: raw}); err == nil {
		t.Fatalf("absolute fee %d was accepted", absOnlyFee)
	} else if !strings.Contains(err.Error(), "fee exceeds ceiling") {
		t.Fatalf("Authorize rejected absolute fee for the wrong reason: %v", err)
	}
	if got := e.countingSigner.callCount(); got != 0 {
		t.Fatalf("fee policy rejection reached signer: got %d calls", got)
	}
}

func TestProviderBoundaryPrevoutFieldRejectsDuplicate(t *testing.T) {
	e := newBoundaryEnv(t)
	ptx := e.canonicalDraft(t, 90_000, 20_000, 500)
	fields, err := txutils.GetArkPsbtFields(ptx, 0, arkade.PrevoutTxField)
	if err != nil || len(fields) != 1 {
		t.Fatalf("fixture prevout fields: len=%d err=%v", len(fields), err)
	}
	if err := txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, fields[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := classify(ptx, e.service.Operational); err == nil {
		t.Fatal("duplicate PrevoutTxField was accepted")
	}
}

func TestProviderBoundaryPolicyRejectsBeforeSigner(t *testing.T) {
	tests := []struct {
		name      string
		input     int64
		recipient int64
		fee       int64
		want      string
	}{
		{
			name:      "recipient above transaction cap",
			input:     100_000,
			recipient: fixture.TxRecipientCapSats + 1,
			fee:       500,
			want:      "recipient exceeds transaction cap",
		},
		{
			name:      "fee above absolute ceiling",
			input:     100_000,
			recipient: 20_000,
			fee:       fixture.AbsoluteFeeCeiling + 1,
			want:      "fee exceeds ceiling",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := newBoundaryEnv(t)
			draft := e.canonicalDraft(t, test.input, test.recipient, test.fee)
			raw, err := draft.B64Encode()
			if err != nil {
				t.Fatal(err)
			}
			mustReject := func(label string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s accepted %s", label, test.name)
				}
				if !strings.Contains(err.Error(), test.want) {
					t.Fatalf("%s: got %v, want %q", label, err, test.want)
				}
			}
			draftReq := boundaryDraftRequest(t, draft, test.recipient, test.fee)
			_, err = e.service.Draft(draftReq)
			mustReject("Draft", err)
			_, err = e.service.Preflight(raw)
			mustReject("Preflight", err)
			_, err = e.service.Bind(BindRequest{PSBT: raw})
			mustReject("Bind", err)
			_, _, err = e.service.Authorize(context.Background(), AuthorizeRequest{PSBT: raw})
			mustReject("Authorize", err)
			if got := e.countingSigner.callCount(); got != 0 {
				t.Fatalf("rejected policy reached signer: got %d calls", got)
			}
		})
	}
}

func TestProviderBoundaryPreflightDoesNotReserveOrSign(t *testing.T) {
	e := newBoundaryEnv(t)
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	encoded, err := draft.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	response, err := e.service.Preflight(encoded)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if response.Challenge == "" {
		t.Fatal("preflight returned empty challenge")
	}
	if got := e.countingSigner.callCount(); got != 0 {
		t.Fatalf("preflight called signer %d times", got)
	}
	spent, err := e.ledger.SpentInPeriod(
		context.Background(), fixture.VaultID, e.ledger.PeriodStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if spent != 0 {
		t.Fatalf("preflight reserved allowance: got %d", spent)
	}
}

func TestProviderBoundarySignerSeesFinalClientTransaction(t *testing.T) {
	e := newBoundaryEnv(t)
	e.countingSigner.inspect = func(ptx *psbt.Packet) error {
		packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
		if err != nil {
			return err
		}
		if len(packet) != 1 || len(packet[0].Witness) != 1 || len(packet[0].Witness[0]) != 64 {
			return fmt.Errorf("signer did not receive one-item direct-auth witness")
		}
		if len(ptx.Inputs[0].TaprootScriptSpendSig) != 1 {
			return fmt.Errorf("signer did not receive exactly one hot signature")
		}
		hotSig := ptx.Inputs[0].TaprootScriptSpendSig[0]
		if !bytes.Equal(hotSig.XOnlyPubKey, schnorr.SerializePubKey(e.hotPriv.PubKey())) {
			return fmt.Errorf("signer received signature from wrong hot key")
		}
		return nil
	}
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	request, _ := e.requestFor(t, draft, e.passkeyPriv)
	if _, _, err := e.service.Authorize(context.Background(), request); err != nil {
		t.Fatalf("authorize final client transaction: %v", err)
	}
}

func TestRemoteSignerRejectsUnsignedTransactionSubstitution(t *testing.T) {
	e := newBoundaryEnv(t)
	original := e.canonicalDraft(t, 90_000, 20_000, 500)
	transport := &boundaryTransport{
		submit: func(_ context.Context, encoded string) (string, error) {
			candidate, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
			if err != nil {
				return "", err
			}
			candidate.UnsignedTx.TxOut[0].Value++
			candidate.UnsignedTx.TxOut[1].Value--
			return candidate.B64Encode()
		},
	}
	expected := schnorr.SerializePubKey(e.service.Operational.TweakedVaultCosigner)
	signer := &RemoteSigner{Client: transport}
	if signed, err := signer.SignExpected(context.Background(), original, expected); err == nil {
		t.Fatalf("remote signer accepted substituted unsigned transaction: %v", signed.UnsignedTx.TxHash())
	}
}

func (e *boundaryEnv) clientFinalPacket(t *testing.T) *psbt.Packet {
	t.Helper()
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	req, _ := e.requestFor(t, draft, e.passkeyPriv)
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(req.PSBT), true)
	if err != nil {
		t.Fatalf("decode client-final fixture: %v", err)
	}
	return ptx
}

func boundaryProviderSig(t *testing.T, ptx *psbt.Packet, expected []byte) *psbt.TaprootScriptSpendSig {
	t.Helper()
	for _, sig := range ptx.Inputs[0].TaprootScriptSpendSig {
		if bytes.Equal(sig.XOnlyPubKey, expected) {
			return sig
		}
	}
	t.Fatal("fixture has no expected provider signature")
	return nil
}

func TestRemoteSignerRequiresExactProviderSignatureDelta(t *testing.T) {
	e := newBoundaryEnv(t)
	expected := schnorr.SerializePubKey(e.service.Operational.TweakedVaultCosigner)

	t.Run("exactly one valid expected signature", func(t *testing.T) {
		original := e.clientFinalPacket(t)
		transport := &boundaryTransport{submit: func(ctx context.Context, encoded string) (string, error) {
			candidate, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
			if err != nil {
				return "", err
			}
			signed, err := (LocalSigner{Priv: e.providerPriv}).Sign(ctx, candidate)
			if err != nil {
				return "", err
			}
			return signed.B64Encode()
		}}
		signer := &RemoteSigner{Client: transport}
		if signer.SuccessfulCalls() != 0 {
			t.Fatal("new RemoteSigner success count is not zero")
		}
		signed, err := signer.SignExpected(context.Background(), original, expected)
		if err != nil {
			t.Fatalf("valid remote signer response: %v", err)
		}
		if len(signed.Inputs[0].TaprootScriptSpendSig) != len(original.Inputs[0].TaprootScriptSpendSig)+1 {
			t.Fatalf("signature delta: got %d entries, want %d", len(signed.Inputs[0].TaprootScriptSpendSig), len(original.Inputs[0].TaprootScriptSpendSig)+1)
		}
		_ = boundaryProviderSig(t, signed, expected)
		if signer.SuccessfulCalls() != 1 {
			t.Fatalf("successful remote calls = %d, want 1", signer.SuccessfulCalls())
		}
	})

	t.Run("no provider signature", func(t *testing.T) {
		original := e.clientFinalPacket(t)
		transport := &boundaryTransport{submit: func(_ context.Context, encoded string) (string, error) {
			return encoded, nil
		}}
		signer := &RemoteSigner{Client: transport}
		if _, err := signer.SignExpected(context.Background(), original, expected); err == nil {
			t.Fatal("unchanged response without provider signature was accepted")
		}
		if signer.SuccessfulCalls() != 0 {
			t.Fatal("invalid response incremented RemoteSigner success count")
		}
	})

	mutations := []struct {
		name   string
		mutate func(*psbt.Packet)
	}{
		{
			name: "wrong x-only key",
			mutate: func(signed *psbt.Packet) {
				sig := boundaryProviderSig(t, signed, expected)
				wrong, err := btcec.NewPrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				sig.XOnlyPubKey = schnorr.SerializePubKey(wrong.PubKey())
			},
		},
		{
			name: "wrong provider leaf hash",
			mutate: func(signed *psbt.Packet) {
				sig := boundaryProviderSig(t, signed, expected)
				sig.LeafHash = append([]byte(nil), sig.LeafHash...)
				sig.LeafHash[0] ^= 0x01
			},
		},
		{
			name: "mutated tapleaf version",
			mutate: func(signed *psbt.Packet) {
				signed.Inputs[0].TaprootLeafScript[0].LeafVersion = txscript.BaseLeafVersion + 2
			},
		},
		{
			name: "wrong provider sighash",
			mutate: func(signed *psbt.Packet) {
				boundaryProviderSig(t, signed, expected).SigHash = txscript.SigHashAll
			},
		},
		{
			name: "invalid 64-byte provider signature",
			mutate: func(signed *psbt.Packet) {
				boundaryProviderSig(t, signed, expected).Signature = bytes.Repeat([]byte{0xff}, 64)
			},
		},
		{
			name: "extra unrelated signature",
			mutate: func(signed *psbt.Packet) {
				providerSig := boundaryProviderSig(t, signed, expected)
				wrong, err := btcec.NewPrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				signed.Inputs[0].TaprootScriptSpendSig = append(
					signed.Inputs[0].TaprootScriptSpendSig,
					&psbt.TaprootScriptSpendSig{
						XOnlyPubKey: schnorr.SerializePubKey(wrong.PubKey()),
						LeafHash:    append([]byte(nil), providerSig.LeafHash...),
						Signature:   append([]byte(nil), providerSig.Signature...),
						SigHash:     providerSig.SigHash,
					},
				)
			},
		},
		{
			name: "unknown input field mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Inputs[0].Unknowns = append(signed.Inputs[0].Unknowns, &psbt.Unknown{
					Key:   []byte{0xfc, 0x04, 't', 'e', 's', 't', 0x01},
					Value: []byte("unexpected emulator metadata"),
				})
			},
		},
		{
			name: "unknown global field mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Unknowns = append(signed.Unknowns, &psbt.Unknown{
					Key:   []byte{0xfc, 0x06, 'g', 'l', 'o', 'b', 'a', 'l', 0x01},
					Value: []byte("unexpected global emulator metadata"),
				})
			},
		},
		{
			name: "unknown output field mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Outputs[0].Unknowns = append(signed.Outputs[0].Unknowns, &psbt.Unknown{
					Key:   []byte{0xfc, 0x06, 'o', 'u', 't', 'p', 'u', 't', 0x01},
					Value: []byte("unexpected output emulator metadata"),
				})
			},
		},
		{
			name: "unexpected standard input field mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Inputs[0].RedeemScript = []byte{txscript.OP_TRUE}
			},
		},
		{
			name: "unexpected non-witness prevout mutation",
			mutate: func(signed *psbt.Packet) {
				fields, err := txutils.GetArkPsbtFields(signed, 0, arkade.PrevoutTxField)
				if err != nil || len(fields) != 1 {
					t.Fatalf("load prevout for response mutation: fields=%d err=%v", len(fields), err)
				}
				signed.Inputs[0].NonWitnessUtxo = fields[0].Copy()
			},
		},
		{
			name: "unexpected input BIP32 derivation mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Inputs[0].Bip32Derivation = append(
					signed.Inputs[0].Bip32Derivation,
					&psbt.Bip32Derivation{
						PubKey:               e.hotPriv.PubKey().SerializeCompressed(),
						MasterKeyFingerprint: 0x01020304,
						Bip32Path:            []uint32{0x80000000},
					},
				)
			},
		},
		{
			name: "unexpected input taproot derivation mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Inputs[0].TaprootBip32Derivation = append(
					signed.Inputs[0].TaprootBip32Derivation,
					&psbt.TaprootBip32Derivation{
						XOnlyPubKey:          schnorr.SerializePubKey(e.hotPriv.PubKey()),
						MasterKeyFingerprint: 0x01020304,
						Bip32Path:            []uint32{0x80000000},
					},
				)
			},
		},
		{
			name: "unexpected standard output field mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Outputs[0].RedeemScript = []byte{txscript.OP_TRUE}
			},
		},
		{
			name: "unexpected output BIP32 derivation mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Outputs[0].Bip32Derivation = append(
					signed.Outputs[0].Bip32Derivation,
					&psbt.Bip32Derivation{
						PubKey:               e.hotPriv.PubKey().SerializeCompressed(),
						MasterKeyFingerprint: 0x01020304,
						Bip32Path:            []uint32{1},
					},
				)
			},
		},
		{
			name: "unexpected output taproot internal key mutation",
			mutate: func(signed *psbt.Packet) {
				signed.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(e.hotPriv.PubKey())
			},
		},
		{
			name: "unexpected output tap tree mutation",
			mutate: func(signed *psbt.Packet) {
				// One depth-0 BaseLeafVersion OP_TRUE leaf in BIP371 tuple form.
				signed.Outputs[0].TaprootTapTree = []byte{0x00, byte(txscript.BaseLeafVersion), 0x01, txscript.OP_TRUE}
			},
		},
		{
			name: "unexpected finalized witness field",
			mutate: func(signed *psbt.Packet) {
				signed.Inputs[0].FinalScriptWitness = []byte{0x01, 0x00}
			},
		},
		{
			name: "unexpected taproot internal key field",
			mutate: func(signed *psbt.Packet) {
				signed.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(e.hotPriv.PubKey())
			},
		},
	}

	reject := map[string]bool{
		"wrong x-only key":                   true,
		"wrong provider leaf hash":           true,
		"wrong provider sighash":             true,
		"invalid 64-byte provider signature": true,
		"unexpected finalized witness field": true,
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			original := e.clientFinalPacket(t)
			transport := &boundaryTransport{submit: func(ctx context.Context, encoded string) (string, error) {
				candidate, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
				if err != nil {
					return "", err
				}
				signed, err := (LocalSigner{Priv: e.providerPriv}).Sign(ctx, candidate)
				if err != nil {
					return "", err
				}
				test.mutate(signed)
				return signed.B64Encode()
			}}
			signer := &RemoteSigner{Client: transport}
			got, err := signer.SignExpected(context.Background(), original, expected)
			if reject[test.name] {
				if err == nil {
					t.Fatalf("remote signer accepted response with %s", test.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid provider signature with %s should reconstruct: %v", test.name, err)
			}
			if leakedEmulatorMutation(original, got, test.name) {
				t.Fatalf("reconstructed PSBT leaked emulator %s", test.name)
			}
			if len(got.Inputs[0].TaprootScriptSpendSig) != len(original.Inputs[0].TaprootScriptSpendSig)+1 {
				t.Fatalf("reconstructed signature count = %d", len(got.Inputs[0].TaprootScriptSpendSig))
			}
			_ = boundaryProviderSig(t, got, expected)
		})
	}
}

func leakedEmulatorMutation(original, got *psbt.Packet, name string) bool {
	switch name {
	case "unknown input field mutation":
		return len(got.Inputs[0].Unknowns) != len(original.Inputs[0].Unknowns)
	case "unknown global field mutation":
		return len(got.Unknowns) != len(original.Unknowns)
	case "unknown output field mutation":
		return len(got.Outputs[0].Unknowns) != len(original.Outputs[0].Unknowns)
	case "unexpected standard input field mutation":
		return len(got.Inputs[0].RedeemScript) != len(original.Inputs[0].RedeemScript)
	case "unexpected non-witness prevout mutation":
		return got.Inputs[0].NonWitnessUtxo != nil
	case "unexpected input BIP32 derivation mutation":
		return len(got.Inputs[0].Bip32Derivation) != len(original.Inputs[0].Bip32Derivation)
	case "unexpected input taproot derivation mutation":
		return len(got.Inputs[0].TaprootBip32Derivation) != len(original.Inputs[0].TaprootBip32Derivation)
	case "unexpected standard output field mutation":
		return len(got.Outputs[0].RedeemScript) != len(original.Outputs[0].RedeemScript)
	case "unexpected output BIP32 derivation mutation":
		return len(got.Outputs[0].Bip32Derivation) != len(original.Outputs[0].Bip32Derivation)
	case "unexpected output taproot internal key mutation":
		return len(got.Outputs[0].TaprootInternalKey) != len(original.Outputs[0].TaprootInternalKey)
	case "unexpected output tap tree mutation":
		return len(got.Outputs[0].TaprootTapTree) != len(original.Outputs[0].TaprootTapTree)
	case "unexpected finalized witness field":
		return len(got.Inputs[0].FinalScriptWitness) != len(original.Inputs[0].FinalScriptWitness)
	case "unexpected taproot internal key field":
		return !bytes.Equal(got.Inputs[0].TaprootInternalKey, original.Inputs[0].TaprootInternalKey)
	case "mutated tapleaf version":
		return got.Inputs[0].TaprootLeafScript[0].LeafVersion != original.Inputs[0].TaprootLeafScript[0].LeafVersion
	case "extra unrelated signature":
		return len(got.Inputs[0].TaprootScriptSpendSig) != len(original.Inputs[0].TaprootScriptSpendSig)+1
	default:
		return false
	}
}

func TestRemoteSignerMalformedResponseIsAnErrorNotAPanic(t *testing.T) {
	e := newBoundaryEnv(t)
	original := e.clientFinalPacket(t)
	malformed := &psbt.Packet{
		UnsignedTx: original.UnsignedTx.Copy(),
		Inputs:     nil,
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("malformed emulator response panicked: %v", recovered)
		}
	}()
	if _, err := extractVerifiedSignerSig(
		original,
		malformed,
		schnorr.SerializePubKey(e.service.Operational.TweakedVaultCosigner),
	); err == nil {
		t.Fatal("malformed emulator response was accepted")
	}
}
