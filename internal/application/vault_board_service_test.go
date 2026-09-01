package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/ports"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
)

type vaultBoardTestChain struct {
	state       vaultBoardConfirmedOutpoint
	err         error
	errAt       int
	calls       int
	sawDeadline bool
}

func (c *vaultBoardTestChain) confirmedOutpoint(context.Context, string, uint32) (vaultBoardConfirmedOutpoint, error) {
	c.calls++
	if c.errAt == c.calls {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("chain query interrupted")
	}
	out := c.state
	out.Txid = bytes.Clone(c.state.Txid)
	out.PkScript = bytes.Clone(c.state.PkScript)
	return out, c.err
}

func (c *vaultBoardTestChain) revalidateOutpoint(ctx context.Context, prior vaultBoardConfirmedOutpoint) (vaultBoardConfirmedOutpoint, error) {
	_, c.sawDeadline = ctx.Deadline()
	return c.confirmedOutpoint(ctx, hex.EncodeToString(prior.Txid), prior.Vout)
}

type vaultBoardTestOperator struct {
	registerErr        error
	deleteErr          error
	finalErr           error
	registers          int
	deletes            int
	finals             int
	beforeDeleteReturn func()
}

func (o *vaultBoardTestOperator) registerIntent(context.Context, string, string) (string, error) {
	o.registers++
	if o.registerErr != nil {
		return "", o.registerErr
	}
	return fmt.Sprintf("intent-%d", o.registers), nil
}

func (o *vaultBoardTestOperator) deleteIntent(context.Context, string, string) error {
	o.deletes++
	if o.beforeDeleteReturn != nil {
		o.beforeDeleteReturn()
	}
	return o.deleteErr
}

func (o *vaultBoardTestOperator) submitCommitment(context.Context, string) error {
	o.finals++
	return o.finalErr
}

type vaultBoardTestResolver struct {
	stubArkResolver
	exact *ports.ResolvedVtxo
	err   error
}

func (r *vaultBoardTestResolver) exactVtxo(context.Context, string, uint32, []byte) (*ports.ResolvedVtxo, error) {
	if r.exact == nil {
		return nil, r.err
	}
	out := *r.exact
	out.Script = bytes.Clone(r.exact.Script)
	out.CommitmentTxids = append([]string(nil), r.exact.CommitmentTxids...)
	return &out, r.err
}

type vaultBoardServiceFixture struct {
	svc      *Service
	ledger   *policy.Ledger
	chain    *vaultBoardTestChain
	operator *vaultBoardTestOperator
	resolver *vaultBoardTestResolver
	proof    vaultBoardProofFixture
	vaultID  string
	receiver string
	now      time.Time
	clock    *time.Time
	dbPath   string
	master   *btcec.PrivateKey
	emulator *btcec.PrivateKey
}

func newVaultBoardServiceFixture(t *testing.T) vaultBoardServiceFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	clock := &now
	dbPath := filepath.Join(t.TempDir(), "board-service.sqlite")
	ledger, err := policy.OpenLedger(dbPath, func() time.Time { return *clock })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	svc := enrollService(t, ledger)
	master, _ := btcec.NewPrivateKey()
	emulator, _ := btcec.NewPrivateKey()
	operatorKey, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	keys, err := NewFileBackedKeyCapabilities(master, LocalSigner{Priv: emulator})
	if err != nil {
		t.Fatal(err)
	}
	svc.keys = keys
	svc.VaultCosignerPub = master.PubKey()
	svc.VaultBoardStore = ledger
	svc.EnrollmentNow = func() time.Time { return *clock }
	resolver := &vaultBoardTestResolver{stubArkResolver: stubArkResolver{
		feePolicy: ports.IntentFeePolicy{OnchainInput: "1000.0"},
		signer:    operatorKey.PubKey().SerializeCompressed(),
	}}
	svc.ArkResolver = resolver
	svc.SessionNow = func() time.Time { return *clock }

	raw := bytes.Repeat([]byte{0x6d}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, _ := HashEnrollmentToken(token)
	if err := ledger.PutInvite(hash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartEnrollment(token, defaultEnrollStartRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	base := attestedFinish(t, svc, start, pass, []byte("cred-board-service"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	request := base
	request.VtxoBoardingProgram = program.VaultBoardV1
	request.VaultBoardingBIP340Pub = hex.EncodeToString(schnorr.SerializePubKey(boarding.PubKey()))
	proposed, err := svc.ProposeEnrollment(token, request)
	if err != nil {
		t.Fatal(err)
	}
	request.DescriptorHash = proposed.DescriptorHash
	status, err := svc.FinishEnrollment(context.Background(), token, request)
	if err != nil {
		t.Fatal(err)
	}
	snap := svc.snapshot(start.VaultID)
	boardTree, err := svc.buildVtxoBoardTree(start.VaultID, snap, snap.Board.BoardingPub)
	if err != nil {
		t.Fatal(err)
	}
	receiverTree, err := svc.buildVtxoPolicyTree(start.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	txid := bytes.Repeat([]byte{0x42}, 32)
	chain := &vaultBoardTestChain{state: vaultBoardConfirmedOutpoint{
		Txid: txid, Vout: 7, ValueSats: 50_000, PkScript: bytes.Clone(boardTree.PkScript),
		SequenceAnchorMTP: now.Unix() - 1_000, TipMTP: now.Unix(),
	}}
	op := &vaultBoardTestOperator{}
	svc.vaultBoardRuntime = &vaultBoardRuntime{
		chain: chain, operatorDial: func(context.Context) (vaultBoardOperator, error) { return op, nil },
		batchExpiry: 604_672,
	}
	treeSession, _ := btcec.NewPrivateKey()
	proof := vaultBoardProofFixture{
		tree: boardTree, boarding: boarding,
		operation: policy.VaultBoardOperation{
			VaultID: start.VaultID, Txid: txid, Vout: 7, ValueSats: 50_000,
			BoardingScript: bytes.Clone(boardTree.PkScript), ReceiverScript: bytes.Clone(receiverTree.PkScript),
			SequenceAnchorMTP: chain.state.SequenceAnchorMTP,
		},
		expireAt:   now.Add(vaultBoardRegisterTTL).Unix(),
		receiver:   &wire.TxOut{Value: 49_000, PkScript: bytes.Clone(receiverTree.PkScript)},
		treePubHex: hex.EncodeToString(treeSession.PubKey().SerializeCompressed()),
	}
	if status.SpendingArkAddress != receiverTree.ArkAddress {
		t.Fatalf("Spending address = %q, want %q", status.SpendingArkAddress, receiverTree.ArkAddress)
	}
	return vaultBoardServiceFixture{
		svc: svc, ledger: ledger, chain: chain, operator: op, resolver: resolver,
		proof: proof, vaultID: start.VaultID, receiver: receiverTree.ArkAddress, now: now, clock: clock,
		dbPath: dbPath, master: master, emulator: emulator,
	}
}

func (f vaultBoardServiceFixture) prepare(t *testing.T) vaultBoardPrepareResult {
	t.Helper()
	result, err := f.svc.prepareVaultBoard(context.Background(), vaultBoardPrepareRequest{
		VaultID: f.vaultID,
		Inputs:  []vaultBoardPrepareInput{{Txid: hex.EncodeToString(f.proof.operation.Txid), Vout: f.proof.operation.Vout}},
		Recipients: []vaultBoardPrepareRecipient{{
			Address: f.receiver, AmountSats: uint64(f.proof.receiver.Value),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f vaultBoardServiceFixture) register(t *testing.T, prepared vaultBoardPrepareResult) vaultBoardRegisterResponse {
	t.Helper()
	f.proof.expireAt = prepared.RegisterExpireAt
	message := f.proof.registerMessage(t)
	result, err := f.svc.registerVaultBoard(context.Background(), vaultBoardRegisterPhaseRequest{
		Handle: prepared.Handle, PSBT: f.proof.proof(t, message, []*wire.TxOut{f.proof.receiver}),
		Message: message, InputIndexes: []int{0, 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f vaultBoardServiceFixture) releaseHandle(t *testing.T) vaultBoardPrepareResult {
	t.Helper()
	operationID, err := policy.ComputeVaultBoardOperationID(f.vaultID, f.proof.operation.Txid, f.proof.operation.Vout)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.ledger.GetCurrentVaultBoardAttempt(context.Background(), operationID)
	if err != nil || snapshot == nil {
		t.Fatalf("release snapshot = %+v, %v", snapshot, err)
	}
	expireAt := f.svc.vtxoNow().Add(vaultBoardDeleteTTL).Unix()
	handle, err := f.svc.sealVaultBoardHandle(vaultBoardHandleClaims{
		Version: 1, Kind: string(vaultBoardReleaseRequired), VaultID: f.vaultID,
		OperationID: operationID, Txid: hex.EncodeToString(f.proof.operation.Txid), Vout: f.proof.operation.Vout,
		Attempt: snapshot.Register.Attempt, DeleteExpireAt: expireAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return vaultBoardPrepareResult{State: vaultBoardReleaseRequired, Handle: handle, DeleteExpireAt: expireAt}
}

func TestVaultBoardServiceSupersedesStaleRegisterThroughDefiniteRejectionAndFinalFence(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	first := fixture.prepare(t)
	if first.State != vaultBoardReady || first.Handle == "" {
		t.Fatalf("first prepare = %+v", first)
	}
	registered := fixture.register(t, first)
	if registered.Status != vaultBoardRegistered || registered.IntentID == "" || fixture.operator.registers != 1 {
		t.Fatalf("first register = %+v, calls=%d", registered, fixture.operator.registers)
	}
	blocked := fixture.prepare(t)
	if blocked.State != vaultBoardBlocked || blocked.Handle != "" || blocked.DeleteExpireAt != 0 || fixture.operator.deletes != 0 {
		t.Fatalf("active register = %+v, delete calls=%d", blocked, fixture.operator.deletes)
	}

	*fixture.clock = time.Unix(first.RegisterExpireAt, 0).UTC().Add(30 * time.Second)
	rejectedAttempt := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardHandle(rejectedAttempt.Handle, string(vaultBoardReady))
	if err != nil || claims.Attempt != 1 {
		t.Fatalf("stale supersession = %+v, claims=%+v, %v", rejectedAttempt, claims, err)
	}
	rejectedSession, _ := btcec.NewPrivateKey()
	fixture.proof.treePubHex = hex.EncodeToString(rejectedSession.PubKey().SerializeCompressed())
	// Stock VTXO_BANNED is InvalidArgument and reaches this adapter as HTTP 400,
	// which is a definite pre-acceptance rejection rather than an ambiguous 500.
	fixture.operator.registerErr = vaultBoardOperatorRejection{status: http.StatusBadRequest}
	if got := fixture.register(t, rejectedAttempt); got.Status != vaultBoardDefinitelyNotSubmitted {
		t.Fatalf("banned register = %+v", got)
	}
	operationID, _ := policy.ComputeVaultBoardOperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	rejectedSnapshot, err := fixture.ledger.GetCurrentVaultBoardAttempt(context.Background(), operationID)
	if err != nil || rejectedSnapshot == nil || rejectedSnapshot.Register.Attempt != 1 ||
		rejectedSnapshot.RegisterSubmission == nil || rejectedSnapshot.RegisterSubmission.Outcome != policy.VaultBoardAuthRejected {
		t.Fatalf("rejected attempt = %+v, %v", rejectedSnapshot, err)
	}

	fixture.operator.registerErr = nil
	successfulAttempt := fixture.prepare(t)
	claims, err = fixture.svc.openVaultBoardHandle(successfulAttempt.Handle, string(vaultBoardReady))
	if err != nil || claims.Attempt != 2 {
		t.Fatalf("post-rejection rotation = %+v, claims=%+v, %v", successfulAttempt, claims, err)
	}
	successfulSession, _ := btcec.NewPrivateKey()
	fixture.proof.treePubHex = hex.EncodeToString(successfulSession.PubKey().SerializeCompressed())
	if got := fixture.register(t, successfulAttempt); got.Status != vaultBoardRegistered || fixture.operator.deletes != 0 {
		t.Fatalf("post-rejection register = %+v, delete calls=%d", got, fixture.operator.deletes)
	}
	successfulSnapshot, err := fixture.ledger.GetCurrentVaultBoardAttempt(context.Background(), operationID)
	if err != nil || successfulSnapshot == nil || successfulSnapshot.Register.Attempt != 2 ||
		bytes.Equal(successfulSnapshot.Register.RequestDigest, rejectedSnapshot.Register.RequestDigest) ||
		bytes.Equal(successfulSnapshot.Register.TreeSessionPub, rejectedSnapshot.Register.TreeSessionPub) {
		t.Fatalf("rotated attempt = %+v, rejected=%+v, %v", successfulSnapshot, rejectedSnapshot, err)
	}

	finalFixture := newVaultBoardFinalFixtureFromProof(t, fixture.proof)
	fixture.operator.finalErr = fmt.Errorf("connection reset after final authorization")
	result, err := fixture.svc.submitVaultBoardCommitment(context.Background(), vaultBoardFinalPhaseRequest{
		Handle: successfulAttempt.Handle, PSBT: finalFixture.evidence.SignedCommitmentPSBT,
		InputIndexes: []int{0}, Batch: finalFixture.evidence,
	})
	if err != nil || result != vaultBoardCommitmentAmbiguous || fixture.operator.finals != 1 {
		t.Fatalf("final authorization = %q, %v, calls=%d", result, err, fixture.operator.finals)
	}
	*fixture.clock = time.Unix(successfulAttempt.RegisterExpireAt, 0).UTC().Add(time.Hour)
	if got := fixture.prepare(t); got.State != vaultBoardBlocked || got.Handle != "" {
		t.Fatalf("final authorization allowed rotation: %+v", got)
	}
}

func TestVaultBoardServiceSupersedesExpiredRegisterAfterAmbiguousDelete(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	prepared := fixture.prepare(t)
	if got := fixture.register(t, prepared); got.Status != vaultBoardRegistered {
		t.Fatalf("register = %+v", got)
	}
	release := fixture.releaseHandle(t)
	deleteMessage, err := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: release.DeleteExpireAt,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	fixture.operator.deleteErr = fmt.Errorf("stock boarding-only delete did not match")
	result, err := fixture.svc.releaseVaultBoard(context.Background(), vaultBoardDeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, deleteMessage, nil),
		Message: deleteMessage, InputIndexes: []int{0, 1},
	})
	if err != nil || result != vaultBoardReleaseAmbiguous {
		t.Fatalf("ambiguous delete = %q, %v", result, err)
	}
	operationID, _ := policy.ComputeVaultBoardOperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardAttempt(context.Background(), operationID)
	if err != nil || snapshot.DeleteAuthorization == nil || snapshot.DeleteDispatch == nil || snapshot.DeleteSubmission != nil {
		t.Fatalf("delete boundary = %+v, %v", snapshot, err)
	}
	*fixture.clock = time.Unix(prepared.RegisterExpireAt, 0).UTC().Add(30 * time.Second)
	next := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardHandle(next.Handle, string(vaultBoardReady))
	if err != nil || claims.Attempt != 1 {
		t.Fatalf("superseding prepare = %+v, claims=%+v, %v", next, claims, err)
	}
	newSession, _ := btcec.NewPrivateKey()
	fixture.proof.treePubHex = hex.EncodeToString(newSession.PubKey().SerializeCompressed())
	fixture.operator.deleteErr = nil
	if got := fixture.register(t, next); got.Status != vaultBoardRegistered {
		t.Fatalf("superseding register = %+v", got)
	}
}

func TestVaultBoardServiceDistinguishesRejectedAndAmbiguousRegister(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want vaultBoardRegisterResult
	}{
		{name: "definite rejection", err: vaultBoardOperatorRejection{status: 412}, want: vaultBoardDefinitelyNotSubmitted},
		{name: "response loss", err: fmt.Errorf("connection reset"), want: vaultBoardRegisterAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVaultBoardServiceFixture(t)
			fixture.operator.registerErr = test.err
			got := fixture.register(t, fixture.prepare(t))
			if got.Status != test.want {
				t.Fatalf("status = %q, want %q", got.Status, test.want)
			}
			prepared := fixture.prepare(t)
			if test.want == vaultBoardDefinitelyNotSubmitted && prepared.State != vaultBoardReady {
				t.Fatalf("definite rejection did not rotate: %+v", prepared)
			}
			if test.want == vaultBoardRegisterAmbiguous && prepared.State != vaultBoardBlocked {
				t.Fatalf("response loss was not held until expiry: %+v", prepared)
			}
		})
	}
}

func TestVaultBoardHandleIsAuthenticatedAndExact(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	prepared := fixture.prepare(t)
	separator := strings.IndexByte(prepared.Handle, '.')
	if separator < 0 || separator+1 >= len(prepared.Handle) {
		t.Fatal("sealed handle has no signature")
	}
	replacement := byte('A')
	if prepared.Handle[separator+1] == replacement {
		replacement = 'B'
	}
	tampered := prepared.Handle[:separator+1] + string(replacement) + prepared.Handle[separator+2:]
	if _, err := fixture.svc.openVaultBoardHandle(tampered, string(vaultBoardReady)); err == nil {
		t.Fatal("tampered handle accepted")
	}
	if _, err := fixture.svc.openVaultBoardHandle(prepared.Handle, string(vaultBoardReleaseRequired)); err == nil {
		t.Fatal("ready handle reused for release")
	}
}

func TestVaultBoardRegisterUsesSharedVerificationCapacity(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	fixture.svc.MaxConcurrentVerifications = 1
	prepared := fixture.prepare(t)
	fixture.proof.expireAt = prepared.RegisterExpireAt
	message := fixture.proof.registerMessage(t)
	release, err := fixture.svc.acquireVerification(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, err = fixture.svc.registerVaultBoard(context.Background(), vaultBoardRegisterPhaseRequest{
		Handle: prepared.Handle, PSBT: fixture.proof.proof(t, message, []*wire.TxOut{fixture.proof.receiver}),
		Message: message, InputIndexes: []int{0, 1},
	})
	if !errors.Is(err, ErrVerificationBusy) {
		t.Fatalf("busy verifier = %v", err)
	}
}

func TestVaultBoardNarrowRevalidationIsBounded(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	state, err := revalidateVaultBoardOutpoint(fixture.svc.vaultBoardRuntime, fixture.chain.state)
	if err != nil || !fixture.chain.sawDeadline || state.TipMTP != fixture.chain.state.TipMTP {
		t.Fatalf("bounded revalidation = %+v, %v, deadline=%v", state, err, fixture.chain.sawDeadline)
	}
}

func TestVaultBoardRegisterRefusesProofInsideDispatchMargin(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	prepared := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardHandle(prepared.Handle, string(vaultBoardReady))
	if err != nil {
		t.Fatal(err)
	}
	claims.RegisterExpireAt = fixture.svc.vtxoNow().Add(vaultBoardDispatchMargin - time.Second).Unix()
	prepared.Handle, err = fixture.svc.sealVaultBoardHandle(claims)
	if err != nil {
		t.Fatal(err)
	}
	fixture.proof.expireAt = claims.RegisterExpireAt
	message := fixture.proof.registerMessage(t)
	result, err := fixture.svc.registerVaultBoard(context.Background(), vaultBoardRegisterPhaseRequest{
		Handle: prepared.Handle, PSBT: fixture.proof.proof(t, message, []*wire.TxOut{fixture.proof.receiver}),
		Message: message, InputIndexes: []int{0, 1},
	})
	if err != nil || result.Status != vaultBoardDefinitelyNotSubmitted || fixture.operator.registers != 0 {
		t.Fatalf("near-expiry register = %+v, %v, calls=%d", result, err, fixture.operator.registers)
	}
	operationID, _ := policy.ComputeVaultBoardOperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardAttempt(context.Background(), operationID)
	if err != nil || snapshot == nil || snapshot.RegisterDispatch != nil {
		t.Fatalf("near-expiry request crossed dispatch: %+v, %v", snapshot, err)
	}
}

func TestVaultBoardReleaseRefusesProofInsideDispatchMargin(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	fixture.register(t, fixture.prepare(t))
	release := fixture.releaseHandle(t)
	claims, err := fixture.svc.openVaultBoardHandle(release.Handle, string(vaultBoardReleaseRequired))
	if err != nil {
		t.Fatal(err)
	}
	claims.DeleteExpireAt = fixture.svc.vtxoNow().Add(vaultBoardDispatchMargin - time.Second).Unix()
	release.Handle, err = fixture.svc.sealVaultBoardHandle(claims)
	if err != nil {
		t.Fatal(err)
	}
	message, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: claims.DeleteExpireAt,
	}).Encode()
	result, err := fixture.svc.releaseVaultBoard(context.Background(), vaultBoardDeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, message, nil), Message: message, InputIndexes: []int{0, 1},
	})
	if err == nil || result != "" || fixture.operator.deletes != 0 {
		t.Fatalf("near-expiry release = %q, %v, calls=%d", result, err, fixture.operator.deletes)
	}
	operationID, _ := policy.ComputeVaultBoardOperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardAttempt(context.Background(), operationID)
	if err != nil || snapshot == nil || snapshot.DeleteAuthorization != nil || snapshot.DeleteDispatch != nil {
		t.Fatalf("near-expiry release crossed dispatch: %+v, %v", snapshot, err)
	}
}

func TestVaultBoardRestartBeforeDispatchRotatesServerAttempt(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	prepared := fixture.prepare(t)
	fixture.proof.expireAt = prepared.RegisterExpireAt
	message := fixture.proof.registerMessage(t)
	raw := fixture.proof.proof(t, message, []*wire.TxOut{fixture.proof.receiver})
	operationID, _ := policy.ComputeVaultBoardOperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	fixture.proof.operation.OperationID = operationID
	verified, err := verifyVaultBoardRegisterProof(raw, message, fixture.proof.operation, fixture.proof.tree, prepared.RegisterExpireAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, auth, _, err := fixture.ledger.BeginVaultBoardAttempt(context.Background(), fixture.proof.operation, policy.VaultBoardRegisterRequest{
		RequestDigest: verified.RequestDigest, TreeSessionPub: verified.TreeSession,
		ReceiverSats: verified.ReceiverSats, FeeSats: verified.FeeSats, ExpireAt: verified.ExpireAt,
	}, vaultBoardChainPolicy(fixture.chain.state)); err != nil || auth.Attempt != 0 {
		t.Fatalf("simulated pre-dispatch authorization = %+v, %v", auth, err)
	}

	next := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardHandle(next.Handle, string(vaultBoardReady))
	if err != nil || claims.Attempt != 1 {
		t.Fatalf("restart prepare = %+v, claims=%+v, %v", next, claims, err)
	}
	newSession, _ := btcec.NewPrivateKey()
	fixture.proof.treePubHex = hex.EncodeToString(newSession.PubKey().SerializeCompressed())
	registered := fixture.register(t, next)
	if registered.Status != vaultBoardRegistered || fixture.operator.registers != 1 {
		t.Fatalf("rotated register = %+v, calls=%d", registered, fixture.operator.registers)
	}
	if _, _, err := fixture.ledger.AppendVaultBoardDispatch(context.Background(), policy.VaultBoardDispatch{
		OperationID: operationID, Attempt: 0, Phase: policy.VaultBoardPhaseRegister,
		RequestDigest: verified.RequestDigest,
	}, vaultBoardChainPolicy(fixture.chain.state)); err == nil {
		t.Fatal("superseded attempt crossed dispatch boundary")
	}
}

func TestVaultBoardAttemptRepricesAfterExpiredRegister(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	first := fixture.prepare(t)
	fixture.register(t, first)
	*fixture.clock = time.Unix(first.RegisterExpireAt, 0).UTC().Add(30 * time.Second)
	fixture.resolver.feePolicy.OnchainInput = "2000.0"
	if _, err := fixture.svc.prepareVaultBoard(context.Background(), vaultBoardPrepareRequest{
		VaultID: fixture.vaultID,
		Inputs:  []vaultBoardPrepareInput{{Txid: hex.EncodeToString(fixture.proof.operation.Txid), Vout: fixture.proof.operation.Vout}},
		Recipients: []vaultBoardPrepareRecipient{{
			Address: fixture.receiver, AmountSats: 49_000,
		}},
	}); err == nil {
		t.Fatal("stale pre-release fee accepted")
	}
	fixture.proof.receiver.Value = 48_000
	next := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardHandle(next.Handle, string(vaultBoardReady))
	if err != nil || claims.Attempt != 1 || claims.FeeSats != 2_000 || claims.ReceiverSats != 48_000 {
		t.Fatalf("repriced attempt = %+v, %v", claims, err)
	}
	newSession, _ := btcec.NewPrivateKey()
	fixture.proof.treePubHex = hex.EncodeToString(newSession.PubKey().SerializeCompressed())
	if got := fixture.register(t, next); got.Status != vaultBoardRegistered {
		t.Fatalf("repriced register = %+v", got)
	}
}

func TestVaultBoardLostFinalResponseReconcilesExactVtxo(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	prepared := fixture.prepare(t)
	if got := fixture.register(t, prepared); got.Status != vaultBoardRegistered {
		t.Fatalf("register = %+v", got)
	}
	finalFixture := newVaultBoardFinalFixtureFromProof(t, fixture.proof)
	fixture.operator.finalErr = fmt.Errorf("connection reset after submit")
	result, err := fixture.svc.submitVaultBoardCommitment(context.Background(), vaultBoardFinalPhaseRequest{
		Handle: prepared.Handle, PSBT: finalFixture.evidence.SignedCommitmentPSBT,
		InputIndexes: []int{0}, Batch: finalFixture.evidence,
	})
	if err != nil || result != vaultBoardCommitmentAmbiguous || fixture.operator.finals != 1 {
		t.Fatalf("ambiguous final = %q, %v, calls=%d", result, err, fixture.operator.finals)
	}
	operationID, _ := policy.ComputeVaultBoardOperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardAttempt(context.Background(), operationID)
	if err != nil || snapshot.FinalAuthorization == nil || snapshot.FinalSubmission != nil {
		t.Fatalf("durable final evidence = %+v, %v", snapshot, err)
	}
	*fixture.clock = time.Unix(prepared.RegisterExpireAt, 0).UTC().Add(time.Hour)
	blocked := fixture.prepare(t)
	if blocked.State != vaultBoardBlocked {
		t.Fatalf("expired attempt crossed final boundary: %+v", blocked)
	}
	auth := snapshot.FinalAuthorization
	fixture.chain.state.Spent = true
	fixture.chain.state.SpendingTxid = auth.CommitmentTxid
	fixture.resolver.exact = &ports.ResolvedVtxo{
		Txid: auth.ReceiverTxid, Vout: auth.ReceiverVout, ValueSats: uint64(snapshot.Register.ReceiverSats),
		Script: bytes.Clone(snapshot.Operation.ReceiverScript), CommitmentTxids: []string{auth.CommitmentTxid},
	}
	fixture.chain.state.TipMTP = fixture.chain.state.SequenceAnchorMTP + int64(program.VaultBoardV1ExitDelay)
	finalized := fixture.prepare(t)
	if finalized.State != vaultBoardFinalized || finalized.CommitmentTxid != auth.CommitmentTxid {
		t.Fatalf("final reconcile = %+v", finalized)
	}
}

func TestVaultBoardDeleteResultPersistsAfterCallerCancellation(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	fixture.register(t, fixture.prepare(t))
	release := fixture.releaseHandle(t)
	deleteMessage, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: release.DeleteExpireAt,
	}).Encode()
	ctx, cancel := context.WithCancel(context.Background())
	fixture.operator.beforeDeleteReturn = cancel
	result, err := fixture.svc.releaseVaultBoard(ctx, vaultBoardDeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, deleteMessage, nil),
		Message: deleteMessage, InputIndexes: []int{0, 1},
	})
	if err != nil || result != vaultBoardReleased {
		t.Fatalf("release after cancellation = %q, %v", result, err)
	}
	next := fixture.prepare(t)
	if next.State != vaultBoardReady {
		t.Fatalf("prepare after durable release = %+v", next)
	}
}

func TestVaultBoardPersistedEnrollmentRequiresResolverBeforeReload(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	if err := fixture.ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := policy.OpenLedger(fixture.dbPath, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	keys, err := NewFileBackedKeyCapabilities(fixture.master, LocalSigner{Priv: fixture.emulator})
	if err != nil {
		t.Fatal(err)
	}
	reloaded := New(Deps{
		Stores: testStores(t, reopened), VaultBoardStore: reopened,
		Deployment: fixture.svc.Deployment, IntegrityKey: append([]byte(nil), testCredentialIntegrityKey...), Keys: keys,
		VaultCosignerPub: fixture.master.PubKey(), ArkadeCosignerPub: fixture.svc.ArkadeCosignerPub,
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
	})
	if err := reloaded.LoadVaults(); err == nil {
		t.Fatal("persisted v2 enrollment loaded before release-pinned resolver")
	}
	reloaded.ArkResolver = fixture.resolver
	if err := reloaded.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	status, err := reloaded.StatusFor(context.Background(), fixture.vaultID)
	if err != nil || status.VtxoBoardingProgram != program.VaultBoardV1 || status.VtxoBoardingAddress == "" {
		t.Fatalf("reloaded v2 status = %+v, %v", status, err)
	}
}

func TestVaultBoardDeleteFailureBeforeDispatchLeavesNoDeadAuthorization(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	fixture.register(t, fixture.prepare(t))
	release := fixture.releaseHandle(t)
	deleteMessage, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: release.DeleteExpireAt,
	}).Encode()
	// release first reloads authoritative chain facts, then rechecks immediately
	// before the atomic authorization+dispatch boundary.
	fixture.chain.errAt = fixture.chain.calls + 2
	result, err := fixture.svc.releaseVaultBoard(context.Background(), vaultBoardDeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, deleteMessage, nil),
		Message: deleteMessage, InputIndexes: []int{0, 1},
	})
	if err != nil || result != vaultBoardReleaseAmbiguous {
		t.Fatalf("pre-dispatch interruption = %q, %v", result, err)
	}
	operationID, _ := policy.ComputeVaultBoardOperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardAttempt(context.Background(), operationID)
	if err != nil || snapshot.DeleteAuthorization != nil || snapshot.DeleteDispatch != nil {
		t.Fatalf("pre-dispatch delete became durable: %+v, %v", snapshot, err)
	}
	fixture.chain.errAt = 0
	retry := fixture.releaseHandle(t)
	retryMessage, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: retry.DeleteExpireAt,
	}).Encode()
	result, err = fixture.svc.releaseVaultBoard(context.Background(), vaultBoardDeletePhaseRequest{
		Handle: retry.Handle, PSBT: fixture.proof.proof(t, retryMessage, nil),
		Message: retryMessage, InputIndexes: []int{0, 1},
	})
	if err != nil || result != vaultBoardReleased {
		t.Fatalf("retry release = %q, %v", result, err)
	}
}
