package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
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

type vaultBoardV2TestChain struct {
	state       vaultBoardV2ConfirmedOutpoint
	err         error
	errAt       int
	calls       int
	sawDeadline bool
}

func (c *vaultBoardV2TestChain) confirmedOutpoint(context.Context, string, uint32) (vaultBoardV2ConfirmedOutpoint, error) {
	c.calls++
	if c.errAt == c.calls {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("chain query interrupted")
	}
	out := c.state
	out.Txid = bytes.Clone(c.state.Txid)
	out.PkScript = bytes.Clone(c.state.PkScript)
	return out, c.err
}

func (c *vaultBoardV2TestChain) revalidateOutpoint(ctx context.Context, prior vaultBoardV2ConfirmedOutpoint) (vaultBoardV2ConfirmedOutpoint, error) {
	_, c.sawDeadline = ctx.Deadline()
	return c.confirmedOutpoint(ctx, hex.EncodeToString(prior.Txid), prior.Vout)
}

type vaultBoardV2TestOperator struct {
	registerErr        error
	deleteErr          error
	finalErr           error
	registers          int
	deletes            int
	finals             int
	beforeDeleteReturn func()
}

func (o *vaultBoardV2TestOperator) registerIntent(context.Context, string, string) (string, error) {
	o.registers++
	if o.registerErr != nil {
		return "", o.registerErr
	}
	return fmt.Sprintf("intent-%d", o.registers), nil
}

func (o *vaultBoardV2TestOperator) deleteIntent(context.Context, string, string) error {
	o.deletes++
	if o.beforeDeleteReturn != nil {
		o.beforeDeleteReturn()
	}
	return o.deleteErr
}

func (o *vaultBoardV2TestOperator) submitCommitment(context.Context, string) error {
	o.finals++
	return o.finalErr
}

type vaultBoardV2TestResolver struct {
	stubArkResolver
	exact *ports.ResolvedVtxo
	err   error
}

func (r *vaultBoardV2TestResolver) exactVtxo(context.Context, string, uint32, []byte) (*ports.ResolvedVtxo, error) {
	if r.exact == nil {
		return nil, r.err
	}
	out := *r.exact
	out.Script = bytes.Clone(r.exact.Script)
	out.CommitmentTxids = append([]string(nil), r.exact.CommitmentTxids...)
	return &out, r.err
}

type vaultBoardV2ServiceFixture struct {
	svc      *Service
	ledger   *policy.Ledger
	chain    *vaultBoardV2TestChain
	operator *vaultBoardV2TestOperator
	resolver *vaultBoardV2TestResolver
	proof    vaultBoardV2ProofFixture
	vaultID  string
	receiver string
	now      time.Time
	dbPath   string
	master   *btcec.PrivateKey
	emulator *btcec.PrivateKey
}

func newVaultBoardV2ServiceFixture(t *testing.T) vaultBoardV2ServiceFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	dbPath := filepath.Join(t.TempDir(), "board-v2-service.sqlite")
	ledger, err := policy.OpenMutinynetVaultBoardV2Ledger(dbPath, func() time.Time { return now })
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
	keys, err := NewFileBackedVaultBoardV2KeyCapabilities(master, LocalSigner{Priv: emulator})
	if err != nil {
		t.Fatal(err)
	}
	svc.keys = keys
	svc.VaultCosignerPub = master.PubKey()
	svc.VaultBoardV2Store = ledger
	svc.EnrollmentNow = func() time.Time { return now }
	resolver := &vaultBoardV2TestResolver{stubArkResolver: stubArkResolver{
		feePolicy: ports.IntentFeePolicy{OnchainInput: "1000.0"},
		signer:    operatorKey.PubKey().SerializeCompressed(),
	}}
	svc.ArkResolver = resolver
	svc.SessionNow = func() time.Time { return now }

	raw := bytes.Repeat([]byte{0x6d}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, _ := HashEnrollmentToken(token)
	if err := ledger.PutInvite(hash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	base := attestedFinish(t, svc, start, pass, []byte("cred-board-v2-service"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	request := EnrollFinishVaultBoardV2Request{
		EnrollFinishRequest: base,
		VaultBoardV2EnrollmentRequest: VaultBoardV2EnrollmentRequest{
			VtxoBoardingProgram:           program.VaultBoardV2,
			VaultBoardV2BoardingBIP340Pub: hex.EncodeToString(schnorr.SerializePubKey(boarding.PubKey())),
		},
	}
	proposed, err := svc.ProposeVaultBoardV2Enrollment(token, request)
	if err != nil {
		t.Fatal(err)
	}
	request.DescriptorHash = proposed.DescriptorHash
	status, err := svc.FinishVaultBoardV2Enrollment(context.Background(), token, request)
	if err != nil {
		t.Fatal(err)
	}
	snap := svc.snapshot(start.VaultID)
	boardTree, err := svc.buildVtxoBoardV2Tree(start.VaultID, snap, snap.BoardV2.BoardingPub)
	if err != nil {
		t.Fatal(err)
	}
	receiverTree, err := svc.buildVtxoPolicyTree(start.VaultID, snap)
	if err != nil {
		t.Fatal(err)
	}
	txid := bytes.Repeat([]byte{0x42}, 32)
	chain := &vaultBoardV2TestChain{state: vaultBoardV2ConfirmedOutpoint{
		Txid: txid, Vout: 7, ValueSats: 50_000, PkScript: bytes.Clone(boardTree.PkScript),
		SequenceAnchorMTP: now.Unix() - 1_000, TipMTP: now.Unix(),
	}}
	op := &vaultBoardV2TestOperator{}
	svc.vaultBoardV2Runtime = &vaultBoardV2Runtime{
		chain: chain, operatorDial: func(context.Context) (vaultBoardV2Operator, error) { return op, nil },
		batchExpiry: 604_672,
	}
	treeSession, _ := btcec.NewPrivateKey()
	proof := vaultBoardV2ProofFixture{
		tree: boardTree, boarding: boarding,
		operation: policy.VaultBoardV2Operation{
			VaultID: start.VaultID, Txid: txid, Vout: 7, ValueSats: 50_000,
			BoardingScript: bytes.Clone(boardTree.PkScript), ReceiverScript: bytes.Clone(receiverTree.PkScript),
			SequenceAnchorMTP: chain.state.SequenceAnchorMTP,
		},
		expireAt:   now.Add(vaultBoardV2RegisterTTL).Unix(),
		receiver:   &wire.TxOut{Value: 49_000, PkScript: bytes.Clone(receiverTree.PkScript)},
		treePubHex: hex.EncodeToString(treeSession.PubKey().SerializeCompressed()),
	}
	if status.SpendingArkAddress != receiverTree.ArkAddress {
		t.Fatalf("Spending address = %q, want %q", status.SpendingArkAddress, receiverTree.ArkAddress)
	}
	return vaultBoardV2ServiceFixture{
		svc: svc, ledger: ledger, chain: chain, operator: op, resolver: resolver,
		proof: proof, vaultID: start.VaultID, receiver: receiverTree.ArkAddress, now: now,
		dbPath: dbPath, master: master, emulator: emulator,
	}
}

func (f vaultBoardV2ServiceFixture) prepare(t *testing.T) vaultBoardV2PrepareResult {
	t.Helper()
	result, err := f.svc.prepareVaultBoardV2(context.Background(), vaultBoardV2PrepareRequest{
		VaultID: f.vaultID,
		Inputs:  []vaultBoardV2PrepareInput{{Txid: hex.EncodeToString(f.proof.operation.Txid), Vout: f.proof.operation.Vout}},
		Recipients: []vaultBoardV2PrepareRecipient{{
			Address: f.receiver, AmountSats: uint64(f.proof.receiver.Value),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f vaultBoardV2ServiceFixture) register(t *testing.T, prepared vaultBoardV2PrepareResult) vaultBoardV2RegisterResponse {
	t.Helper()
	f.proof.expireAt = prepared.RegisterExpireAt
	message := f.proof.registerMessage(t)
	result, err := f.svc.registerVaultBoardV2(context.Background(), vaultBoardV2RegisterPhaseRequest{
		Handle: prepared.Handle, PSBT: f.proof.proof(t, message, []*wire.TxOut{f.proof.receiver}),
		Message: message, InputIndexes: []int{0, 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestVaultBoardV2ServiceDirectRegisterReleaseAndGenerationRotation(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	prepared := fixture.prepare(t)
	if prepared.State != vaultBoardV2Ready || prepared.Handle == "" {
		t.Fatalf("prepare = %+v", prepared)
	}
	registered := fixture.register(t, prepared)
	if registered.Status != vaultBoardV2Registered || registered.IntentID == "" || fixture.operator.registers != 1 {
		t.Fatalf("register = %+v, calls=%d", registered, fixture.operator.registers)
	}
	release := fixture.prepare(t)
	if release.State != vaultBoardV2ReleaseRequired || release.DeleteExpireAt <= fixture.now.Unix() {
		t.Fatalf("release prepare = %+v", release)
	}
	deleteMessage, err := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: release.DeleteExpireAt,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	result, err := fixture.svc.releaseVaultBoardV2(context.Background(), vaultBoardV2DeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, deleteMessage, nil),
		Message: deleteMessage, InputIndexes: []int{0, 1},
	})
	if err != nil || result != vaultBoardV2Released || fixture.operator.deletes != 1 {
		t.Fatalf("release = %q, %v, calls=%d", result, err, fixture.operator.deletes)
	}
	next := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardV2Handle(next.Handle, string(vaultBoardV2Ready))
	if err != nil || claims.Attempt != 1 {
		t.Fatalf("next attempt = %+v, %v", claims, err)
	}
	if _, err := fixture.svc.registerVaultBoardV2(context.Background(), vaultBoardV2RegisterPhaseRequest{
		Handle: prepared.Handle, PSBT: fixture.proof.proof(t, fixture.proof.registerMessage(t), []*wire.TxOut{fixture.proof.receiver}),
		Message: fixture.proof.registerMessage(t), InputIndexes: []int{0, 1},
	}); err == nil {
		t.Fatalf("released attempt replay accepted: %v", err)
	}
}

func TestVaultBoardV2ServiceDistinguishesRejectedAndAmbiguousRegister(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want vaultBoardV2RegisterResult
	}{
		{name: "definite rejection", err: vaultBoardV2OperatorRejection{status: 412}, want: vaultBoardV2DefinitelyNotSubmitted},
		{name: "response loss", err: fmt.Errorf("connection reset"), want: vaultBoardV2RegisterAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVaultBoardV2ServiceFixture(t)
			fixture.operator.registerErr = test.err
			got := fixture.register(t, fixture.prepare(t))
			if got.Status != test.want {
				t.Fatalf("status = %q, want %q", got.Status, test.want)
			}
			prepared := fixture.prepare(t)
			if test.want == vaultBoardV2DefinitelyNotSubmitted && prepared.State != vaultBoardV2Ready {
				t.Fatalf("definite rejection did not rotate: %+v", prepared)
			}
			if test.want == vaultBoardV2RegisterAmbiguous && prepared.State != vaultBoardV2ReleaseRequired {
				t.Fatalf("response loss did not require release: %+v", prepared)
			}
		})
	}
}

func TestVaultBoardV2HandleIsAuthenticatedAndExact(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	prepared := fixture.prepare(t)
	tampered := prepared.Handle[:len(prepared.Handle)-1] + "A"
	if _, err := fixture.svc.openVaultBoardV2Handle(tampered, string(vaultBoardV2Ready)); err == nil {
		t.Fatal("tampered handle accepted")
	}
	if _, err := fixture.svc.openVaultBoardV2Handle(prepared.Handle, string(vaultBoardV2ReleaseRequired)); err == nil {
		t.Fatal("ready handle reused for release")
	}
}

func TestVaultBoardV2RegisterUsesSharedVerificationCapacity(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	fixture.svc.MaxConcurrentVerifications = 1
	prepared := fixture.prepare(t)
	fixture.proof.expireAt = prepared.RegisterExpireAt
	message := fixture.proof.registerMessage(t)
	release, err := fixture.svc.acquireVerification(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, err = fixture.svc.registerVaultBoardV2(context.Background(), vaultBoardV2RegisterPhaseRequest{
		Handle: prepared.Handle, PSBT: fixture.proof.proof(t, message, []*wire.TxOut{fixture.proof.receiver}),
		Message: message, InputIndexes: []int{0, 1},
	})
	if !errors.Is(err, ErrVerificationBusy) {
		t.Fatalf("busy verifier = %v", err)
	}
}

func TestVaultBoardV2NarrowRevalidationIsBounded(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	state, err := revalidateVaultBoardV2Outpoint(fixture.svc.vaultBoardV2Runtime, fixture.chain.state)
	if err != nil || !fixture.chain.sawDeadline || state.TipMTP != fixture.chain.state.TipMTP {
		t.Fatalf("bounded revalidation = %+v, %v, deadline=%v", state, err, fixture.chain.sawDeadline)
	}
}

func TestVaultBoardV2RegisterRefusesProofInsideDispatchMargin(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	prepared := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardV2Handle(prepared.Handle, string(vaultBoardV2Ready))
	if err != nil {
		t.Fatal(err)
	}
	claims.RegisterExpireAt = fixture.svc.vtxoNow().Add(vaultBoardV2DispatchMargin - time.Second).Unix()
	prepared.Handle, err = fixture.svc.sealVaultBoardV2Handle(claims)
	if err != nil {
		t.Fatal(err)
	}
	fixture.proof.expireAt = claims.RegisterExpireAt
	message := fixture.proof.registerMessage(t)
	result, err := fixture.svc.registerVaultBoardV2(context.Background(), vaultBoardV2RegisterPhaseRequest{
		Handle: prepared.Handle, PSBT: fixture.proof.proof(t, message, []*wire.TxOut{fixture.proof.receiver}),
		Message: message, InputIndexes: []int{0, 1},
	})
	if err != nil || result.Status != vaultBoardV2DefinitelyNotSubmitted || fixture.operator.registers != 0 {
		t.Fatalf("near-expiry register = %+v, %v, calls=%d", result, err, fixture.operator.registers)
	}
	operationID, _ := policy.ComputeVaultBoardV2OperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardV2Attempt(context.Background(), operationID)
	if err != nil || snapshot == nil || snapshot.RegisterDispatch != nil {
		t.Fatalf("near-expiry request crossed dispatch: %+v, %v", snapshot, err)
	}
}

func TestVaultBoardV2ReleaseRefusesProofInsideDispatchMargin(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	fixture.register(t, fixture.prepare(t))
	release := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardV2Handle(release.Handle, string(vaultBoardV2ReleaseRequired))
	if err != nil {
		t.Fatal(err)
	}
	claims.DeleteExpireAt = fixture.svc.vtxoNow().Add(vaultBoardV2DispatchMargin - time.Second).Unix()
	release.Handle, err = fixture.svc.sealVaultBoardV2Handle(claims)
	if err != nil {
		t.Fatal(err)
	}
	message, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: claims.DeleteExpireAt,
	}).Encode()
	result, err := fixture.svc.releaseVaultBoardV2(context.Background(), vaultBoardV2DeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, message, nil), Message: message, InputIndexes: []int{0, 1},
	})
	if err == nil || result != "" || fixture.operator.deletes != 0 {
		t.Fatalf("near-expiry release = %q, %v, calls=%d", result, err, fixture.operator.deletes)
	}
	operationID, _ := policy.ComputeVaultBoardV2OperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardV2Attempt(context.Background(), operationID)
	if err != nil || snapshot == nil || snapshot.DeleteAuthorization != nil || snapshot.DeleteDispatch != nil {
		t.Fatalf("near-expiry release crossed dispatch: %+v, %v", snapshot, err)
	}
}

func TestVaultBoardV2RestartBeforeDispatchRotatesServerAttempt(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	prepared := fixture.prepare(t)
	fixture.proof.expireAt = prepared.RegisterExpireAt
	message := fixture.proof.registerMessage(t)
	raw := fixture.proof.proof(t, message, []*wire.TxOut{fixture.proof.receiver})
	operationID, _ := policy.ComputeVaultBoardV2OperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	fixture.proof.operation.OperationID = operationID
	verified, err := verifyVaultBoardV2RegisterProof(raw, message, fixture.proof.operation, fixture.proof.tree, prepared.RegisterExpireAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, auth, _, err := fixture.ledger.BeginVaultBoardV2Attempt(context.Background(), fixture.proof.operation, policy.VaultBoardV2RegisterRequest{
		RequestDigest: verified.RequestDigest, TreeSessionPub: verified.TreeSession,
		ReceiverSats: verified.ReceiverSats, FeeSats: verified.FeeSats, ExpireAt: verified.ExpireAt,
	}, vaultBoardV2ChainPolicy(fixture.chain.state)); err != nil || auth.Attempt != 0 {
		t.Fatalf("simulated pre-dispatch authorization = %+v, %v", auth, err)
	}

	next := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardV2Handle(next.Handle, string(vaultBoardV2Ready))
	if err != nil || claims.Attempt != 1 {
		t.Fatalf("restart prepare = %+v, claims=%+v, %v", next, claims, err)
	}
	newSession, _ := btcec.NewPrivateKey()
	fixture.proof.treePubHex = hex.EncodeToString(newSession.PubKey().SerializeCompressed())
	registered := fixture.register(t, next)
	if registered.Status != vaultBoardV2Registered || fixture.operator.registers != 1 {
		t.Fatalf("rotated register = %+v, calls=%d", registered, fixture.operator.registers)
	}
	if _, _, err := fixture.ledger.AppendVaultBoardV2Dispatch(context.Background(), policy.VaultBoardV2Dispatch{
		OperationID: operationID, Attempt: 0, Phase: policy.VaultBoardV2PhaseRegister,
		RequestDigest: verified.RequestDigest,
	}, vaultBoardV2ChainPolicy(fixture.chain.state)); err == nil {
		t.Fatal("superseded attempt crossed dispatch boundary")
	}
}

func TestVaultBoardV2AttemptRepricesAfterAuthoritativeRelease(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	first := fixture.prepare(t)
	fixture.register(t, first)
	release := fixture.prepare(t)
	deleteMessage, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: release.DeleteExpireAt,
	}).Encode()
	if result, err := fixture.svc.releaseVaultBoardV2(context.Background(), vaultBoardV2DeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, deleteMessage, nil),
		Message: deleteMessage, InputIndexes: []int{0, 1},
	}); err != nil || result != vaultBoardV2Released {
		t.Fatalf("release = %q, %v", result, err)
	}
	fixture.resolver.feePolicy.OnchainInput = "2000.0"
	if _, err := fixture.svc.prepareVaultBoardV2(context.Background(), vaultBoardV2PrepareRequest{
		VaultID: fixture.vaultID,
		Inputs:  []vaultBoardV2PrepareInput{{Txid: hex.EncodeToString(fixture.proof.operation.Txid), Vout: fixture.proof.operation.Vout}},
		Recipients: []vaultBoardV2PrepareRecipient{{
			Address: fixture.receiver, AmountSats: 49_000,
		}},
	}); err == nil {
		t.Fatal("stale pre-release fee accepted")
	}
	fixture.proof.receiver.Value = 48_000
	next := fixture.prepare(t)
	claims, err := fixture.svc.openVaultBoardV2Handle(next.Handle, string(vaultBoardV2Ready))
	if err != nil || claims.Attempt != 1 || claims.FeeSats != 2_000 || claims.ReceiverSats != 48_000 {
		t.Fatalf("repriced attempt = %+v, %v", claims, err)
	}
	newSession, _ := btcec.NewPrivateKey()
	fixture.proof.treePubHex = hex.EncodeToString(newSession.PubKey().SerializeCompressed())
	if got := fixture.register(t, next); got.Status != vaultBoardV2Registered {
		t.Fatalf("repriced register = %+v", got)
	}
}

func TestVaultBoardV2LostFinalResponseReconcilesExactVtxo(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	prepared := fixture.prepare(t)
	if got := fixture.register(t, prepared); got.Status != vaultBoardV2Registered {
		t.Fatalf("register = %+v", got)
	}
	finalFixture := newVaultBoardV2FinalFixtureFromProof(t, fixture.proof)
	fixture.operator.finalErr = fmt.Errorf("connection reset after submit")
	result, err := fixture.svc.submitVaultBoardV2Commitment(context.Background(), vaultBoardV2FinalPhaseRequest{
		Handle: prepared.Handle, PSBT: finalFixture.evidence.SignedCommitmentPSBT,
		InputIndexes: []int{0}, Batch: finalFixture.evidence,
	})
	if err != nil || result != vaultBoardV2CommitmentAmbiguous || fixture.operator.finals != 1 {
		t.Fatalf("ambiguous final = %q, %v, calls=%d", result, err, fixture.operator.finals)
	}
	operationID, _ := policy.ComputeVaultBoardV2OperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardV2Attempt(context.Background(), operationID)
	if err != nil || snapshot.FinalAuthorization == nil || snapshot.FinalSubmission != nil {
		t.Fatalf("durable final evidence = %+v, %v", snapshot, err)
	}
	auth := snapshot.FinalAuthorization
	fixture.chain.state.Spent = true
	fixture.chain.state.SpendingTxid = auth.CommitmentTxid
	fixture.resolver.exact = &ports.ResolvedVtxo{
		Txid: auth.ReceiverTxid, Vout: auth.ReceiverVout, ValueSats: uint64(snapshot.Register.ReceiverSats),
		Script: bytes.Clone(snapshot.Operation.ReceiverScript), CommitmentTxids: []string{auth.CommitmentTxid},
	}
	fixture.chain.state.TipMTP = fixture.chain.state.SequenceAnchorMTP + int64(program.VaultBoardV2ExitDelay)
	finalized := fixture.prepare(t)
	if finalized.State != vaultBoardV2Finalized || finalized.CommitmentTxid != auth.CommitmentTxid {
		t.Fatalf("final reconcile = %+v", finalized)
	}
}

func TestVaultBoardV2DeleteResultPersistsAfterCallerCancellation(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	fixture.register(t, fixture.prepare(t))
	release := fixture.prepare(t)
	deleteMessage, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: release.DeleteExpireAt,
	}).Encode()
	ctx, cancel := context.WithCancel(context.Background())
	fixture.operator.beforeDeleteReturn = cancel
	result, err := fixture.svc.releaseVaultBoardV2(ctx, vaultBoardV2DeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, deleteMessage, nil),
		Message: deleteMessage, InputIndexes: []int{0, 1},
	})
	if err != nil || result != vaultBoardV2Released {
		t.Fatalf("release after cancellation = %q, %v", result, err)
	}
	next := fixture.prepare(t)
	if next.State != vaultBoardV2Ready {
		t.Fatalf("prepare after durable release = %+v", next)
	}
}

func TestVaultBoardV2PersistedEnrollmentRequiresResolverBeforeReload(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	if err := fixture.ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := policy.OpenMutinynetVaultBoardV2Ledger(fixture.dbPath, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	keys, err := NewFileBackedVaultBoardV2KeyCapabilities(fixture.master, LocalSigner{Priv: fixture.emulator})
	if err != nil {
		t.Fatal(err)
	}
	reloaded := New(Deps{
		Stores: testStores(t, reopened), VaultBoardV2Store: reopened,
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
	if err != nil || status.VtxoBoardingProgram != program.VaultBoardV2 || status.VtxoBoardingAddress == "" {
		t.Fatalf("reloaded v2 status = %+v, %v", status, err)
	}
}

func TestVaultBoardV2DeleteFailureBeforeDispatchLeavesNoDeadAuthorization(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	fixture.register(t, fixture.prepare(t))
	release := fixture.prepare(t)
	deleteMessage, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: release.DeleteExpireAt,
	}).Encode()
	// release first reloads authoritative chain facts, then rechecks immediately
	// before the atomic authorization+dispatch boundary.
	fixture.chain.errAt = fixture.chain.calls + 2
	result, err := fixture.svc.releaseVaultBoardV2(context.Background(), vaultBoardV2DeletePhaseRequest{
		Handle: release.Handle, PSBT: fixture.proof.proof(t, deleteMessage, nil),
		Message: deleteMessage, InputIndexes: []int{0, 1},
	})
	if err != nil || result != vaultBoardV2ReleaseAmbiguous {
		t.Fatalf("pre-dispatch interruption = %q, %v", result, err)
	}
	operationID, _ := policy.ComputeVaultBoardV2OperationID(fixture.vaultID, fixture.proof.operation.Txid, fixture.proof.operation.Vout)
	snapshot, err := fixture.ledger.GetCurrentVaultBoardV2Attempt(context.Background(), operationID)
	if err != nil || snapshot.DeleteAuthorization != nil || snapshot.DeleteDispatch != nil {
		t.Fatalf("pre-dispatch delete became durable: %+v, %v", snapshot, err)
	}
	fixture.chain.errAt = 0
	retry := fixture.prepare(t)
	if retry.State != vaultBoardV2ReleaseRequired {
		t.Fatalf("retry prepare = %+v", retry)
	}
	retryMessage, _ := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete}, ExpireAt: retry.DeleteExpireAt,
	}).Encode()
	result, err = fixture.svc.releaseVaultBoardV2(context.Background(), vaultBoardV2DeletePhaseRequest{
		Handle: retry.Handle, PSBT: fixture.proof.proof(t, retryMessage, nil),
		Message: retryMessage, InputIndexes: []int{0, 1},
	})
	if err != nil || result != vaultBoardV2Released {
		t.Fatalf("retry release = %q, %v", result, err)
	}
}
