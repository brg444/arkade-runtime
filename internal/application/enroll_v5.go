package application

import (
	"bytes"
	"fmt"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/vault"
	v5 "github.com/brg444/arkade-vault-server/internal/vault/v5"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

func recoveryField(req RegisterRequest) string {
	if strings.TrimSpace(req.RecoveryXOnly) != "" {
		return req.RecoveryXOnly
	}
	return req.RecoveryKeyXOnly
}

func (s *Service) previewV5Descriptor(vaultID string, req RegisterRequest) (*ProposedEnrollment, error) {
	if vaultID == "" || vaultID == program.LeftoverVaultID {
		return nil, fmt.Errorf("tenant vault id required")
	}
	master, err := s.vaultCosignerMaster()
	if err != nil {
		return nil, err
	}
	child, err := policy.DeriveVaultCosignerScalar(master, vaultID, policy.CosignerModeHKDFSHA256V1)
	if err != nil {
		return nil, err
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return nil, err
	}
	// Recovery is optional. Skip it and the family is phone+hardware only.
	in, err := s.v5FamilyInput(vaultID, parsed, child.PubKey(), s.ArkadeCosignerPub)
	if err != nil {
		return nil, err
	}
	applyStagedProgram(&in, v5.Template)
	origin, version := s.arkadeIdentity()
	desc, _, err := v5.BuildPublicDescriptor(in, origin, version)
	if err != nil {
		return nil, err
	}
	hash, err := v5.HashPublicDescriptor(desc)
	if err != nil {
		return nil, err
	}
	return &ProposedEnrollment{VaultID: vaultID, DescriptorHash: hash, Descriptor: desc}, nil
}

func (s *Service) v5FamilyInput(vaultID string, parsed parsedRegisterRequest, vaultBase, arkadeBase *btcec.PublicKey) (v5.FamilyInput, error) {
	if arkadeBase == nil || parsed.phoneRoutine == nil || parsed.externalOwner == nil {
		return v5.FamilyInput{}, fmt.Errorf("v5 keys required")
	}
	auth, err := vault.AuthorizationScript(parsed.phoneDirectP256, configuredAuthorizationPolicy())
	if err != nil {
		return v5.FamilyInput{}, err
	}
	routineVault := arkade.ComputeArkadeScriptPublicKey(vaultBase, arkade.ArkadeScriptHash(auth))
	routineArkade := arkade.ComputeArkadeScriptPublicKey(arkadeBase, arkade.ArkadeScriptHash(auth))
	if routineVault == nil || routineArkade == nil {
		return v5.FamilyInput{}, fmt.Errorf("routine tweak is degenerate")
	}
	return v5.FamilyInput{
		VaultID:            vaultID,
		Network:            s.runtimeConfig().Network,
		Phone:              parsed.phoneRoutine,
		Hardware:           parsed.externalOwner,
		Recovery:           parsed.recovery,
		PhoneDirectP256:    parsed.phoneDirectP256,
		VaultCosignerBase:  vaultBase,
		ArkadeCosignerBase: arkadeBase,
		RoutineVault:       routineVault,
		RoutineArkade:      routineArkade,
	}, nil
}

func (s *Service) mintV5Credential(vaultID string, parsed parsedRegisterRequest, vaultBase *btcec.PublicKey) (policy.Credential, *vault.Built, *vault.Built, error) {
	in, err := s.v5FamilyInput(vaultID, parsed, vaultBase, s.ArkadeCosignerPub)
	if err != nil {
		return policy.Credential{}, nil, nil, err
	}
	applyStagedProgram(&in, v5.Template)
	origin, version := s.arkadeIdentity()
	_, fam, err := v5.BuildPublicDescriptor(in, origin, version)
	if err != nil {
		return policy.Credential{}, nil, nil, err
	}
	cfg := s.runtimeConfig()
	cred := policy.Credential{
		ID:                  append([]byte(nil), parsed.id...),
		WebAuthnP256:        append([]byte(nil), parsed.webauthnP256...),
		PhoneDirectP256:     append([]byte(nil), parsed.phoneDirectP256...),
		PhoneRoutineBIP340:  parsed.phoneRoutine.SerializeCompressed(),
		ExternalOwnerWallet: parsed.externalOwner.SerializeCompressed(),
		RecoveryKey: func() []byte {
			if parsed.recovery == nil {
				return retiredRecoveryPlaceholder()
			}
			return parsed.recovery.SerializeCompressed()
		}(),
		RPID:                  cfg.RPID,
		Origin:                cfg.ClientOrigin,
		VaultCosignerBase:     vaultBase.SerializeCompressed(),
		TweakedVaultCosigner:  in.RoutineVault.SerializeCompressed(),
		TweakedArkadeCosigner: in.RoutineArkade.SerializeCompressed(),
		ArkadeCosignerBase:    s.ArkadeCosignerPub.SerializeCompressed(),
		ArkadeCosignerOrigin:  origin,
		ArkadeCosignerVersion: version,
		TemplateVersion:       v5.Template,
		PolicyVersion:         program.PolicyVersion,
		Network:               cfg.Network,
		VaultID:               vaultID,
		OperationalCSVType:    int64(arklib.LocktimeTypeBlock),
		OperationalCSVValue:   cfg.OperationalCSVBlocks,
		SavingsCSVType:        int64(arklib.LocktimeTypeBlock),
		SavingsCSVValue:       cfg.SavingsCSVBlocks,
		OperationalAddress:    fam.Daily.Address,
		OperationalScript:     append([]byte(nil), fam.Daily.PkScript...),
		SavingsAddress:        fam.Savings.Address,
		SavingsScript:         append([]byte(nil), fam.Savings.PkScript...),
		RecipientDustSats:     program.DustSats,
		TxRecipientCapSats:    program.TxRecipientCapSats,
		PeriodAllowanceSats:   program.PeriodAllowanceSats,
		AbsoluteFeeCapSats:    program.AbsoluteFeeCeiling,
		FeerateCapSatPerV:     program.FeerateCeilingSatPerV,
	}
	op, sv, err := wrapV5Family(cred, fam, in)
	if err != nil {
		return policy.Credential{}, nil, nil, err
	}
	return cred, op, sv, nil
}

func (s *Service) arkadeIdentity() (string, string) {
	origin := s.ArkadeCosignerOrigin
	version := s.ArkadeCosignerVersion
	if origin == "" {
		origin = "http://emulator.local"
	}
	if version == "" {
		version = "authorizer"
	}
	return origin, version
}

func wrapV5Family(cred policy.Credential, fam *v5.Family, in v5.FamilyInput) (*vault.Built, *vault.Built, error) {
	auth, err := vault.AuthorizationScript(in.PhoneDirectP256, configuredAuthorizationPolicy())
	if err != nil {
		return nil, nil, err
	}
	scripts, err := dailyScriptVector(in, fam)
	if err != nil {
		return nil, nil, err
	}
	ctrl, err := controlForScript(in.VaultID, "daily", "", in.ProgramTemplate(), scripts, fam.DailyRoutine)
	if err != nil {
		return nil, nil, err
	}
	daily := &vault.Built{
		Address:               fam.Daily.Address,
		PkScript:              append([]byte(nil), fam.Daily.PkScript...),
		TweakedVaultCosigner:  in.RoutineVault,
		TweakedArkadeCosigner: in.RoutineArkade,
		Record: vault.Record{
			Kind:                vault.Operational,
			PhoneRoutineBIP340:  in.Phone,
			PhoneDirectP256:     append([]byte(nil), in.PhoneDirectP256...),
			ExternalOwnerWallet: in.Hardware,
			RecoveryKey:         in.Recovery,
			VaultCosignerBase:   in.VaultCosignerBase,
			ArkadeCosignerBase:  in.ArkadeCosignerBase,
			AuthScript:          auth,
			AuthorizationPolicy: configuredAuthorizationPolicy(),
			Network:             cred.Network,
		},
		Leaves: vault.Leaves{
			Routine: routineLeaf(fam.DailyRoutine, ctrl, &arkscript.MultisigClosure{
				PubKeys: []*btcec.PublicKey{in.Phone, in.RoutineVault, in.RoutineArkade},
			}),
		},
	}
	savings := &vault.Built{
		Address:  fam.Savings.Address,
		PkScript: append([]byte(nil), fam.Savings.PkScript...),
		Record: vault.Record{
			Kind:                vault.Savings,
			PhoneRoutineBIP340:  in.Phone,
			ExternalOwnerWallet: in.Hardware,
			RecoveryKey:         in.Recovery,
			Network:             cred.Network,
		},
	}
	return daily, savings, nil
}

func dailyScriptVector(in v5.FamilyInput, fam *v5.Family) ([][]byte, error) {
	admin, err := v5.Checksig(in.Phone, in.Hardware)
	if err != nil {
		return nil, err
	}
	out := [][]byte{append([]byte(nil), fam.DailyRoutine...), admin}
	claimants := []string{"phone", "hardware"}
	if in.Recovery != nil {
		claimants = append(claimants, "recovery")
	}
	for _, claimant := range claimants {
		pair := fam.InitiateDaily[claimant]
		var pub *btcec.PublicKey
		switch claimant {
		case "phone":
			pub = in.Phone
		case "hardware":
			pub = in.Hardware
		default:
			pub = in.Recovery
		}
		script, err := v5.Checksig(pub, pair.Vault, pair.Arkade)
		if err != nil {
			return nil, err
		}
		out = append(out, script)
	}
	return out, nil
}

func routineLeaf(script, control []byte, closure arkscript.Closure) *vault.Leaf {
	h := txscript.NewBaseTapLeaf(script).TapHash()
	return &vault.Leaf{
		Name:         "routine",
		Closure:      closure,
		Script:       append([]byte(nil), script...),
		ControlBlock: append([]byte(nil), control...),
		Hash:         h[:],
	}
}

func controlForScript(vaultID, kind, claimant, template string, scripts [][]byte, want []byte) ([]byte, error) {
	internal, err := v5.ContextInternalKeyTemplate(vaultID, kind, claimant, template)
	if err != nil {
		return nil, err
	}
	leaves := make([]txscript.TapLeaf, len(scripts))
	idx := -1
	for i, s := range scripts {
		leaves[i] = txscript.NewBaseTapLeaf(s)
		if bytes.Equal(s, want) {
			idx = i
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("routine leaf missing")
	}
	if len(leaves) == 1 {
		h := leaves[0].TapHash()
		output := txscript.ComputeTaprootOutputKey(internal, h[:])
		cb := txscript.ControlBlock{
			InternalKey:     internal,
			OutputKeyYIsOdd: output.SerializeCompressed()[0] == 0x03,
			LeafVersion:     txscript.BaseLeafVersion,
		}
		return cb.ToBytes()
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	cb := tree.LeafMerkleProofs[idx].ToControlBlock(internal)
	return cb.ToBytes()
}

func (s *Service) rebuildV5(cred *policy.Credential) (
	phoneRoutine, externalOwner, recovery, vaultBase, arkadeBase *btcec.PublicKey,
	op, sv *vault.Built, err error,
) {
	phoneRoutine, err = btcec.ParsePubKey(cred.PhoneRoutineBIP340)
	if err != nil {
		return
	}
	externalOwner, err = btcec.ParsePubKey(cred.ExternalOwnerWallet)
	if err != nil {
		return
	}
	if len(cred.RecoveryKey) > 0 {
		recovery, err = btcec.ParsePubKey(cred.RecoveryKey)
		if err != nil {
			return
		}
		if knownFixtureXOnly(schnorr.SerializePubKey(recovery)) {
			recovery = nil
		}
	}
	vaultBase, err = btcec.ParsePubKey(cred.VaultCosignerBase)
	if err != nil {
		return
	}
	arkadeBase, err = btcec.ParsePubKey(cred.ArkadeCosignerBase)
	if err != nil {
		return
	}
	parsed := parsedRegisterRequest{
		id: cred.ID, webauthnP256: cred.WebAuthnP256, phoneDirectP256: cred.PhoneDirectP256,
		phoneRoutine: phoneRoutine, externalOwner: externalOwner, recovery: recovery,
	}
	in, inErr := s.v5FamilyInput(cred.VaultID, parsed, vaultBase, arkadeBase)
	if inErr != nil {
		err = inErr
		return
	}
	applyStagedProgram(&in, cred.TemplateVersion)
	_, fam, bErr := v5.BuildPublicDescriptor(in, cred.ArkadeCosignerOrigin, cred.ArkadeCosignerVersion)
	if bErr != nil {
		err = bErr
		return
	}
	if fam.Daily.Address != cred.OperationalAddress || !bytes.Equal(fam.Daily.PkScript, cred.OperationalScript) {
		err = fmt.Errorf("rebuilt daily vault does not match stored descriptor")
		return
	}
	if fam.Savings.Address != cred.SavingsAddress || !bytes.Equal(fam.Savings.PkScript, cred.SavingsScript) {
		err = fmt.Errorf("rebuilt savings vault does not match stored descriptor")
		return
	}
	if !bytes.Equal(in.RoutineVault.SerializeCompressed(), cred.TweakedVaultCosigner) ||
		!bytes.Equal(in.RoutineArkade.SerializeCompressed(), cred.TweakedArkadeCosigner) {
		err = fmt.Errorf("rebuilt routine tweaks do not match stored descriptor")
		return
	}
	op, sv, err = wrapV5Family(*cred, fam, in)
	return
}

func applyStagedProgram(in *v5.FamilyInput, template string) {
	if in == nil {
		return
	}
	if template == "" {
		template = v5.Template
	}
	in.TemplateVersion = template
	in.ServerFreeClawback = template == v5.Template
}

func knownTemplate(template string) bool {
	return template == program.LeftoverV4Template || isStagedTemplate(template)
}

func isStagedTemplate(template string) bool {
	return template == v5.Template || template == v5.PriorTemplate
}

func isV5Template(template string) bool {
	return isStagedTemplate(template)
}

func publicEnrollTemplate(s *Service) string {
	return v5.Template
}
