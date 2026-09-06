package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// connectorEnrollmentSchema is the versioned connector descriptor carried in
// enrollment responses and Recovery Kits. DescriptorHash agreement never
// depends on its JSON serialization: the combined hash commits the connector
// enrollment digest and the boarding wrapper hash.
const connectorEnrollmentSchema = "arkade-vault/connector-enrollment-v1"

// connectorEnrollmentDescriptor is the informative connector enrollment
// object. Every value it carries is independently reconstructed on both
// sides; only the combined hash below is compared.
type connectorEnrollmentDescriptor struct {
	Schema           string `json:"schema"`
	Template         string `json:"template"`
	VaultID          string `json:"vaultId"`
	Network          string `json:"network"`
	ProtectionTier   string `json:"protectionTier"`
	PhonePub         string `json:"phonePub"`
	HardwarePub      string `json:"hardwarePub"`
	RecoveryPub      string `json:"recoveryPub,omitempty"`
	PhoneDirectP256  string `json:"phoneDirectP256"`
	VaultCosigner    string `json:"vaultCosignerBase"`
	ArkadeCosigner   string `json:"arkadeCosignerBase"`
	SpendingPolicy   string `json:"spendingPolicyDigest"`
	Program          string `json:"program"`
	SavingsScript    string `json:"savingsScript"`
	SavingsAddress   string `json:"savingsAddress"`
	ConnectorScript  string `json:"connectorScript"`
	ConnectorType    string `json:"connectorType"`
	Fingerprint      uint32 `json:"fingerprint"`
	OriginPath       string `json:"originPath"`
	EnrollmentDigest string `json:"enrollmentDigest"`
}

// connectorBoardCompositeDescriptor commits the connector enrollment AND every
// boarding field. Boarding binding is never omitted: the hash covers the
// connector digest plus the complete legacy boarding wrapper hash.
type connectorBoardCompositeDescriptor struct {
	Schema    string                        `json:"schema"`
	VaultID   string                        `json:"vaultId"`
	Connector connectorEnrollmentDescriptor `json:"connector"`
	Boarding  vaultBoardPublicDescriptor    `json:"boarding"`
}

const connectorBoardEnrollmentSchema = "arkade-vault/enrollment-with-connector-v1"

// connectorSavingsPublicDescriptor builds the savings descriptor the boarding
// wrapper hash commits for connector vaults. savings.BuildPublicDescriptor
// always renders the legacy normal leaf even for the connector template, so
// the legacy Savings reference is replaced with the ACTUAL enrolled connector
// Savings tree before hashing. The wallet reproduces this identical override:
// build the savings descriptor from the documented inputs, then substitute the
// actual connector script/address carried in the connector descriptor object.
// Tweaks, pending, and quarantine come from the shared recovery base, so only
// the Savings reference differs from the raw builder output.
func connectorSavingsPublicDescriptor(in savings.FamilyInput, originName, version string, fam *connector.Family) (savings.PublicDescriptor, error) {
	desc, _, err := savings.BuildPublicDescriptor(in, originName, version)
	if err != nil {
		return savings.PublicDescriptor{}, err
	}
	if fam == nil || fam.Recovery == nil || len(fam.Recovery.Savings.PkScript) == 0 || fam.Recovery.Savings.Address == "" {
		return savings.PublicDescriptor{}, fmt.Errorf("connector recovery family required")
	}
	desc.Savings = savings.TreeRef{
		Script:  hex.EncodeToString(fam.Recovery.Savings.PkScript),
		Address: fam.Recovery.Savings.Address,
	}
	return desc, nil
}

// hashConnectorBoardComposite commits 0x01 ‖ connectorDigest ‖ boardingHash.
// Both sides implement this byte layout identically; no canonical JSON is
// hashed, so JSON field order and whitespace cannot cause disagreement.
func hashConnectorBoardComposite(digestHex, boardingHashHex string) (string, error) {
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("connector enrollment digest required")
	}
	boarding, err := hex.DecodeString(boardingHashHex)
	if err != nil || len(boarding) != sha256.Size {
		return "", fmt.Errorf("connector boarding hash required")
	}
	payload := make([]byte, 0, 65)
	payload = append(payload, 0x01)
	payload = append(payload, digest...)
	payload = append(payload, boarding...)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// hasConnectorRequest reports whether the enrollment carries any connector
// origin field. All-absent means a legacy vault; any present field routes the
// request through the connector preview, mint, and duplicate-finish paths,
// where partial origins are rejected.
func hasConnectorRequest(req RegisterRequest) bool {
	return req.ConnectorType != "" || req.ConnectorPub != "" ||
		req.ConnectorFingerprint != 0 || len(req.ConnectorPath) > 0
}

// parseConnectorOriginRequest validates the additive enrollment origin
// fields. All-absent means a legacy vault. The full 33-byte compressed origin
// key is required and compared exactly: P2WPKH identity depends on parity, so
// x-only equivalence is never substituted.
func parseConnectorOriginRequest(req RegisterRequest, network string) (*connector.KeyOrigin, *btcec.PublicKey, error) {
	kind := connector.Kind(req.ConnectorType)
	hasType := req.ConnectorType != ""
	hasPub := req.ConnectorPub != ""
	hasPath := len(req.ConnectorPath) > 0
	if !hasType && !hasPub && !hasPath && req.ConnectorFingerprint == 0 {
		return nil, nil, nil
	}
	if kind != connector.Taproot && kind != connector.NativeSegwit {
		return nil, nil, fmt.Errorf("connector type must be p2tr or p2wpkh")
	}
	if !hasPub {
		return nil, nil, fmt.Errorf("connector origin public key required")
	}
	raw, err := decodeHex(req.ConnectorPub)
	if err != nil || len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		return nil, nil, fmt.Errorf("connector origin compressed public key required")
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil || !bytes.Equal(pub.SerializeCompressed(), raw) {
		return nil, nil, fmt.Errorf("connector origin public key invalid")
	}
	origin := &connector.KeyOrigin{
		Type: kind, PublicKey: append([]byte(nil), raw...),
		Fingerprint: req.ConnectorFingerprint, Path: append([]uint32(nil), req.ConnectorPath...),
	}
	if _, err := origin.Kind(); err != nil {
		return nil, nil, fmt.Errorf("connector origin: %w", err)
	}
	// Standard BIP84/BIP86 origins commit the enrollment network's coin.
	// Electrum native origins (m/0'/...) carry no purpose prefix and skip this.
	coin := uint32(0x80000000)
	if network == "mutinynet" {
		coin++
	}
	if (origin.Path[0] == connector.NativeSegwit.Purpose() || origin.Path[0] == connector.Taproot.Purpose()) &&
		origin.Path[1] != coin {
		return nil, nil, fmt.Errorf("connector origin network mismatch")
	}
	return origin, pub, nil
}

// applyConnectorEnrollmentRequest binds the origin to the parsed enrollment.
// The origin key must share the enrolled hardware key's x-coordinate, while
// the full 33-byte compressed origin (including odd parity) is preserved in
// the side table and family: P2WPKH identity depends on parity, so the origin
// is never even-normalized. Connector vaults keep Standard/Advanced
// Savings semantics (Light is untouched).
func applyConnectorEnrollmentRequest(parsed parsedRegisterRequest, req RegisterRequest, network string) (parsedRegisterRequest, error) {
	origin, pub, err := parseConnectorOriginRequest(req, network)
	if err != nil {
		return parsed, err
	}
	if origin == nil {
		return parsed, nil
	}
	if parsed.externalOwner == nil ||
		!bytes.Equal(schnorr.SerializePubKey(pub), schnorr.SerializePubKey(parsed.externalOwner)) {
		return parsed, fmt.Errorf("connector origin key must be the enrolled hardware key")
	}
	if err := program.ValidateProtectionTier(parsed.protectionTier); err != nil {
		return parsed, err
	}
	parsed.connectorOrigin = origin
	parsed.connectorPub = pub
	return parsed, nil
}

// createConnectorTenantVault persists a connector vault atomically: the
// credential, the sealed hardware origin row, the boarding enrollment, and
// the invite consumption commit in one ledger transaction. The descriptor
// hash commits the FULL connector+boarding tuple; legacy previews never match
// a connector request.
func (s *Service) createConnectorTenantVault(vaultID string, tokenHash []byte, req RegisterRequest, parsed parsedRegisterRequest, pending *policy.PendingEnrollment, childPub *btcec.PublicKey) error {
	if parsed.connectorOrigin == nil || s.Stores.VaultBoard == nil || s.Stores.Connector == nil {
		return fmt.Errorf("connector enrollment store required")
	}
	proposed, err := s.previewConnectorEnrollmentDescriptor(vaultID, req)
	if err != nil {
		return err
	}
	if req.DescriptorHash == "" || req.DescriptorHash != proposed.DescriptorHash {
		return fmt.Errorf("enrollment descriptor hash does not match the proposed vault")
	}
	descriptor, sv, _, connectorRow, err := s.mintConnectorCredential(vaultID, parsed, childPub)
	if err != nil {
		return err
	}
	rec := vaultRecordFromDescriptor(descriptor)
	if err := sealVaultRecordForService(&rec, s); err != nil {
		return err
	}
	vcred := policy.VaultCredential{
		CredentialID: append([]byte(nil), descriptor.ID...),
		VaultID:      vaultID,
		WebAuthnP256: append([]byte(nil), descriptor.WebAuthnP256...),
		UserHandle:   []byte(vaultID),
		Resident:     true,
	}
	if err := sealVaultCredentialForService(&vcred, s); err != nil {
		return err
	}
	boardRec, boardSnap, err := s.mintVaultBoardEnrollment(vaultID, parsed)
	if err != nil {
		return err
	}
	if boardRec == nil || boardSnap == nil {
		return fmt.Errorf("vault-board-v1 release store is not active")
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	sealed := connectorRow
	if err := policy.SealConnectorEnrollment(&sealed, key); err != nil {
		return err
	}
	create := policy.CreateVaultInput{Record: rec, Credential: vcred, TokenHash: tokenHash, Pending: pending, Connector: &sealed}
	if err := s.Stores.VaultBoard.CreateVaultWithBoard(create, *boardRec); err != nil {
		return err
	}
	storedBoard, err := s.Stores.VaultBoard.GetVaultBoardEnrollment(vaultID)
	if err != nil || storedBoard == nil || !bytes.Equal(storedBoard.IntegrityMAC, boardRec.IntegrityMAC) {
		return fmt.Errorf("vault-board-v1 enrollment readback failed")
	}
	storedConnector, err := s.Stores.Connector.GetConnectorEnrollment(vaultID)
	if err != nil || storedConnector == nil || !bytes.Equal(storedConnector.IntegrityMAC, sealed.IntegrityMAC) {
		return fmt.Errorf("connector enrollment readback failed")
	}
	s.publishEnrollmentAt(vaultID, descriptor.ID, parsed.phone, sv, boardSnap)
	return nil
}

// connectorFamilyInput builds the exact mint tuple the connector family
// commits. The wallet reconstructs the identical tuple from its descriptor.
// in.Hardware carries the full parity-preserving origin key so P2WPKH scripts
// commit correctly; binding to the enrolled x-only hardware key is checked by
// x-coordinate, never by even-normalizing the origin.
func (s *Service) connectorFamilyInput(vaultID string, parsed parsedRegisterRequest, vaultBase, arkadeBase *btcec.PublicKey) (savings.FamilyInput, *connector.KeyOrigin, error) {
	if parsed.connectorOrigin == nil || parsed.externalOwner == nil || parsed.connectorPub == nil {
		return savings.FamilyInput{}, nil, fmt.Errorf("connector enrollment origin required")
	}
	in, err := s.savingsFamilyInput(vaultID, parsed, vaultBase, arkadeBase)
	if err != nil {
		return savings.FamilyInput{}, nil, err
	}
	in.TemplateVersion = connector.Template
	in.ServerFreeClawback = true
	origin := *parsed.connectorOrigin
	origin.PublicKey = append([]byte(nil), parsed.connectorOrigin.PublicKey...)
	origin.Path = append([]uint32(nil), parsed.connectorOrigin.Path...)
	if !bytes.Equal(schnorr.SerializePubKey(parsed.connectorPub), schnorr.SerializePubKey(parsed.externalOwner)) {
		return savings.FamilyInput{}, nil, fmt.Errorf("connector origin key must be the enrolled hardware key")
	}
	if !bytes.Equal(origin.PublicKey, parsed.connectorPub.SerializeCompressed()) {
		return savings.FamilyInput{}, nil, fmt.Errorf("connector origin key must be the enrolled hardware key")
	}
	// Preserve parity for script derivation: the family commits the full
	// compressed origin, not the even-normalized onboarding key.
	in.Hardware = parsed.connectorPub
	return in, &origin, nil
}

func connectorOriginPathString(path []uint32) string {
	fields := make([]string, len(path))
	for i, n := range path {
		fields[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(fields, "/")
}

// mintConnectorCredential builds the connector credential, its descriptor,
// and the sealed origin row from already-parsed enrollment material.
func (s *Service) mintConnectorCredential(vaultID string, parsed parsedRegisterRequest, vaultBase *btcec.PublicKey) (policy.Credential, *savingsSnapshot, *connector.Family, policy.ConnectorEnrollment, error) {
	var empty policy.ConnectorEnrollment
	in, origin, err := s.connectorFamilyInput(vaultID, parsed, vaultBase, s.ArkadeCosignerPub)
	if err != nil {
		return policy.Credential{}, nil, nil, empty, err
	}
	kind, err := origin.Kind()
	if err != nil {
		return policy.Credential{}, nil, nil, empty, err
	}
	fam, err := connector.BuildFamily(in, kind)
	if err != nil {
		return policy.Credential{}, nil, nil, empty, err
	}
	cfg := s.runtimeConfig()
	arkadeOrigin, arkadeVersion := s.arkadeIdentity()
	cred := policy.Credential{
		ID:                    append([]byte(nil), parsed.id...),
		WebAuthnP256:          append([]byte(nil), parsed.webauthnP256...),
		PhoneDirectP256:       append([]byte(nil), parsed.phoneDirectP256...),
		PhoneBIP340:           parsed.phone.SerializeCompressed(),
		ExternalOwnerWallet:   append([]byte(nil), in.Hardware.SerializeCompressed()...),
		RecoveryKey:           nil,
		RPID:                  cfg.RPID,
		Origin:                cfg.ClientOrigin,
		VaultCosignerBase:     vaultBase.SerializeCompressed(),
		ArkadeCosignerBase:    s.ArkadeCosignerPub.SerializeCompressed(),
		ArkadeCosignerOrigin:  arkadeOrigin,
		ArkadeCosignerVersion: arkadeVersion,
		TemplateVersion:       connector.Template,
		PolicyVersion:         program.PolicyVersion,
		ProtectionTier:        parsed.protectionTier,
		Network:               cfg.Network,
		VaultID:               vaultID,
		SavingsAddress:        fam.Recovery.Savings.Address,
		SavingsScript:         append([]byte(nil), fam.Recovery.Savings.PkScript...),
		RecipientDustSats:     program.DustSats,
		TxRecipientCapSats:    parsed.spendingPolicy.TxRecipientCapSats,
		PeriodAllowanceSats:   parsed.spendingPolicy.PeriodAllowanceSats,
		AbsoluteFeeCapSats:    parsed.spendingPolicy.AbsoluteFeeCapSats,
		FeerateCapSatPerV:     parsed.spendingPolicy.FeerateCapSatPerV,
	}
	if parsed.recovery != nil {
		cred.RecoveryKey = parsed.recovery.SerializeCompressed()
	}
	row := policy.ConnectorEnrollment{
		VaultID: vaultID, Type: string(kind), Pub: append([]byte(nil), origin.PublicKey...),
		Fingerprint: origin.Fingerprint, Path: append([]uint32(nil), origin.Path...),
	}
	sv := &savingsSnapshot{
		Address:             fam.Recovery.Savings.Address,
		PkScript:            append([]byte(nil), fam.Recovery.Savings.PkScript...),
		ExternalOwnerWallet: in.Hardware,
		RecoveryKey:         in.Recovery,
		VaultCosignerBase:   in.VaultCosignerBase,
		ArkadeCosignerBase:  in.ArkadeCosignerBase,
	}
	return cred, sv, fam, row, nil
}

// previewConnectorEnrollmentDescriptor rebuilds the combined enrollment
// commitment the wallet must reproduce: the connector digest plus the full
// boarding wrapper hash over the ACTUAL connector Savings descriptor (see
// connectorSavingsPublicDescriptor). The legacy savings builder always renders
// the old admin-leaf tree, so the wallet applies the same documented override.
func (s *Service) previewConnectorEnrollmentDescriptor(vaultID string, req RegisterRequest) (*ProposedEnrollment, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("tenant vault id required")
	}
	childPub, err := s.keys.enrollmentPublic(vaultID)
	if err != nil {
		return nil, err
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return nil, err
	}
	parsed, err = s.applyVaultBoardEnrollmentRequest(parsed, req)
	if err != nil {
		return nil, err
	}
	parsed, err = applyConnectorEnrollmentRequest(parsed, req, s.runtimeConfig().Network)
	if err != nil {
		return nil, err
	}
	if parsed.connectorOrigin == nil {
		return nil, fmt.Errorf("connector enrollment origin required")
	}
	in, origin, err := s.connectorFamilyInput(vaultID, parsed, childPub, s.ArkadeCosignerPub)
	if err != nil {
		return nil, err
	}
	kind, err := origin.Kind()
	if err != nil {
		return nil, err
	}
	fam, err := connector.BuildFamily(in, kind)
	if err != nil {
		return nil, err
	}
	digest, err := connector.EnrollmentDigest(in, *origin)
	if err != nil {
		return nil, err
	}
	originName, version := s.arkadeIdentity()
	baseDesc, err := connectorSavingsPublicDescriptor(in, originName, version, fam)
	if err != nil {
		return nil, err
	}
	board, _, err := s.buildVaultBoardEnrollment(vaultID, parsed)
	if err != nil {
		return nil, err
	}
	boardingHash, err := hashVaultBoardComposite(vaultBoardCompositeDescriptor{
		Schema: vaultBoardEnrollmentSchema, VaultID: vaultID, Savings: baseDesc, Boarding: board,
	})
	if err != nil {
		return nil, err
	}
	hash, err := hashConnectorBoardComposite(digest, boardingHash)
	if err != nil {
		return nil, err
	}
	recovery := ""
	if in.Recovery != nil {
		recovery = hex.EncodeToString(in.Recovery.SerializeCompressed())
	}
	policyDigest, err := program.SpendingPolicyDigestHexFor(in.Network, in.SpendingPolicy)
	if err != nil {
		return nil, err
	}
	desc := connectorBoardCompositeDescriptor{
		Schema: connectorBoardEnrollmentSchema, VaultID: vaultID,
		Connector: connectorEnrollmentDescriptor{
			Schema: connectorEnrollmentSchema, Template: connector.Template,
			VaultID: vaultID, Network: in.Network, ProtectionTier: in.ProtectionTier,
			PhonePub:         hex.EncodeToString(in.Phone.SerializeCompressed()),
			HardwarePub:      hex.EncodeToString(in.Hardware.SerializeCompressed()),
			RecoveryPub:      recovery,
			PhoneDirectP256:  hex.EncodeToString(in.PhoneDirectP256),
			VaultCosigner:    hex.EncodeToString(in.VaultCosignerBase.SerializeCompressed()),
			ArkadeCosigner:   hex.EncodeToString(in.ArkadeCosignerBase.SerializeCompressed()),
			SpendingPolicy:   policyDigest,
			Program:          hex.EncodeToString(fam.Program),
			SavingsScript:    hex.EncodeToString(fam.Recovery.Savings.PkScript),
			SavingsAddress:   fam.Recovery.Savings.Address,
			ConnectorScript:  hex.EncodeToString(fam.Rules.ConnectorScript),
			ConnectorType:    string(kind),
			Fingerprint:      origin.Fingerprint,
			OriginPath:       connectorOriginPathString(origin.Path),
			EnrollmentDigest: digest,
		},
		Boarding: board,
	}
	return &ProposedEnrollment{VaultID: vaultID, DescriptorHash: hash, Descriptor: desc}, nil
}

// parseConnectorCredentialKeys parses the enrolled keys without trusting any
// stored script: the caller must verify via rebuildConnectorFamily.
func parseConnectorCredentialKeys(cred *policy.Credential) (phone, hardware, recovery, vaultBase, arkadeBase *btcec.PublicKey, err error) {
	if cred == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("connector credential required")
	}
	if phone, err = btcec.ParsePubKey(cred.PhoneBIP340); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("phone key")
	}
	if hardware, err = btcec.ParsePubKey(cred.ExternalOwnerWallet); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("hardware key")
	}
	if len(cred.RecoveryKey) > 0 {
		if recovery, err = btcec.ParsePubKey(cred.RecoveryKey); err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("recovery key")
		}
		if knownFixtureXOnly(schnorr.SerializePubKey(recovery)) {
			recovery = nil
		}
	}
	if vaultBase, err = btcec.ParsePubKey(cred.VaultCosignerBase); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("vault cosigner key")
	}
	if arkadeBase, err = btcec.ParsePubKey(cred.ArkadeCosignerBase); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("arkade cosigner key")
	}
	return phone, hardware, recovery, vaultBase, arkadeBase, nil
}

// rebuildConnectorFamily reconstructs the exact enrolled connector family
// from the MAC-verified credential plus the MAC-verified origin row, then
// proves the rebuild: the Savings script and connector script must match the
// credential. Every recovery and withdrawal path for connector vaults
// goes through this function (R7): a template gate alone never selects the
// contract.
func (s *Service) connectorFamilyParameters(cred *policy.Credential) (savings.FamilyInput, connector.KeyOrigin, error) {
	phone, hardware, recovery, vaultBase, arkadeBase, err := parseConnectorCredentialKeys(cred)
	if err != nil {
		return savings.FamilyInput{}, connector.KeyOrigin{}, err
	}
	originRow, err := s.Stores.Connector.GetConnectorEnrollment(cred.VaultID)
	if err != nil {
		return savings.FamilyInput{}, connector.KeyOrigin{}, err
	}
	if originRow == nil {
		return savings.FamilyInput{}, connector.KeyOrigin{}, fmt.Errorf("connector enrollment missing")
	}
	origin := connector.KeyOrigin{
		Type: connector.Kind(originRow.Type), PublicKey: append([]byte(nil), originRow.Pub...),
		Fingerprint: originRow.Fingerprint, Path: append([]uint32(nil), originRow.Path...),
	}
	if !bytes.Equal(origin.PublicKey, hardware.SerializeCompressed()) {
		return savings.FamilyInput{}, connector.KeyOrigin{}, fmt.Errorf("connector origin key mismatch")
	}
	in := savings.FamilyInput{
		VaultID: cred.VaultID, Network: cred.Network, Phone: phone, Hardware: hardware,
		Recovery: recovery, PhoneDirectP256: append([]byte(nil), cred.PhoneDirectP256...),
		VaultCosignerBase: vaultBase, ArkadeCosignerBase: arkadeBase,
		TemplateVersion: connector.Template, ServerFreeClawback: true,
		ProtectionTier: cred.ProtectionTier,
		SpendingPolicy: program.SpendingPolicyFromValues(
			cred.TxRecipientCapSats, cred.PeriodAllowanceSats, cred.AbsoluteFeeCapSats, cred.FeerateCapSatPerV,
		),
	}
	return in, origin, nil
}

func (s *Service) rebuildConnectorFamily(cred *policy.Credential) (*connector.Family, error) {
	if cred == nil || cred.TemplateVersion != connector.Template {
		return nil, fmt.Errorf("connector credential required")
	}
	in, origin, err := s.connectorFamilyParameters(cred)
	if err != nil {
		return nil, err
	}
	kind, err := origin.Kind()
	if err != nil {
		return nil, err
	}
	fam, err := connector.BuildFamily(in, kind)
	if err != nil {
		return nil, err
	}
	if fam.Recovery.Savings.Address != cred.SavingsAddress || !bytes.Equal(fam.Recovery.Savings.PkScript, cred.SavingsScript) {
		return nil, fmt.Errorf("rebuilt connector vault does not match stored descriptor")
	}
	return fam, nil
}

// connectorRecoveryFamily returns the recovery base every recovery path must
// use for connector credentials: initiate, pending, clawback, quarantine, and
// claim tooling operate on this family, never on the old admin-leaf tree.
func (s *Service) connectorRecoveryFamily(cred *policy.Credential) (*savings.Family, error) {
	fam, err := s.rebuildConnectorFamily(cred)
	if err != nil {
		return nil, err
	}
	if fam.Recovery == nil {
		return nil, fmt.Errorf("connector recovery family missing")
	}
	return fam.Recovery, nil
}

func isConnectorCredential(cred *policy.Credential) bool {
	return cred != nil && cred.TemplateVersion == connector.Template
}

// acceptConnectorDuplicateFinish resumes an already-finished connector
// enrollment only on exact replay: the combined descriptor hash, the minted
// credential, the boarding row, and the sealed origin row must all compare
// equal. No stranded or replaced row is accepted.
func (s *Service) acceptConnectorDuplicateFinish(vaultID string, req RegisterRequest, parsed parsedRegisterRequest, rec *policy.VaultRecord, cred *policy.VaultCredential) (*Status, bool) {
	if rec == nil || cred == nil || parsed.connectorOrigin == nil {
		return nil, false
	}
	preview, err := s.previewConnectorEnrollmentDescriptor(vaultID, req)
	if err != nil || req.DescriptorHash == "" || req.DescriptorHash != preview.DescriptorHash {
		return nil, false
	}
	childPub, err := s.keys.enrollmentPublic(vaultID)
	if err != nil {
		return nil, false
	}
	descriptor, _, _, wantConnector, err := s.mintConnectorCredential(vaultID, parsed, childPub)
	if err != nil {
		return nil, false
	}
	wantRecord := vaultRecordFromDescriptor(descriptor)
	wantCredential := policy.VaultCredential{
		CredentialID: parsed.id, VaultID: vaultID, WebAuthnP256: parsed.webauthnP256,
		UserHandle: []byte(vaultID), Resident: true,
	}
	if policy.VaultRecordsCanonicallyEqual(*rec, wantRecord) != nil ||
		policy.VaultCredentialsCanonicallyEqual(*cred, wantCredential) != nil {
		return nil, false
	}
	if s.Stores.VaultBoard == nil || s.Stores.Connector == nil {
		return nil, false
	}
	storedBoard, loadErr := s.Stores.VaultBoard.GetVaultBoardEnrollment(vaultID)
	wantBoard, _, buildErr := s.mintVaultBoardEnrollment(vaultID, parsed)
	if loadErr != nil || buildErr != nil || storedBoard == nil || wantBoard == nil ||
		storedBoard.Program != wantBoard.Program || !bytes.Equal(storedBoard.BoardingPub, wantBoard.BoardingPub) ||
		!bytes.Equal(storedBoard.CosignerPub, wantBoard.CosignerPub) || !bytes.Equal(storedBoard.OperatorPub, wantBoard.OperatorPub) ||
		storedBoard.ExitDelay != wantBoard.ExitDelay || storedBoard.ExitDelayUnit != wantBoard.ExitDelayUnit ||
		!bytes.Equal(storedBoard.PkScript, wantBoard.PkScript) || storedBoard.Address != wantBoard.Address {
		return nil, false
	}
	storedConnector, err := s.Stores.Connector.GetConnectorEnrollment(vaultID)
	if err != nil || storedConnector == nil {
		return nil, false
	}
	if storedConnector.Type != string(parsed.connectorOrigin.Type) ||
		!bytes.Equal(storedConnector.Pub, parsed.connectorOrigin.PublicKey) ||
		storedConnector.Fingerprint != parsed.connectorOrigin.Fingerprint ||
		!equalUint32Path(storedConnector.Path, parsed.connectorOrigin.Path) ||
		storedConnector.VaultID != vaultID {
		return nil, false
	}
	// The origin row must also match the minted descriptor's enrolled key.
	if wantConnector.VaultID != vaultID || wantConnector.Type != storedConnector.Type ||
		!bytes.Equal(wantConnector.Pub, storedConnector.Pub) ||
		wantConnector.Fingerprint != storedConnector.Fingerprint ||
		!equalUint32Path(wantConnector.Path, storedConnector.Path) {
		return nil, false
	}
	st, err := s.statusFor(context.Background(), vaultID)
	if err != nil {
		return nil, false
	}
	return &st, true
}

// statusConnectorBoardDescriptor rebuilds the boarding view for a connector
// vault from the enrolled connector family. The returned hash is the boarding
// wrapper hash over the connector Savings descriptor: it matches the
// boarding half of the enrollment commitment, while the full enrollment hash
// additionally commits the connector digest.
func (s *Service) statusConnectorBoardDescriptor(cred *policy.Credential, snap enrolledSnapshot) (vaultBoardCompositeDescriptor, string, error) {
	if cred == nil || snap.Board == nil || snap.Board.BoardingPub == nil {
		return vaultBoardCompositeDescriptor{}, "", fmt.Errorf("vault-board-v1 enrollment descriptor unavailable")
	}
	fam, err := s.rebuildConnectorFamily(cred)
	if err != nil {
		return vaultBoardCompositeDescriptor{}, "", err
	}
	phone, hardware, recovery, vaultBase, arkadeBase, err := parseConnectorCredentialKeys(cred)
	if err != nil {
		return vaultBoardCompositeDescriptor{}, "", err
	}
	in := savings.FamilyInput{
		VaultID: cred.VaultID, Network: cred.Network, Phone: phone, Hardware: hardware,
		Recovery: recovery, PhoneDirectP256: append([]byte(nil), cred.PhoneDirectP256...),
		VaultCosignerBase: vaultBase, ArkadeCosignerBase: arkadeBase,
		TemplateVersion: connector.Template, ServerFreeClawback: true,
		ProtectionTier: cred.ProtectionTier,
		SpendingPolicy: program.SpendingPolicyFromValues(
			cred.TxRecipientCapSats, cred.PeriodAllowanceSats, cred.AbsoluteFeeCapSats, cred.FeerateCapSatPerV,
		),
	}
	// The hash commits the ACTUAL connector Savings tree, identical to the
	// enrollment preview; rebuildConnectorFamily above already proved the
	// family matches the stored credential.
	savingsDesc, err := connectorSavingsPublicDescriptor(in, cred.ArkadeCosignerOrigin, cred.ArkadeCosignerVersion, fam)
	if err != nil {
		return vaultBoardCompositeDescriptor{}, "", err
	}
	if savingsDesc.Savings.Address != cred.SavingsAddress {
		return vaultBoardCompositeDescriptor{}, "", fmt.Errorf("rebuilt connector vault does not match stored descriptor")
	}
	boardTree, err := s.buildVtxoBoardTree(cred.VaultID, snap, snap.Board.BoardingPub)
	if err != nil || boardTree.OnchainAddress != snap.Board.Address || !bytes.Equal(boardTree.PkScript, snap.Board.PkScript) {
		return vaultBoardCompositeDescriptor{}, "", fmt.Errorf("vault-board-v1 enrollment descriptor mismatch")
	}
	board := vaultBoardPublicDescriptor{
		Schema: program.VaultBoardV1Schema, Program: program.VaultBoardV1, Template: program.VaultBoardV1Template,
		Network: cred.Network, BoardingPub: hex.EncodeToString(boardTree.BoardingPub.SerializeCompressed()),
		RecoveryPhonePub: hex.EncodeToString(phone.SerializeCompressed()),
		CosignerPub:      hex.EncodeToString(boardTree.CosignerPub.SerializeCompressed()),
		OperatorPub:      hex.EncodeToString(boardTree.OperatorPub.SerializeCompressed()),
		ExitDelay:        s.boardExitDelay(), ExitDelayUnit: program.VaultBoardV1ExitDelayUnit,
		Script: hex.EncodeToString(boardTree.PkScript), Address: boardTree.OnchainAddress,
	}
	desc := vaultBoardCompositeDescriptor{Schema: vaultBoardEnrollmentSchema, VaultID: cred.VaultID, Savings: savingsDesc, Boarding: board}
	hash, err := hashVaultBoardComposite(desc)
	return desc, hash, err
}

func equalUint32Path(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ConnectorCapability advertises the exact enrollment and withdrawal contract.
type ConnectorCapability struct {
	Schema           string `json:"schema"`
	Program          string `json:"program"`
	Template         string `json:"template"`
	ReserveSats      int64  `json:"reserveSats"`
	EnrollmentSchema string `json:"enrollmentSchema"`
}

func currentConnectorCapability() *ConnectorCapability {
	return &ConnectorCapability{Schema: "arkade-vault/connector-capability-v1", Program: "savings-connector-v1", Template: connector.Template, ReserveSats: connector.ReserveSats, EnrollmentSchema: connectorBoardEnrollmentSchema}
}

// ConnectorEnrollmentStatus is reconstructed from authenticated enrollment
// records. A recovering client also checks it against the phone-signed binding.
type ConnectorEnrollmentStatus struct {
	ConnectorType        string   `json:"connectorType"`
	ConnectorPub         string   `json:"connectorPub"`
	ConnectorFingerprint uint32   `json:"connectorFingerprint"`
	ConnectorPath        []uint32 `json:"connectorPath"`
	EnrollmentDigest     string   `json:"enrollmentDigest"`
	DescriptorHash       string   `json:"descriptorHash"`
}

func (s *Service) connectorEnrollmentStatus(cred *policy.Credential, snap enrolledSnapshot) (*ConnectorEnrollmentStatus, error) {
	if !isConnectorCredential(cred) || s.Stores.Connector == nil {
		return nil, fmt.Errorf("connector enrollment required")
	}
	row, err := s.Stores.Connector.GetConnectorEnrollment(cred.VaultID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("connector enrollment missing")
	}
	_, boardingHash, err := s.statusConnectorBoardDescriptor(cred, snap)
	if err != nil {
		return nil, err
	}
	in, origin, err := s.connectorFamilyParameters(cred)
	if err != nil {
		return nil, err
	}
	digest, err := connector.EnrollmentDigest(in, origin)
	if err != nil {
		return nil, err
	}
	digestHex := digest
	combined, err := hashConnectorBoardComposite(digestHex, boardingHash)
	if err != nil {
		return nil, err
	}
	return &ConnectorEnrollmentStatus{ConnectorType: row.Type, ConnectorPub: hex.EncodeToString(row.Pub), ConnectorFingerprint: row.Fingerprint, ConnectorPath: append([]uint32(nil), row.Path...), EnrollmentDigest: digestHex, DescriptorHash: combined}, nil
}
