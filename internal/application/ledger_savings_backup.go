package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/wire"
)

type LedgerSavingsRegistration struct {
	Name           string                     `json:"name"`
	Version        int                        `json:"version"`
	ContextDigest  string                     `json:"contextDigest"`
	WalletID       string                     `json:"walletId"`
	WalletHMAC     string                     `json:"walletHmac"`
	WalletPolicy   savings.LedgerWalletPolicy `json:"walletPolicy"`
	ReceiveAddress string                     `json:"receiveAddress"`
	ChangeAddress  string                     `json:"changeAddress"`
}
type LedgerSavingsPhoneSeedBackup struct {
	Name          string                      `json:"name"`
	Version       int                         `json:"version"`
	Purpose       string                      `json:"purpose"`
	ContextDigest string                      `json:"contextDigest"`
	PhoneOrigin   savings.LedgerAccountOrigin `json:"phoneOrigin"`
	Salt          string                      `json:"salt"`
	Nonce         string                      `json:"nonce"`
	Ciphertext    string                      `json:"ciphertext"`
}
type LedgerSavingsBackup struct {
	Registration    LedgerSavingsRegistration    `json:"registration"`
	PhoneSeedBackup LedgerSavingsPhoneSeedBackup `json:"phoneSeedBackup"`
}

// Ledger wallet descriptors contain multipath angle brackets. Version6 uses
// JSON.stringify-compatible ASCII encoding rather than Go's HTML escaping.
// Prior binding versions retain their original json.Marshal preimages.
func marshalLedgerSavingsJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

func ledgerSavingsWalletPolicyID(policy savings.LedgerWalletPolicy) string {
	var root func([][]byte) []byte
	root = func(leaves [][]byte) []byte {
		if len(leaves) == 0 {
			return make([]byte, 32)
		}
		if len(leaves) == 1 {
			return leaves[0]
		}
		split := 1
		for split*2 < len(leaves) {
			split *= 2
		}
		raw := append([]byte{1}, root(leaves[:split])...)
		raw = append(raw, root(leaves[split:])...)
		sum := sha256.Sum256(raw)
		return sum[:]
	}
	var leaves [][]byte
	for _, key := range policy.KeysInfo {
		sum := sha256.Sum256(append([]byte{0}, []byte(key)...))
		leaves = append(leaves, sum[:])
	}
	var out bytes.Buffer
	out.WriteByte(2)
	_ = wire.WriteVarInt(&out, 0, uint64(len(policy.Name)))
	out.WriteString(policy.Name)
	_ = wire.WriteVarInt(&out, 0, uint64(len(policy.DescriptorTemplate)))
	descriptor := sha256.Sum256([]byte(policy.DescriptorTemplate))
	out.Write(descriptor[:])
	_ = wire.WriteVarInt(&out, 0, uint64(len(policy.KeysInfo)))
	out.Write(root(leaves))
	digest := sha256.Sum256(out.Bytes())
	return hex.EncodeToString(digest[:])
}
func (s *Service) canonicalLedgerSavingsBackup(cred *policy.Credential, payload *LedgerSavingsBackup) (string, string, string, error) {
	if cred.TemplateVersion != savings.LedgerNativeTemplate {
		if payload != nil {
			return "", "", "", fmt.Errorf("Ledger backup requires enrolled Ledger Savings")
		}
		return "", "", "", nil
	}
	if payload == nil {
		return "", "", "", fmt.Errorf("Ledger Savings encrypted seed and registration required")
	}
	enrolled, family, err := s.verifiedLedgerSavings(cred)
	if err != nil {
		return "", "", "", err
	}
	digest, err := savings.LedgerSavingsContextDigest(enrolled.Context)
	if err != nil {
		return "", "", "", err
	}
	contextDigest := hex.EncodeToString(digest)
	r, b := payload.Registration, payload.PhoneSeedBackup
	if r.Name != "vaulted-ledger-registration" || r.Version != 1 || r.ContextDigest != contextDigest || r.WalletID != ledgerSavingsWalletPolicyID(family.WalletPolicy) || !reflect.DeepEqual(r.WalletPolicy, family.WalletPolicy) || r.ReceiveAddress != family.Receive.Address || r.ChangeAddress != family.Change.Address {
		return "", "", "", fmt.Errorf("Ledger Savings registration mismatch")
	}
	if _, err := decodeFixedHex(r.WalletHMAC, 32, "Ledger registration HMAC"); err != nil {
		return "", "", "", err
	}
	if b.Name != "vaulted-ledger-savings-phone-seed" || b.Version != 1 || b.Purpose != "passkey-prf" || b.ContextDigest != contextDigest || !reflect.DeepEqual(b.PhoneOrigin, enrolled.Context.Phone) {
		return "", "", "", fmt.Errorf("Ledger Savings encrypted seed context mismatch")
	}
	for _, value := range []struct {
		value string
		size  int
		name  string
	}{{b.Salt, 32, "Ledger seed salt"}, {b.Nonce, 12, "Ledger seed nonce"}, {b.Ciphertext, 48, "Ledger encrypted seed"}} {
		if _, err := decodeFixedHex(value.value, value.size, value.name); err != nil {
			return "", "", "", err
		}
	}
	raw, err := marshalLedgerSavingsJSON(payload)
	if err != nil {
		return "", "", "", err
	}
	if len(raw) > 8192 {
		return "", "", "", fmt.Errorf("Ledger Savings backup too large")
	}
	return string(raw), contextDigest, enrolled.DescriptorHash, nil
}
func (s *Service) recoverLedgerSavingsBackup(cred *policy.Credential, binding string) (*LedgerSavingsBackup, error) {
	var saved recoveryBinding
	if err := json.Unmarshal([]byte(binding), &saved); err != nil {
		return nil, err
	}
	if cred.TemplateVersion != savings.LedgerNativeTemplate {
		if saved.LedgerSavingsBackup != "" || saved.LedgerSavingsContextDigest != "" || saved.LedgerSavingsDescriptorHash != "" {
			return nil, fmt.Errorf("unexpected Ledger Savings backup")
		}
		return nil, nil
	}
	if saved.Version != 6 {
		return nil, fmt.Errorf("Ledger Savings binding version mismatch")
	}
	var backup LedgerSavingsBackup
	decoder := json.NewDecoder(bytes.NewBufferString(saved.LedgerSavingsBackup))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&backup); err != nil {
		return nil, err
	}
	raw, digest, descriptor, err := s.canonicalLedgerSavingsBackup(cred, &backup)
	if err != nil {
		return nil, err
	}
	if raw != saved.LedgerSavingsBackup || digest != saved.LedgerSavingsContextDigest || descriptor != saved.LedgerSavingsDescriptorHash {
		return nil, fmt.Errorf("Ledger Savings stored backup mismatch")
	}
	return &backup, nil
}
