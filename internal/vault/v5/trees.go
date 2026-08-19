package v5

import (
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
)

var padScript = []byte{0x6a}

// Checksig is the v5 tapscript leaf: OP_CHECKSIG for each pub.
func Checksig(pubs ...*btcec.PublicKey) ([]byte, error) {
	return checksig(pubs...)
}

func checksig(pubs ...*btcec.PublicKey) ([]byte, error) {
	script, err := (&arkscript.MultisigClosure{PubKeys: pubs}).Script()
	if err != nil {
		return nil, err
	}
	return script, nil
}

func csvChecksig(blocks uint32, pub *btcec.PublicKey) ([]byte, error) {
	c := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{pub}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: blocks},
	}
	return c.Script()
}

func pendingDelay(claimant string) uint32 {
	switch claimant {
	case "hardware":
		return 6
	case "phone":
		return 144
	default:
		return 288
	}
}

func familyClaimants(hasRecovery bool) []string {
	if hasRecovery {
		return []string{"phone", "hardware", "recovery"}
	}
	return []string{"phone", "hardware"}
}

func quarantineGuardians(claimant string, hasRecovery bool) []string {
	switch claimant {
	case "phone":
		if hasRecovery {
			return []string{"hardware", "recovery"}
		}
		return []string{"hardware"}
	case "hardware":
		if hasRecovery {
			return []string{"phone", "recovery"}
		}
		return []string{"phone"}
	default:
		return []string{"phone", "hardware"}
	}
}

func rolePub(roles map[string]*btcec.PublicKey, name string) (*btcec.PublicKey, error) {
	pub := roles[name]
	if pub == nil {
		return nil, fmt.Errorf("missing %s", name)
	}
	return pub, nil
}

// BuildQuarantine returns the 2-of-2 excluding claimant.
func BuildQuarantine(vaultID, kind, claimant, network string, phone, hardware, recovery *btcec.PublicKey) (addr string, pkScript []byte, err error) {
	return BuildQuarantineTemplate(vaultID, kind, claimant, network, Template, phone, hardware, recovery)
}

func BuildQuarantineTemplate(vaultID, kind, claimant, network, template string, phone, hardware, recovery *btcec.PublicKey) (addr string, pkScript []byte, err error) {
	internal, err := ContextInternalKeyTemplate(vaultID, kind, claimant, template)
	if err != nil {
		return "", nil, err
	}
	roles := map[string]*btcec.PublicKey{"phone": phone, "hardware": hardware, "recovery": recovery}
	names := quarantineGuardians(claimant, recovery != nil)
	var pubs []*btcec.PublicKey
	for _, name := range names {
		p, err := rolePub(roles, name)
		if err != nil {
			return "", nil, err
		}
		pubs = append(pubs, p)
	}
	script, err := checksig(pubs...)
	if err != nil {
		return "", nil, err
	}
	return taprootFromScripts(internal, [][]byte{script}, network)
}

// BuildPending returns CSV+claimant, two guardian 3-of-3s, padding.
func BuildPending(vaultID, kind, claimant, network string, phone, hardware, recovery, vaultTweak, arkadeTweak *btcec.PublicKey) (addr string, pkScript []byte, err error) {
	return BuildPendingTemplate(vaultID, kind, claimant, network, Template, false, phone, hardware, recovery, vaultTweak, arkadeTweak)
}

func BuildPendingTemplate(vaultID, kind, claimant, network, template string, serverFree bool, phone, hardware, recovery, vaultTweak, arkadeTweak *btcec.PublicKey) (addr string, pkScript []byte, err error) {
	internal, err := ContextInternalKeyTemplate(vaultID, kind, claimant, template)
	if err != nil {
		return "", nil, err
	}
	roles := map[string]*btcec.PublicKey{"phone": phone, "hardware": hardware, "recovery": recovery}
	claimantPub, err := rolePub(roles, claimant)
	if err != nil {
		return "", nil, err
	}
	claim, err := csvChecksig(pendingDelay(claimant), claimantPub)
	if err != nil {
		return "", nil, err
	}
	var clawbacks [][]byte
	var guardians []*btcec.PublicKey
	for _, g := range familyClaimants(recovery != nil) {
		if g == claimant {
			continue
		}
		gp, err := rolePub(roles, g)
		if err != nil {
			return "", nil, err
		}
		guardians = append(guardians, gp)
		cb, err := checksig(gp, vaultTweak, arkadeTweak)
		if err != nil {
			return "", nil, err
		}
		clawbacks = append(clawbacks, cb)
	}
	scripts := [][]byte{claim}
	scripts = append(scripts, clawbacks...)
	if serverFree {
		if len(guardians) == 0 {
			return "", nil, fmt.Errorf("server-free clawback requires a remaining key")
		}
		free, err := checksig(guardians...)
		if err != nil {
			return "", nil, err
		}
		scripts = append(scripts, free)
	}
	scripts = append(scripts, padScript)
	return taprootFromScripts(internal, scripts, network)
}
