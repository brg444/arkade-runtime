package rolling

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Descriptor is the canonical public enrollment and recovery record.
// Keys use compressed public-key encodings and contain no signing material.
type Descriptor struct {
	Program                                                string
	Parameters                                             RollingParameters
	Tier                                                   string
	ExitDelaySeconds                                       uint32
	User, Guardian, Emulator, Operator, Hardware, Recovery string
}

func EncodeDescriptor(contract *Contract) ([]byte, error) {
	c, err := canonicalContract(contract)
	if err != nil {
		return nil, err
	}
	encode := func(k *btcec.PublicKey) string {
		if k == nil {
			return ""
		}
		return hex.EncodeToString(k.SerializeCompressed())
	}
	d := Descriptor{Program: RollingProgram, Parameters: c.Parameters, Tier: c.Tier, ExitDelaySeconds: c.ExitDelaySeconds, User: encode(c.Keys.User), Guardian: encode(c.Keys.Guardian), Emulator: encode(c.Keys.Emulator), Operator: encode(c.Keys.Operator), Hardware: encode(c.Keys.Hardware), Recovery: encode(c.Keys.Recovery)}
	return json.Marshal(d)
}

func DecodeDescriptor(raw []byte) (*Contract, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return nil, fmt.Errorf("descriptor size")
	}
	var d Descriptor
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	if d.Program != RollingProgram {
		return nil, fmt.Errorf("unknown rolling program")
	}
	var keys [6]*btcec.PublicKey
	for i, encoded := range []string{d.User, d.Guardian, d.Emulator, d.Operator, d.Hardware, d.Recovery} {
		if encoded == "" {
			continue
		}
		raw, err := hex.DecodeString(encoded)
		if err != nil || len(raw) != 33 || encoded != hex.EncodeToString(raw) {
			return nil, fmt.Errorf("noncanonical descriptor key")
		}
		keys[i], err = btcec.ParsePubKey(raw)
		if err != nil {
			return nil, err
		}
	}
	c, err := BuildContract(d.Parameters, ContractKeys{User: keys[0], Guardian: keys[1], Emulator: keys[2], Operator: keys[3], Hardware: keys[4], Recovery: keys[5]}, d.Tier, d.ExitDelaySeconds)
	if err != nil {
		return nil, err
	}
	canonical, err := EncodeDescriptor(c)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, raw) {
		return nil, fmt.Errorf("noncanonical descriptor")
	}
	return c, nil
}
