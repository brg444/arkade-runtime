package rolling

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unicode/utf8"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// AuthorizationDigest binds the passkey's companion device proof to one vault,
// complete contract tree and exact transaction. It grants no signing capability.
func AuthorizationDigest(contract *Contract, vault, operationID string) ([32]byte, error) {
	c, err := canonicalContract(contract)
	if err != nil {
		return [32]byte{}, err
	}
	if vault == "" || len(vault) > 1024 || !utf8.ValidString(vault) {
		return [32]byte{}, fmt.Errorf("invalid rolling vault identity")
	}
	id, err := chainhash.NewHashFromStr(operationID)
	if err != nil || id.String() != operationID {
		return [32]byte{}, fmt.Errorf("invalid rolling operation identity")
	}
	payload := []byte(RollingProgram + "\x00authorize\x00")
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(vault)))
	payload = append(payload, []byte(vault)...)
	payload = append(payload, c.PkScript...)
	payload = append(payload, id[:]...)
	return sha256.Sum256(payload), nil
}
