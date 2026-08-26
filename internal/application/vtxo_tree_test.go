package application

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestVaultBoardRequiresFourDistinctSigningRoles(t *testing.T) {
	roles := make([]*btcec.PublicKey, 4)
	for i := range roles {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		roles[i] = priv.PubKey()
	}
	if err := requireDistinctVaultBoardRoles(roles[0], roles[1], roles[2], roles[3]); err != nil {
		t.Fatalf("distinct roles rejected: %v", err)
	}
	for i := range roles {
		for j := i + 1; j < len(roles); j++ {
			colliding := append([]*btcec.PublicKey(nil), roles...)
			colliding[j] = colliding[i]
			if err := requireDistinctVaultBoardRoles(colliding[0], colliding[1], colliding[2], colliding[3]); err == nil {
				t.Fatalf("roles %d and %d were allowed to share a key", i, j)
			}
		}
	}
}
