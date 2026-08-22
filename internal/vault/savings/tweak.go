package savings

import (
	"fmt"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
)

func tweakByArkScript(base *btcec.PublicKey, script []byte) (*btcec.PublicKey, error) {
	if base == nil {
		return nil, fmt.Errorf("tweak base required")
	}
	pub := arkade.ComputeArkadeScriptPublicKey(base, arkade.ArkadeScriptHash(script))
	if pub == nil {
		return nil, fmt.Errorf("Arkade tweak is degenerate")
	}
	return pub, nil
}

func tweakPair(vaultBase, arkadeBase *btcec.PublicKey, script []byte) (vault, ark *btcec.PublicKey, err error) {
	vault, err = tweakByArkScript(vaultBase, script)
	if err != nil {
		return nil, nil, err
	}
	ark, err = tweakByArkScript(arkadeBase, script)
	if err != nil {
		return nil, nil, err
	}
	return vault, ark, nil
}
