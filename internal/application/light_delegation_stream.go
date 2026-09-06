package application

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/brg444/arkade-runtime/internal/policy"
)

func delegationStreamPhase(e lightDelegationEvent, batch string) (string, error) {
	if batch == "" {
		return "", nil
	}
	if tx := e.TreeTx; tx != nil && tx.ID == batch {
		if requireTxid(tx.Txid) != nil || tx.BatchIndex > 1 {
			return "", fmt.Errorf("Light delegation tree event identity")
		}
		return fmt.Sprintf("stream_tree_%d_%s", tx.BatchIndex, tx.Txid), nil
	}
	if n := e.TreeNonces; n != nil && n.ID == batch {
		if requireTxid(n.Txid) != nil {
			return "", fmt.Errorf("Light delegation nonce event identity")
		}
		return "stream_nonce_" + n.Txid, nil
	}
	if sig := e.TreeSignature; sig != nil && sig.ID == batch {
		if requireTxid(sig.Txid) != nil || sig.BatchIndex != 0 {
			return "", fmt.Errorf("Light delegation signature event identity")
		}
		return "stream_signature_" + sig.Txid, nil
	}
	if start := e.TreeSigningStarted; start != nil && start.ID == batch {
		return "stream_signing_started", nil
	}
	if final := e.BatchFinalization; final != nil && final.ID == batch {
		return "stream_finalization", nil
	}
	return "", nil
}

// Resume from our authenticated transcript, not a presumed Operator replay.
// Events never received before disconnect remain unavailable and ownership is
// retained. A completed signature or final forfeit is reused byte-for-byte.
func replayDelegationStream(ctx context.Context, saved *policy.LightDelegationSnapshot, live <-chan lightDelegationEvent) (<-chan lightDelegationEvent, error) {
	names := []string{}
	for phase := range saved.Events {
		if strings.HasPrefix(phase, "stream_") {
			names = append(names, phase)
		}
	}
	rank := func(name string) int {
		switch {
		case strings.HasPrefix(name, "stream_tree_"):
			return 0
		case name == "stream_signing_started":
			return 1
		case strings.HasPrefix(name, "stream_nonce_"):
			return 2
		case strings.HasPrefix(name, "stream_signature_"):
			return 3
		default:
			return 4
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := rank(names[i]), rank(names[j])
		if a != b {
			return a < b
		}
		return names[i] < names[j]
	})
	replay := make([]lightDelegationEvent, 0, len(names))
	for _, name := range names {
		var e lightDelegationEvent
		if err := json.Unmarshal([]byte(saved.Events[name].Evidence), &e); err != nil {
			return nil, err
		}
		replay = append(replay, e)
	}
	out := make(chan lightDelegationEvent, 8)
	go func() {
		defer close(out)
		for _, e := range replay {
			select {
			case out <- e:
			case <-ctx.Done():
				return
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-live:
				if !ok {
					return
				}
				select {
				case out <- e:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}
