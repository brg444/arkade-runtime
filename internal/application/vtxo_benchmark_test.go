package application

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/brg444/vaulted-guardian/internal/apperr"
	"github.com/brg444/vaulted-guardian/internal/ports"
	"github.com/brg444/vaulted-guardian/internal/program"
)

func BenchmarkSelectSpendVtxosFeeWork(b *testing.B) {
	pkScript := []byte{0x51, 0x20, 0x01}
	destScript := []byte{0x51, 0x20, 0x02}

	tests := []struct {
		name       string
		vtxos      []ports.ResolvedVtxo
		amountSats uint64
		feePolicy  ports.IntentFeePolicy
		wantInputs int
		wantFee    uint64
		wantChange uint64
		wantBusy   bool
	}{
		{
			name: "one_input_zero_fee",
			vtxos: []ports.ResolvedVtxo{{
				Txid: fmt.Sprintf("%064x", 1), ValueSats: 30_000, Script: pkScript,
			}},
			amountSats: 20_000,
			wantInputs: 1,
			wantChange: 10_000,
		},
		{
			name:       "fragmented_50_exact_fee",
			vtxos:      benchmarkResolvedVtxos(50, 1_000, pkScript),
			amountSats: 49_001,
			feePolicy:  ports.IntentFeePolicy{OffchainOutput: "250.0"},
			wantInputs: 50,
			wantFee:    500,
			wantChange: 499,
		},
		{
			name:       "bounded_rejection",
			vtxos:      benchmarkResolvedVtxos(5, 10_000, pkScript),
			amountSats: 1_000,
			feePolicy:  ports.IntentFeePolicy{OffchainOutput: "5001.0"},
			wantBusy:   true,
		},
	}

	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			estimator, _, err := newVtxoFeeEstimator(test.feePolicy)
			if err != nil {
				b.Fatal(err)
			}
			svc := &Service{ArkResolver: benchmarkArkResolver{vtxos: test.vtxos}}
			ctx := context.Background()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				coins, fee, change, err := svc.selectSpendVtxos(
					ctx, pkScript, destScript, test.amountSats,
					uint64(program.AbsoluteFeeCeiling), estimator,
				)
				if test.wantBusy {
					if !errors.Is(err, apperr.ErrBusy) {
						b.Fatalf("bounded fee selection = %v, want BUSY", err)
					}
					continue
				}
				if err != nil {
					b.Fatal(err)
				}
				if len(coins) != test.wantInputs || fee != test.wantFee || change != test.wantChange {
					b.Fatalf(
						"fee selection = inputs %d fee %d change %d, want %d/%d/%d",
						len(coins), fee, change, test.wantInputs, test.wantFee, test.wantChange,
					)
				}
			}
		})
	}
}

type benchmarkArkResolver struct {
	vtxos []ports.ResolvedVtxo
}

func (r benchmarkArkResolver) SpendableVtxos(context.Context, []byte) ([]ports.ResolvedVtxo, error) {
	return append([]ports.ResolvedVtxo(nil), r.vtxos...), nil
}

func (benchmarkArkResolver) IntentFeePolicy(context.Context) (ports.IntentFeePolicy, error) {
	return ports.IntentFeePolicy{}, nil
}

func (benchmarkArkResolver) SubmittedVtxoState(context.Context, []byte, []ports.ResolvedVtxo, string, *uint32, uint64) (ports.SubmittedVtxoState, error) {
	return ports.SubmittedVtxoPending, nil
}

func (benchmarkArkResolver) CheckpointTapscript() []byte { return nil }
func (benchmarkArkResolver) OperatorSignerPub() []byte   { return nil }
func (benchmarkArkResolver) Network() string             { return program.NetworkMutinynet }

func benchmarkResolvedVtxos(count int, valueSats uint64, script []byte) []ports.ResolvedVtxo {
	vtxos := make([]ports.ResolvedVtxo, count)
	for i := range vtxos {
		vtxos[i] = ports.ResolvedVtxo{
			Txid: fmt.Sprintf("%064x", i+1), ValueSats: valueSats, Script: script,
		}
	}
	return vtxos
}
