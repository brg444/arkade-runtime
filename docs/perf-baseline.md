# Performance baseline

This baseline protects two intentionally bounded server paths while packages
are reorganized. It does not set machine-independent service objectives or
authorize changes to ledger integrity, fee selection, or policy semantics.

## Reference environment

- Runnable benchmark commit: `73c576e0e4ee42b7b95efc7f09dd06775adabb28`
- Production-code parent: `50a687d0982985fc06f3bd0313ca0e3e82df0f77`
- Go: `go1.26.6 darwin/arm64`
- Host: Apple M1, macOS 14.5 (`23F79`)
- Scheduler: `GOMAXPROCS=1`
- Samples: 10 per case, `-benchtime=500ms`

The reference command was:

```sh
GOMAXPROCS=1 go test ./internal/policy ./internal/application \
  -run '^$' \
  -bench 'Benchmark(SpentInPeriodHistory|SelectSpendVtxosFeeWork)$' \
  -benchmem -count=10 -benchtime=500ms
```

`BenchmarkSpentInPeriodHistory` measures the authenticated allowance scan at
100, 1,000, and 10,000 historical operations. `BenchmarkSelectSpendVtxosFeeWork`
measures a one-input zero-fee selection, the accepted 50-input fragmented edge
case, and rejection at the fixed fee-evaluation budget.

## Same-host results

The `ns/op samples` column preserves all ten observations. Allocation columns
show the observed range where a sample differed.

| Benchmark | ns/op samples | B/op | allocs/op |
| --- | --- | ---: | ---: |
| `SpentInPeriodHistory/rows_100` | 743176, 698103, 733040, 734534, 711303, 709012, 725057, 711359, 700501, 704808 | 250232 | 5042 |
| `SpentInPeriodHistory/rows_1000` | 6745784, 6778881, 6923233, 9959164, 8407754, 6897981, 7727694, 7140487, 7539211, 7132366 | 2482232–2482233 | 50042 |
| `SpentInPeriodHistory/rows_10000` | 69399359, 84133802, 81263065, 73721423, 71845386, 70203286, 81648979, 73123339, 76763979, 75480682 | 24802240–24802257 | 500042 |
| `SelectSpendVtxosFeeWork/one_input_zero_fee` | 2766, 2771, 3166, 2743, 2966, 2812, 2863, 2786, 2770, 3055 | 3264 | 49 |
| `SelectSpendVtxosFeeWork/fragmented_50_exact_fee` | 8835531, 8350026, 7621691, 8209779, 7630933, 9787772, 11659596, 8431586, 7672987, 9904116 | 9791386–9791396 | 132647–132648 |
| `SelectSpendVtxosFeeWork/bounded_rejection` | 27417169, 25866894, 25881695, 25967833, 26071962, 27202345, 29372884, 27161509, 25494047, 28183222 | 33590951–33590966 | 509843 |

## Review guidance

Compare base and candidate samples on the same otherwise-idle host, preferably
by alternating runs, and evaluate them with `benchstat`. Absolute numbers from
different machines or shared CI runners are incomparable.

A candidate needs investigation when `ns/op` regresses by more than 20 percent
and the comparison is statistically significant (`p < 0.05`). An increase of
more than 10 percent in `B/op` or `allocs/op` also needs investigation. Any
benchmark correctness failure blocks the change regardless of timing.

These thresholds are review guidance, not CI-enforced machine numbers. Explain
any deliberate performance tradeoff in its own change, outside a structural
refactor.
