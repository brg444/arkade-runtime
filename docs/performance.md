# Performance checks

The policy benchmarks measure authenticated allowance scans and bounded input
selection. Run comparable revisions on the same otherwise idle machine:

```sh
GOMAXPROCS=1 go test ./internal/policy ./internal/application \
  -run '^$' \
  -bench 'Benchmark(SpentInPeriodHistory|SelectSpendVtxosFeeWork)$' \
  -benchmem -count=10 -benchtime=500ms
```

Compare samples with `benchstat`, including allocations and variation.
Measurements from different machines or shared CI runners are not directly
comparable. Preserve MAC-before-use checks, fee semantics, input bounds, and
policy-sequence ordering when changing performance-sensitive code.
