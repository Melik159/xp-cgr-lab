# Inverse Benchmark v2 — Phase F Scaling Study

## Scope

This phase consolidates the observed Python, native CPU, CUDA, and Z3 SMT
results already frozen in Phases C, D, and E.

No new solver experiment is introduced here. Derived values are explicitly
separated from observed measurements.

## Observed measurements

### Python exhaustive search

| Instance | Tested | Elapsed (s) | Candidates/s | Verdict |
|---|---:|---:|---:|---|
| B00-K08 | 37 | 0.005090345 | 7,268.663 | PASS |
| B00-K12 | 1,511 | 0.256000451 | 5,902.333 | PASS |
| B00-K16 | 12,142 | 1.631135772 | 7,443.893 | PASS |
| B00-K20 | 710,990 | 125.921135190 | 5,646.312 | PASS |

### Native CPU exhaustive search

| Instance | Tested | Elapsed (s) | Candidates/s | Verdict |
|---|---:|---:|---:|---|
| B00-K20 | 710,990 | 0.399268444 | 1,780,731.762 | PASS |
| B00-K24 | 9,688,326 | 5.483564967 | 1,766,793.329 | PASS |
| B00-K28 | 197,789,713 | 120.548506147 | 1,640,747.939 | PASS |

### CUDA exhaustive search

| Instance | Scanned | GPU seconds | Candidates/s | Verdict |
|---|---:|---:|---:|---|
| B00-K28 | 201,326,592 | 0.272321793 | 739,296,661.042 | PASS |
| B00-K32 | 956,301,312 | 1.235399775 | 774,082,472.491 | PASS |

### Z3 SMT

| Instance | SMT status | Elapsed (s) | Phase status |
|---|---|---:|---|
| B00-K08 | sat | 5.728064427 | PASS |
| B00-K12 | sat | 177.404367996 | PASS |
| B00-K16 | unknown / timeout | 300.262312870 | INCOMPLETE |

## Cross-backend agreement

All successful reduced instances converge on:

`adb870799c7d3cc1ac3492d939ad290fda40163b`

The successful candidates passed the independent Phase-B verifier.

For K28, native CPU and CUDA also agree on:

`SOLUTION_COUNTER=197789712`

## Derived comparisons

Observed K28 CUDA throughput divided by observed K28 native CPU throughput:

`739,296,661.042 / 1,640,747.939 ≈ 450.6`

This is a descriptive ratio for the two recorded runs only.

Observed Z3 elapsed-time ratio from K08 to K12:

`177.404367996 / 5.728064427 ≈ 30.97`

Four additional unknown bits increased the search-space size by 16×, while the
observed SMT wall time increased by about 31×. K16 then exceeded the 300-second
budget.

## Exhaustive-search planning projections

The following values are **not measurements**. They use the observed K32 CUDA
throughput:

`R = 774,082,472.491 candidates/s`

and assume constant throughput with increasing search size.

| Unknown bits | Full scan | Mean solution time if uniformly distributed |
|---:|---:|---:|
| 32 | 5.55 s | 2.77 s |
| 40 | 23.7 min | 11.8 min |
| 48 | 4.21 days | 2.10 days |
| 56 | 2.95 years | 1.47 years |
| 64 | 755 years | 378 years |
| 80 | 49.5 million years | 24.7 million years |
| 160 | 5.98e31 years | 2.99e31 years |

These projections are arithmetic extrapolations only. They do not account for
multi-GPU scaling, optimized kernels, ASICs, algorithmic improvements,
cryptanalytic shortcuts, or future architectures.

## Interpretation

The observed reduced benchmark separates three regimes:

1. Python exhaustive search is suitable for correctness validation only.
2. Native CPU exhaustive search scales predictably through the tested K28 case.
3. CUDA exhaustive search is highly effective for reduced spaces through K32,
   reaching roughly 0.74–0.77 billion candidates/s on one Tesla T4 in the
   observed runs.
4. The tested Z3 formulation is already impractical relative to exhaustive
   search by K12 and reaches timeout at K16 under the 300-second budget.

This does **not** establish that full 160-bit inversion is impossible. It does
show that none of the tested generic methods changes the fundamental scaling
enough to make the real 160-bit instance practically reachable.

## Phase F verdict

`PHASE_F_SCALING_STUDY=PASS`

Meaning:

- CPU, CUDA, and SMT measurements were consolidated;
- successful backends agree on the same reconstructed XVAL;
- observed and extrapolated quantities are explicitly separated;
- the tested methods show no practical route from the reduced benchmark to the
  full 160-bit provider preimage.
