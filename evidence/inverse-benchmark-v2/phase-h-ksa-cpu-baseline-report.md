# Phase H — RC4 KSA CPU Baseline

## Scope

This report records the observed native-CPU brute-force baseline for the
Phase-H reduced RC4-KSA inverse benchmark on instance family `H-KSA-00`.

It does **not** establish recovery of the full 640-bit `new_state`, nor recovery
from disk/RAM forensic artifacts. It validates the reduced search architecture
and records observed CPU performance for the selected host/run.

## Pinned inputs

- Parent H-KSA challenge SHA-256:
  `78867366dc5f0659375ffdf16d8a9881cf10a99e3a26e069659dd45568ff5b35`
- Reduced H-KSA challenge SHA-256:
  `6cdd7ead421ad71a376eeb52a746b4f67cc9de43b546c6f58cf66a3acd522c27`
- Native solver source SHA-256:
  `20f6333c2857f3b326612a50c70d5198be507f6cd778286c1a57d5a1645c2cc7`
- Runner SHA-256:
  `2f4b19584ab399d5bc5eca9c78d2efd5778a67c0a901f22ec8ee41a14b152b15`

## Build

Observed build command:

`cc -O3 -std=c11 -Wall -Wextra -o tools/solve_phase_h_ksa_native tools/solve_phase_h_ksa_native.c`

The compiled binary is a host artifact and is not required to be committed.

## Observed results

| Instance | Search space | Tested | Elapsed (s) | Candidates/s | Solution counter |
|---|---:|---:|---:|---:|---:|
| K08 | 256 | 191 | 0.000187673 | 1,017,729.408 | 190 |
| K12 | 4,096 | 603 | 0.001116933 | 539,871.316 | 602 |
| K16 | 65,536 | 50,692 | 0.066556476 | 761,638.882 | 50,691 |
| K20 | 1,048,576 | 125,455 | 0.152168835 | 824,446.083 | 125,454 |
| K24 | 16,777,216 | 8,900,810 | 10.934614296 | 814,003.106 | 8,900,809 |
| K28 | 268,435,456 | 12,462,088 | 15.471230034 | 805,500.789 | 12,462,087 |
| K32 | 4,294,967,296 | 225,671,413 | 303.738363615 | 742,979.617 | 225,671,412 |

All seven runs returned:

- `SEARCH_STATUS=FOUND`
- `KNOWN_MASK_MATCH=PASS`
- `RC4_KSA_MATCH=PASS`
- `VERDICT=PASS`
- `INDEPENDENT_VERIFIER_EXIT_CODE=0`
- `SOLVER_EXIT_CODE=0`

The recovered 80-byte candidate was identical across K08 through K32 and was
accepted by the independent reduced H-KSA verifier.

## Interpretation

The very short K08/K12 runs are dominated by timer/startup noise and should not
be used as stable throughput measurements.

For the longer native runs, observed throughput was:

- K20: 824,446.083 candidates/s
- K24: 814,003.106 candidates/s
- K28: 805,500.789 candidates/s
- K32: 742,979.617 candidates/s

The aggregate throughput over K20+K24+K28+K32, computed as total tested divided
by total elapsed, is `748,296.934` candidates/s.

This aggregate is descriptive only. It is not a calibrated hardware benchmark
and does not establish asymptotic performance. The K32 rate is lower than
K24/K28 on this observed run; no causal explanation is asserted from these data
alone.

## K32 result

The precomputed oracle counter for K32 was:

`225671412`

The actual solver result was:

- `TESTED=225671413`
- `SOLUTION_COUNTER=225671412`
- `ELAPSED_SECONDS=303.738363615`
- `CANDIDATES_PER_SECOND=742979.617`

Thus the solver enumeration order and reduced-bit encoding agreed exactly with
the independently computed oracle position.

## Methodological status

This phase demonstrates:

1. deterministic construction of reduced RC4-KSA inverse instances;
2. exhaustive native-CPU search over the hidden-bit subspace;
3. recovery of the correct reduced candidate through K32;
4. independent forward verification of every recovered candidate.

It does **not** demonstrate tractability of the full 640-bit inverse KSA
problem. Any extrapolation from K32 to larger hidden-bit counts must be labeled
as arithmetic projection rather than measurement.

## Verdict

`PHASE_H_KSA_CPU_BASELINE=PASS`
