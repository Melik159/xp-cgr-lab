# Inverse Benchmark v2 — Phase C CPU Baseline

## Scope

This report records the observed CPU exhaustive-search baseline for the reduced
provider preimage benchmark. It does not generalize beyond the tested host,
compiler/runtime, challenge instance, and code revisions.

Reference instance family: `B00-K08` through `B00-K28`.

Recovered XVAL for every successful run:

`adb870799c7d3cc1ac3492d939ad290fda40163b`

Independent Phase-B verification of the K28 solution:

- `KNOWN_MASK_MATCH=PASS`
- `OUT_A_MATCH=PASS`
- `OUT_B_MATCH=PASS`
- `VERDICT=PASS`

## Observed results

| Instance | Backend | Search space | Tested | Solution counter | Elapsed (s) | Candidates/s | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| B00-K08 | Python | 256 | 37 | 36 | 0.005090345 | 7,268.663 | PASS |
| B00-K12 | Python | 4,096 | 1,511 | 1,510 | 0.256000451 | 5,902.333 | PASS |
| B00-K16 | Python | 65,536 | 12,142 | 12,141 | 1.631135772 | 7,443.893 | PASS |
| B00-K20 | Python | 1,048,576 | 710,990 | 710,989 | 125.921135190 | 5,646.312 | PASS |
| B00-K20 | Native C (`-O3 -march=native`) | 1,048,576 | 710,990 | 710,989 | 0.399268444 | 1,780,731.762 | FOUND |
| B00-K24 | Native C (`-O3 -march=native`) | 16,777,216 | 9,688,326 | 9,688,325 | 5.483564967 | 1,766,793.329 | FOUND |
| B00-K28 | Native C (`-O3 -march=native`) | 268,435,456 | 197,789,713 | 197,789,712 | 120.548506147 | 1,640,747.939 | FOUND |

## Cross-checks

- Python K20 and native K20 recovered the same `SOLUTION_COUNTER=710989`.
- Python K20 and native K20 recovered the same XVAL.
- K24 and K28 recovered the same XVAL.
- The K28 XVAL was re-submitted to the independent Phase-B verifier and passed all
  mask and cryptographic checks.

## Derived performance note

For the same K20 instance, the observed native-C throughput was approximately
315.4× the observed Python throughput:

`1,780,731.762 / 5,646.312 ≈ 315.4`

This ratio is descriptive of these runs only; it is not a platform-independent
speedup claim.

## K32 status

`B00-K32` was not exhaustively run during Phase C.

Using the observed K28 native throughput only as a rough planning estimate,
a complete 2^32 scan would be on the order of tens of minutes on this host.
This is an extrapolation, not an experimental result.

## Phase C verdict

`PHASE_C_CPU_BASELINE=PASS`

Meaning:

1. exhaustive reduced-bit search recovered the expected XVAL through K28;
2. the native and Python implementations agreed on overlapping K20 evidence;
3. the K28 result passed the independent oracle-free verifier;
4. K32 remains intentionally unmeasured in this phase.
