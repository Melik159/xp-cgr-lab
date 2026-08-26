# Inverse Benchmark v2 — Phase E Z3 SMT Baseline

## Scope

This report records the observed Z3 SMT baseline for the reduced provider
preimage benchmark using the full reduced relation:

- `out_a = G(xval)`
- `out_b = G((xval + out_a + 1) mod 2^160)`

The solver is oracle-free: it reads only the reduced challenge and the
independent Phase-B verifier. It does not read `events.jsonl`, AUX values, or
`inverse-benchmark-v1`.

Solver version observed:

`Z3_VERSION=5.1.0`

Timeout budget:

`TIMEOUT_MS=300000`

## Observed results

| Instance | Search space | SMT status | Elapsed (s) | Solution counter | Final verifier | Phase-E status |
|---|---:|---|---:|---:|---|---|
| B00-K08 | 256 | sat | 5.728064427 | 36 | PASS | PASS |
| B00-K12 | 4,096 | sat | 177.404367996 | 1,510 | PASS | PASS |
| B00-K16 | 65,536 | unknown | 300.262312870 | — | — | INCOMPLETE |

Recovered XVAL for the successful K08 and K12 runs:

`adb870799c7d3cc1ac3492d939ad290fda40163b`

For both successful runs, the independent Phase-B verifier returned:

- `FINAL_KNOWN_MASK=PASS`
- `FINAL_OUT_A=PASS`
- `FINAL_OUT_B=PASS`
- `FINAL_VERDICT=PASS`

For K16, Z3 returned:

- `SMT_STATUS=unknown`
- `UNKNOWN_REASON=timeout`

## Interpretation

Under this exact encoding, solver version, host, and 300-second timeout budget:

- K08 is solved;
- K12 is solved;
- K16 does not complete within the budget.

The measured transition from K08 to K12 is strongly superlinear in wall time:
adding four unknown bits increased elapsed time from about 5.73 s to about
177.40 s. K16 then exceeded the fixed 300 s budget.

This is an empirical property of this formulation and run configuration. It is
not a general impossibility result for SMT, Z3, SHA-1 preimages, or alternative
encodings/solvers.

## Phase E verdict

`PHASE_E_Z3_BASELINE=PASS`

Meaning:

1. the full reduced relation was encoded and solved correctly at K08 and K12;
2. successful candidates matched the same XVAL recovered by exhaustive search;
3. each successful candidate passed the independent Phase-B verifier;
4. K16 established an observed timeout boundary for this formulation and
   300-second budget;
5. no K20+ run is required for this baseline because K16 already crossed the
   defined timeout boundary.

`B00-K16` remains `INCOMPLETE`, not `UNSAT`.
