# Inverse Benchmark v2 — Phase D CUDA Baseline

## Scope

This report records the observed Kaggle CUDA exhaustive-search results for the
reduced provider preimage benchmark.

Pinned repository commit:

`092d116c6c154980851f85652f02d5ad14049db5`

Pinned reduced challenge SHA-256:

`d01cf89e1a052ea992a4227fc2005a3c3bbe47b59ba7adf7a829c44ddaa94605`

Original Kaggle results archive SHA-256:

`c2d5c7690ff97731e2040b7414b8b894924c37b3df0c125ebf4897e1e4b29b9e`

CUDA source SHA-256:

`9d5e4199a87e4bab1216c73befe5bd1d00a99d2dffca8328512f9c287ba154b5`

The Kaggle run loaded only the reduced challenge and the independent Phase-B
verifier from the pinned commit. It did not load `events.jsonl`, AUX values, or
the v1 oracle-bearing trace.

## Environment

- GPU used by solver: Tesla T4
- Compute capability: 7.5
- Multiprocessors: 40
- Driver reported by NVIDIA-SMI: 580.159.04
- CUDA reported by NVIDIA-SMI: 13.0
- `nvcc` compilation: PASS
- Kaggle exposed two Tesla T4 devices; the solver explicitly used device 0 only.

## Observed results

| Instance | Search space | Scanned | GPU seconds | Wall seconds | Candidates/s | Solution counter | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| B00-K28 | 268,435,456 | 201,326,592 | 0.272321793 | 0.272950784 | 739,296,661.042 | 197,789,712 | PASS |
| B00-K32 | 4,294,967,296 | 956,301,312 | 1.235399775 | 1.238907428 | 774,082,472.491 | 946,169,713 | PASS |

Recovered XVAL for both runs:

`adb870799c7d3cc1ac3492d939ad290fda40163b`

For both K28 and K32, the candidate was passed to the independent Phase-B
verifier and produced:

- `KNOWN_MASK_MATCH=PASS`
- `OUT_A_MATCH=PASS`
- `OUT_B_MATCH=PASS`
- `VERDICT=PASS`

## Result artifact hashes

- `phase-d-b00-k28-result.json`
  - SHA-256: `41e708293c5f4e828694ae684ef2ce26a91cfad68b95c1105f78d4a2c933e4fc`
- `phase-d-b00-k32-result.json`
  - SHA-256: `cc9041381591f6cde7fdea7abfe1fd1a77ee2b25bd84ae7877938f49043358f6`
- `solve_inverse_gpu.cu`
  - SHA-256: `9d5e4199a87e4bab1216c73befe5bd1d00a99d2dffca8328512f9c287ba154b5`

## Cross-checks

- K28 CUDA recovered the same `SOLUTION_COUNTER=197789712` and the same XVAL
  as the Phase-C native CPU run.
- K32 recovered that same XVAL while solving a 32-bit reduced instance.
- The K32 search stopped after the chunk containing the solution, so
  `SCANNED=956301312` is greater than `SOLUTION_COUNTER+1=946169714`.
- The throughput values above are observed for these runs only and are not
  generalized to other GPUs or configurations.

## Derived comparison

Using the observed native K28 Phase-C rate of `1,640,747.939 candidates/s`
and the observed CUDA K28 rate of `739,296,661.042 candidates/s`, the
descriptive throughput ratio for these two runs is approximately 450.6x.

This is a run-to-run comparison, not a hardware-independent speedup claim.

## Phase D verdict

`PHASE_D_CUDA_BASELINE=PASS`

Meaning:

1. the CUDA solver compiled successfully on Kaggle;
2. it recovered the known reduced-preimage solution at K28 and K32;
3. K28 matched the native CPU solution counter and XVAL;
4. both GPU solutions passed the independent Phase-B verifier;
5. the solver operated on the reduced challenge without consuming the runtime
   oracle-bearing trace.
