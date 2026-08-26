# Phase H — RC4 KSA CUDA Baseline (Kaggle T4)

## Scope

This report records the observed CUDA baseline for the Phase-H reduced RC4-KSA
inverse benchmark on Kaggle using Tesla T4 GPU device 0.

The run is pinned to:

- repository commit:
  `b4216cf479ceb4f44b9c3d399e8297aac48440a9`
- reduced H-KSA challenge SHA-256:
  `6cdd7ead421ad71a376eeb52a746b4f67cc9de43b546c6f58cf66a3acd522c27`
- CUDA source SHA-256:
  `ee1394edfe6374386e155db9b180481936164dd2487525f4e7b08238568f0db8`

The solver uses CUDA device 0 only.

## Environment

Observed environment:

- GPU: Tesla T4
- GPU count visible: 2
- device used by solver: 0
- compute capability: 7.5
- multiprocessors: 40
- driver: 580.159.04
- NVIDIA-SMI CUDA runtime report: 13.0
- nvcc: CUDA 12.8, V12.8.93

The presence of a second visible T4 does not imply it participated in the
measurement.

## Input gate and build

Observed:

- `PINNED_COMMIT=b4216cf479ceb4f44b9c3d399e8297aac48440a9`
- `CHALLENGE_SHA256=6cdd7ead421ad71a376eeb52a746b4f67cc9de43b546c6f58cf66a3acd522c27`
- `INPUT_GATE=PASS`
- `CUDA_SOURCE_SHA256=ee1394edfe6374386e155db9b180481936164dd2487525f4e7b08238568f0db8`
- `CUDA_BUILD=PASS`

The nvcc warning about future removal of offline compilation support for
architectures prior to sm_75 is informational for this run. The observed T4 is
compute capability 7.5.

## K28 observed result

- `SEARCH_SPACE=268435456`
- `CHUNK_SIZE=4194304`
- `BLOCK_SIZE=128`
- `SCANNED=12582912`
- `GPU_SECONDS=1.677722961`
- `WALL_SECONDS=1.677934349`
- `CANDIDATES_PER_SECOND=7499993.914`
- `SEARCH_STATUS=FOUND`
- `SOLUTION_COUNTER=12462087`
- `KNOWN_MASK_MATCH=PASS`
- `RC4_KSA_MATCH=PASS`
- `VERDICT=PASS`
- `K28_GPU_VERDICT=PASS`

The solution counter matches the previously observed native-CPU K28 result:
`12462087`.

The GPU scanned a full chunk through the chunk containing the solution, so
`SCANNED` is greater than `SOLUTION_COUNTER + 1`. This is expected from the
chunked kernel design and should not be interpreted as the exact number of
candidate indices preceding the solution.

## K32 observed result

- `SEARCH_SPACE=4294967296`
- `CHUNK_SIZE=4194304`
- `BLOCK_SIZE=128`
- `SCANNED=226492416`
- `GPU_SECONDS=35.798743103`
- `WALL_SECONDS=35.801641152`
- `CANDIDATES_PER_SECOND=6326825.926`
- `SEARCH_STATUS=FOUND`
- `SOLUTION_COUNTER=225671412`
- `KNOWN_MASK_MATCH=PASS`
- `RC4_KSA_MATCH=PASS`
- `VERDICT=PASS`
- `K32_GPU_VERDICT=PASS`

The solution counter matches the previously observed native-CPU K32 result:
`225671412`.

## Descriptive CPU/GPU comparison

Previously frozen native-CPU measurements:

- K28 CPU: `805500.789` candidates/s
- K32 CPU: `742979.617` candidates/s

Observed CUDA/CPU throughput ratios for these specific runs are approximately:

- K28: `9.31x`
- K32: `8.52x`

These ratios are descriptive comparisons between the recorded runs only. They
are not normalized hardware benchmarks and should not be generalized to other
GPUs, CPUs, compiler versions, thermal states, or solver implementations.

## Verifier-path correction

The first K28 CUDA search succeeded but the independent verifier initially
failed to start because the verifier's default challenge path was the local
host path:

`/home/hal/xp-cgr-lab/evidence/inverse-benchmark-v2/phase-h-ksa-reduced-challenges.json`

That path does not exist in the Kaggle checkout.

The notebook was corrected to invoke the verifier with:

`--challenge /kaggle/working/xp-cgr-lab/evidence/inverse-benchmark-v2/phase-h-ksa-reduced-challenges.json`

After that correction, both K28 and K32 passed the independent verifier.

The initial verifier-path failure is therefore an orchestration/path issue, not
a solver or cryptographic mismatch.

## Result artifact

Observed Kaggle result artifact:

- path: `/kaggle/working/phase-h-ksa-cuda-results.json`
- SHA-256:
  `d25cd036dd532e0dbad50919025df53f20f9035dd1c0cb8f87e7595dbc5d34f4`
- `PHASE_H_KSA_CUDA_RUN=PASS`

The exact Kaggle-generated JSON should be preserved directly from the Kaggle
runtime rather than reconstructed from console output.

## Methodological status

This CUDA baseline demonstrates:

1. pinned-input execution against the frozen reduced H-KSA challenge;
2. native CUDA exhaustive search over the reduced hidden-bit subspace;
3. recovery of the same K28 and K32 solution counters as the CPU baseline;
4. independent forward verification of both recovered 80-byte candidates;
5. a reproducible single-T4 measurement for the selected implementation.

It does not demonstrate tractability of the full 640-bit inverse KSA problem.
Any projection beyond the measured reduced instances must be labeled as an
arithmetic extrapolation, not as an observed result.

## Verdict

`PHASE_H_KSA_CUDA_BASELINE=PASS`
