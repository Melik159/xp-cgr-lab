# Phase H — H-MIXER GPU campaign

## Scope

Campaign: `MIX-GPU`

Frozen reduced-challenge baseline commit:

`17ed6b1d9db49eae4418e252f1cb66621f3d1647`

The CUDA campaign searches the exact reduced H-MIXER challenge geometry already frozen by MIX-R. Candidate acceptance remains delegated to the independent Python verifier.

## CUDA sources

Performance source (v1):

`tools/solve_phase_h_mixer_gpu_v1.cu`

SHA-256:

`25845b86892f8f05a85f1f2eb4666f94f5ae92613c84fe23ff3ca2cd2e247908`

Canonical corrected source (v2):

`tools/solve_phase_h_mixer_gpu.cu`

SHA-256:

`6033ade237fca4fd7f5a043dcc9923f19aa5dc6eae1f163cb72768cf6bcb4f3e`

The v1 performance source printed `HOST_EXACT_MODEL_CONTROL=PASS` although that label was not backed by an actual comparison. This label is therefore not used as evidence. The search results remain independently checked by the frozen Python verifier.

The v2 source replaces that label with a real host-side cross-check of the optimized rejection path against the exact mixer model at two counters: `0` and `2^K-1`.

## Kaggle environment

Observed environment:

- GPU: Tesla T4
- visible devices: 2
- campaign device: 0
- compute capability: 7.5
- NVIDIA driver: 580.159.04
- CUDA runtime reported by nvidia-smi: 13.0
- nvcc toolkit: 12.8, V12.8.93
- block size: 128
- chunk size: 4,194,304 candidates

Only GPU 0 was used by the campaign.

## Frozen result artifact

`evidence/inverse-benchmark-v2/phase-h-mixer-cuda-results.json`

SHA-256:

`8586dfea10abf034c56ed607bb58b801264471f058e1a98fb021876e801d2d9b`

This artifact records the v1 source SHA and the per-instance CUDA observations.

## OLD profile results

| K | counter | GPU scanned | GPU wall s | GPU wall candidates/s | verifier |
|---:|---:|---:|---:|---:|:---:|
| 20 | 829,365 | 1,048,576 | 0.007819183 | 134,103,013.065 | PASS |
| 24 | 6,072,245 | 8,388,608 | 0.052813471 | 158,834,627.627 | PASS |
| 28 | 56,403,893 | 58,720,256 | 0.403945527 | 145,366,768.723 | PASS |
| 32 | 3,546,064,821 | 3,548,381,184 | 26.144947529 | 135,719,575.649 | PASS |

The GPU scans full chunks, so `SCANNED` can exceed `FIRST_MATCH_COUNTER + 1`.

## CPU/GPU comparison on identical OLD instances

| K | CPU candidates/s | GPU wall candidates/s | throughput ratio GPU/CPU | CPU wall s | GPU wall s | wall-time ratio |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 79,112.772 | 134,103,013.065 | 1,695.09x | 10.483339 | 0.007819183 | 1,340.72x |
| 24 | 76,945.015 | 158,834,627.627 | 2,064.26x | 78.916692 | 0.052813471 | 1,494.25x |
| 28 | 75,305.143 | 145,366,768.723 | 1,930.37x | 749.004544691 | 0.403945527 | 1,854.22x |

These are machine-specific observations, not universal speedup factors.

The K28 CPU and GPU implementations recovered the same counter:

`56403893`

Both candidates were independently accepted by the frozen verifier.

## WS and SPLIT controls

Observed GPU controls:

| instance | counter | verifier |
|---|---:|:---:|
| WS-K28 | 0 | PASS |
| WS-K32 | 0 | PASS |
| SPLIT-K28 | 10,165 | PASS |
| SPLIT-K32 | 42,933 | PASS |

For this corpus, the low hidden workspace bits used by WS and the workspace part of SPLIT are zero. Therefore these search-to-first-solution timings are not useful scaling measurements. They are retained as correctness controls only.

## Fast-path interpretation

The CUDA kernel uses the first 20 bytes of the H-MIXER target as an optimized rejection predicate. It does not replay the complete 80-byte output for every candidate.

A FOUND candidate is then reconstructed and passed to the independent exact verifier, which checks the complete reduced challenge semantics and full mixer target.

Therefore the reported GPU throughput measures the optimized candidate rejection path for this exact reduced-mask geometry, not a generic full-mixer replay throughput.

## Corrected v2 KAT

Observed v2 OLD-K20 control:

- `HOST_FAST_PATH_CROSSCHECK_SAMPLES=2`
- `HOST_FAST_PATH_CROSSCHECK=PASS`
- `FIRST_MATCH_COUNTER=829365`
- `INDEPENDENT_VERIFIER=PASS`
- `PHASE_H_MIXER_CUDA_V2_KAT=PASS`

The corrected v2 source therefore reproduces the known OLD-K20 solution while additionally validating the optimized host fast path against the exact mixer model.

## Verdict

`MIX-GPU` establishes:

1. CUDA recovery of reduced H-MIXER OLD challenges through K32 on one Tesla T4.
2. Independent exact verification of every reported candidate.
3. CPU/GPU convergence on the same OLD-K20/K24/K28 solutions.
4. A measured OLD-K28 throughput ratio of approximately `1930x` GPU/CPU on the tested hosts.
5. Correctness controls for WS/SPLIT K28/K32.
6. A corrected canonical CUDA v2 implementation with a real fast-path/exact-model KAT.

This campaign does **not** establish recovery of the historical 680-byte mixer input from seized artifacts, nor does it generalize the measured throughput to arbitrary unknown-bit placement.
