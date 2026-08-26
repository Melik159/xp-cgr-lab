# Inverse Benchmark — Phase H Constraint Specification

## Scope

Phase H formalizes the exact inverse constraints at the remaining RC4/KSec
boundary. It does not claim recovery from disk, RAM, pagefile, hibernation, or
other forensic artifacts. Those acquisition/recovery questions belong to a
later forensic-artifact phase.

The purpose here is to define solver-neutral relations that can later be used
by exhaustive, SAT/SMT, symbolic, probabilistic, or other solvers.

## Pinned implementations

The following local files were hashed before this specification was written:

- `tools/check_cgr640_inverse_extended.py`
  - SHA-256: `a2c80152635ca9d7ec7e336e6ce658eb73cedf1e80be1039872f4e952cc9a917`
- `tools/check_cgr640_ksecdd_json_v2.py`
  - SHA-256: `f9b5804279cc370b6427d5ad6cc2c2efbc445b88da748b6a4cc1697e57d835b6`
- upstream `check_kernel_fullchain.py`
  - SHA-256: `13be039ed472d794cbbc3bec33a6f6c9e6bedff44af01333c5dae52eaf52d4fa`
- upstream `check_strict_e2e.py`
  - SHA-256: `ebef626dfabd44cf04ea74933c435c7762f50321e1ea2ef8240bd0059b2666ac`

These hashes identify the exact implementations from which the relations below
were transcribed.

## H1 — RC4 KSA constraint

The pinned `rc4_ksa` implementation is:

- initial permutation `S_0 = [0, 1, ..., 255]`;
- initial `j_0 = 0`;
- for round `i = 0..255`:

  `j_(i+1) = (j_i + S_i[i] + K[i mod |K|]) mod 256`

  followed by:

  `S_(i+1) = swap(S_i, i, j_(i+1))`

- serialized post-KSA state:

  `S_256 || 0x00 || 0x00`

For the KSec final KSA observed in the pinned checker:

`K = new_state`

with:

`|new_state| = 80 bytes`.

Therefore the exact inverse constraint is:

`RC4_KSA(new_state) == observed_post_ksa_state`

where `new_state` is the 80-byte unknown and the 258-byte post-KSA state is the
constraint target.

No claim is made here that KSA inversion is unique, easy, or computationally
feasible.

## H2 — PRGA boundary

The RC4 PRGA transition on `(S, i, j)` is bijective per step and has already
been reversed exactly in the inverse baseline/extended work.

Accordingly, when only a later RC4 state is available, the solver input may use
the exactly derived pre-PRGA/post-KSA state.

This reversible PRGA step is not itself the remaining cryptanalytic boundary.

## H3 — KSec mixer constraint

Let:

`data = workspace[:used]`

and:

`quarter = used // 4`.

For the captured execution/model, `used` is divisible by four. Define:

- `Q0 = data[0*quarter : 1*quarter]`
- `Q1 = data[1*quarter : 2*quarter]`
- `Q2 = data[2*quarter : 3*quarter]`
- `Q3 = data[3*quarter : 4*quarter]`

Split the 80-byte prior global state as:

- `S0 = old_state[0:20]`
- `S1 = old_state[20:40]`
- `S2 = old_state[40:60]`
- `S3 = old_state[60:80]`

Let `H` denote the exact pinned `ksec_mixer_hash`, not `hashlib.sha1`.

Then:

`A = H(S0 || Q0 || S1 || Q1)`

`B = H(S1 || Q1 || S0 || Q0)`

`C = H(S2 || Q2 || S3 || Q3)`

`D = H(S3 || Q3 || S2 || Q2)`

and:

`new_state = H(A || C) || H(B || D) || H(C || A) || H(D || B)`.

This is the exact mixer relation used by the pinned checker.

## H4 — Exact H function semantics

`ksec_mixer_hash` is intentionally not interchangeable with normal SHA-1.

Its pinned behavior is:

1. SHA-1 IV:
   `67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0`.
2. Every complete 64-byte message block is parsed as 16 native
   little-endian DWORDs and compressed with the SHA-1 compression function.
3. Padding is constructed with:
   - byte `0x80`;
   - zero fill;
   - high 32 bits of bit length in little-endian;
   - low 32 bits of bit length in little-endian.
4. Final padded block(s) are parsed as big-endian DWORDs by the compression
   function.
5. The five final state DWORDs are serialized little-endian.

Any Phase-H solver or verifier must reproduce these semantics exactly.

## State classification

### OBSERVED

In the instrumented 2026 reference execution, the capture contains values such
as KSec `old_state`, `workspace`, `new_state`, and the final post-KSA RC4
context. These values are ground-truth instrumentation artifacts.

They may be used to test a generator/verifier, but values designated as hidden
must not be serialized into an inverse challenge.

### DERIVED

Examples:

- post-KSA state reconstructed by exact reverse PRGA from a later RC4 state;
- algebraically reconstructed states from previously proven reversible
  transitions.

A derived value must be reproducible solely from the declared public inputs and
the pinned model.

### CONSTRAINED

Examples:

- candidate `new_state` satisfying
  `RC4_KSA(new_state) == target_post_ksa`;
- candidate `(old_state, workspace[:used])` satisfying
  `replay_mixer(workspace, used, old_state) == new_state`.

A constrained value is not considered recovered until independently verified.

### UNKNOWN

In a forensic-blind scenario, values unavailable from seized artifacts remain
unknown even if the instrumented reference run contains an oracle copy.

Typical unknowns may include:

- some or all 80 bytes of `new_state`;
- some or all 80 bytes of `old_state`;
- some or all bytes of `workspace[:used]`;
- source values from which the workspace was populated.

## Phase-H experimental decomposition

Phase H should be split into solver-neutral gates:

1. **H-KSA challenge/verifier**  
   Public target: post-KSA 258-byte state.  
   Hidden oracle: 80-byte `new_state`.  
   Verification: exact pinned `rc4_ksa`.

2. **H-KSA reduced benchmarks**  
   Reveal a controlled subset of key bits/bytes while hiding the remainder,
   solely to measure solver scaling and validate encodings.

3. **H-MIXER challenge/verifier**  
   Public target: `new_state`, plus only those old-state/workspace fields that
   the selected challenge contract intentionally exposes.  
   Verification: exact pinned `replay_mixer`.

4. **H-COMBINED constraint**  
   Candidate values must satisfy both:
   `replay_mixer(...) == new_state`
   and
   `RC4_KSA(new_state) == target_post_ksa`.

## Methodological boundary

A successful reduced or oracle-assisted constraint solve demonstrates solver
correctness for that bounded challenge only.

It does not demonstrate that the corresponding state is recoverable from a
historical disk image or memory artifact.

Conversely, timeout or failure of one solver/encoding is not an impossibility
result for the inverse relation.

## Phase-H specification verdict

`PHASE_H_CONSTRAINT_SPEC=PASS`

Meaning only that the remaining RC4 KSA and KSec mixer inverse relations have
been stated from pinned implementations with their observational status
separated from their solver status.
