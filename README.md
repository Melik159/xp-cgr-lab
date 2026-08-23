# xp-cgr-lab

Reproducible research laboratory for studying the causal relationship between the Windows XP `CryptGenRandom` API, the TrueCrypt 6.2a userspace RNG, and cryptographic material generated during synthetic volume creation.

The repository is designed as an **executable-evidence / forensic-research corpus**. It separates:

- observed runtime data;
- exact deterministic replay;
- source-derived behavior;
- inferred or constrained state;
- unknown state that is deliberately left unresolved.

The current reference execution is **RUN3**.

## Research question

> Under what circumstances can information produced or retained by Windows XP RNG mechanisms during cryptographic material generation leave enough state for later forensic reconstruction?

The present repository does **not** claim that a TrueCrypt volume can be recovered from disk alone, nor that the internal state of Windows `CryptGenRandom` has been reconstructed.

The work completed so far establishes the **forward causal model** required before a meaningful inverse forensic problem can be defined.

## Current result

For the instrumented RUN3 execution, the TrueCrypt userspace RNG state is exactly replayable from a single observed zero-pool anchor through all subsequently observed lifecycle RNG mutations, without snapshot resynchronization.

The following chain has been independently replayed or verified bit-for-bit:

```text
observed CryptGenRandom outputs
        ↓
TrueCrypt userspace RNG
        ↓
master key material / salts
        ↓
PBKDF2-RIPEMD160
        ↓
header keys
        ↓
plaintext headers + CRCs
        ↓
AES-XTS encrypted headers
        ↓
reserved areas
        ↓
FAT RandgetBytes(4)
        ↓
FAT16 volume ID
        ↓
GetFatParams()
        ↓
PutBoot()
        ↓
FAT16 boot sector
        ↓
AES-XTS data units
        ↓
logged physical writes
        ↓
final container bytes
```

### RUN3 reference values

- trace records: **3081**
- trace overflow: **0**
- final container size: **16 MiB**
- logged final-write coverage: **407,552 bytes**
- final-write coverage fraction: **2.429199%**
- final bytes without logged-write provenance: **16,369,664 bytes**

The uncovered bytes are **not inferred** to be zero, random, or otherwise reconstructed. Their provenance remains explicitly unknown in the current forward model.

## Exact replay results

### Global userspace RNG replay

RUN3 global replay:

- 1,163 `Randmix` pairs
- 607 `Randadd*` events
- 18,332 injected bytes
- 21 observed `CryptGenRandom` outputs
- 18 background/fast-poll restorations
- 8 `RandgetBytes` calls
- all modeled pool/index transitions exact
- no snapshot resynchronization after the initial zero-pool anchor

### Downstream cryptography

Exact replay includes:

- master key material
- primary salt
- backup salt
- PBKDF2-RIPEMD160
- primary and backup header keys
- plaintext header structures
- header CRCs
- AES-XTS encrypted primary and backup headers
- primary and backup reserved areas

### FAT / quick-format bridge

The observed 4-byte RNG output:

```text
83 7b fc fb
```

is reproduced exactly as the FAT16 volume ID.

The quick-format geometry is independently recomputed as:

- 32,256 sectors
- 512-byte sectors
- 1 sector per cluster
- FAT16
- 2 reserved sectors
- 2 FATs
- 125 sectors per FAT
- 32 root-directory sectors
- 284 metadata sectors

The three logged `WRITE_DATA` records exactly cover those 284 sectors.

### Source-level `PutBoot()` replay

The exact RUN3 `Fat.c` source is used to execute the original:

- `GetFatParams()`
- `PutBoot()`

with only the observed 4-byte FAT RNG result supplied through a deterministic `RandgetBytes()` stub.

The resulting 512-byte FAT16 boot sector is bit-identical to the independently decrypted RUN3 boot sector.

Its independent AES-XTS encryption reproduces:

1. the logged `WRITE_DATA` sector;
2. the final container bytes at the corresponding physical offset.

Reference hashes:

```text
PutBoot plaintext SHA256
b2052920312ed52f15b21292f97154f22973864f44abd11b217b7b6849ace612

PutBoot XTS SHA256
7843975498a0351920e337856834f3cb7327584f82cbb45ab6b66e405dcf95c5
```

## Scientific boundary

What RUN3 demonstrates:

- exact replay of the instrumented TrueCrypt userspace RNG;
- exact causal connection between observed RNG outputs and generated cryptographic material;
- exact deterministic replay of downstream TrueCrypt cryptographic transformations;
- exact source-level regeneration of the FAT16 boot sector;
- exact reconciliation of all surviving logged writes with the corresponding final container bytes.

What RUN3 does **not** demonstrate:

- reconstruction of the internal Windows `CryptGenRandom` state;
- reconstruction of Windows RNG prehistory;
- recovery from a seized host;
- recovery from disk-only evidence;
- observational neutrality of the instrumentation;
- provenance of bytes never covered by a logged write.

Instrumentation changes timing, scheduling, and entropy collection. Exact claims therefore apply only to the instrumented execution being analyzed.

## Repository structure

Typical layout:

```text
src/                         research instrumentation and helper source
j2/                          earlier API-provenance work
j3/                          RUN3 instrumentation / packaging logic
tools/                       analysis and support tools
patches/                     patch against upstream TrueCrypt source

evidence/
  j3/
    gt-run3/
      analysis-global-rng-v3/
      analysis-downstream-crypto/
      analysis-fat-data-bridge/
      analysis-fat-source/
      analysis-putboot-source-replay-v5/
      analysis-forward-model-final/
```

Large VM and binary evidence are deliberately not tracked in Git.

## Large artifacts intentionally excluded

The repository does not contain:

- Windows XP installation media;
- QEMU/QCOW2 virtual-machine disks;
- raw disk images;
- full TrueCrypt containers;
- memory dumps;
- large transport images;
- upstream TrueCrypt binary distributions.

These artifacts are retained separately and identified by hashes in the research records.

This keeps the Git repository small while preserving verifiable provenance.

## TrueCrypt provenance

Primary historical target:

- TrueCrypt **6.2a**
- signed release dated 2009
- archived source provenance recorded separately
- modified GroundTruth source is represented as a patch rather than as a complete vendored source tree

The research instrumentation is intended to make causal transitions observable. It is not intended to represent normal production behavior.

## Reproducibility model

The project follows a strict distinction between:

- **OBSERVED** — directly captured from the instrumented execution;
- **DERIVED** — deterministically recomputed from observed inputs;
- **CONSTRAINED** — narrowed by source behavior or artifact structure;
- **INFERRED** — supported but not directly observed;
- **UNKNOWN** — deliberately unresolved.

A successful replay must reproduce the target bytes exactly.

## Forward model vs inverse problem

The current milestone closes the forward model for RUN3.

The next research stage is the **inverse forensic problem**:

```text
INPUT
  disk image
  RAM snapshot
  pagefile.sys
  hiberfil.sys
  process dumps
  version / timing metadata
  known fragments

MODEL
  exact state-transition model

UNKNOWN
  Windows RNG state
  CryptGenRandom outputs
  TrueCrypt RNG pool state
  indices
  scheduling / event ordering

SOLVER
  interchangeable backend:
  classical / GPU / SAT-SMT / symbolic /
  probabilistic / future algorithms

VERIFIER
  exact forward replay

SUCCESS
  calculated bytes == seized artifacts
```

The final objective is a **Forensic Cryptographic State Reconstruction Corpus** in which the forward model remains stable while the inverse solver can evolve independently.

## Safety and scope

All current experiments use a synthetic, isolated research environment.

No production credentials, third-party secrets, or live operational systems are required.

## Status

**RUN3 forward causal model: closed for all surviving logged writes.**

Current boundary:

```text
TrueCrypt userspace forward model       CLOSED
Windows CryptGenRandom internal state   NOT RECONSTRUCTED
cold-case forensic recoverability       NOT YET TESTED
```

## License

The repository's original research code and documentation should be licensed separately from any upstream TrueCrypt material.

Upstream TrueCrypt source and binaries remain subject to their own historical license terms.
