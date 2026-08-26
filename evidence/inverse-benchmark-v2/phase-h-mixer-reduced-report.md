# Phase H — H-MIXER Reduced Challenge Campaign

## Campaign identity

- Campaign: `MIX-R`
- Parent repository baseline: `250a6863d07276cb4f9477c7490a1e119cb67408`
- Parent H-MIXER challenge SHA-256: `6c7b6f5eae09dbc3844f225872f7bf424cc64d4c0d184244a94c660d35b4a28c`
- Source events SHA-256: `f0ceb2775e3458ff5c204bd353c39cc7efe835f8a4fa972323a44d594b7a3acf`
- Parent H-MIXER verifier SHA-256: `9b0f6f3d49330b2c9eedcd7c689c1a45c8b8d0aab3d52c27d30e0d2b0d225ef6`

## Purpose

This campaign defines deterministic reduced inverse challenges for the exact KSec mixer relation
used by `H-MIXER-00`.

The reduced corpus is intended to validate solver correctness and scaling. It does **not**
demonstrate recovery of the historical mixer state from forensic disk/RAM artifacts.

## Reduced profiles

Three profiles are generated for:

`k = 8, 12, 16, 20, 24, 28, 32`

- `OLD-Kxx`: exactly `k` low bits of the 80-byte `old_state` are unknown.
- `WS-Kxx`: exactly `k` low bits of the 600-byte workspace prefix are unknown.
- `SPLIT-Kxx`: `ceil(k/2)` low bits of `old_state` and `floor(k/2)` low bits of the workspace
  prefix are unknown.

Bit numbering treats each component as one big-endian integer; bit 0 is the least-significant
bit of the complete component.

## Isolation design

All reduced tasks derive from the same `H-MIXER-00` oracle. Co-serializing profiles or
different `k` levels would leak bits hidden by another task.

The final design therefore uses **one reduced instance per challenge file**.

A solver run may read only its selected per-instance challenge file. Sibling reduced challenge
files, the reduced manifest, event logs, the parent full challenge, and oracle/KAT helpers are
excluded from the solver input contract.

The manifest is provenance/index metadata only.

## Builder and verifier

- Builder: `tools/build_phase_h_mixer_reduced.py`
  - SHA-256: `739419f2501f44b96e7dc2c88bbff81d499a7d6fa8c7ff14e2c00b30a9453429`
- Independent verifier: `tools/verify_phase_h_mixer_reduced_candidate.py`
  - SHA-256: `c59e87e857c00d2ee936907b0a539cfa055025731e11b207b8f038d2717d67a1`
- KAT driver: `tools/check_phase_h_mixer_reduced_verifier_kat.py`
  - SHA-256: `60eb4c6df7f6c18707dd94eb720cae27018962474b4c5f1c9f8a0bb7be3d7da7`

The independent verifier does not read the captured event log, sibling reduced challenges, the
manifest, parent verifier, or upstream checker.

## Generated corpus

- Instance count: `21`
- Serialization mode: `ONE_INSTANCE_PER_FILE`
- Cross-instance leakage guard: `PASS`
- Oracle serialization check: `PASS`
- Manifest SHA-256:
  `c389308a185877d2fae3cedba84ddb03e9c2a4501d45ed13a3b4196366c8fc5d`

### Challenge SHA-256 values

| Instance | SHA-256 |
|---|---|
| H-MIXER-00-OLD-K08 | `7822de32a29a149f0ddd0c759558b2ce0168ca91dbbf68b437f86db0187aabe0` |
| H-MIXER-00-OLD-K12 | `b6d42dcc55f78e434e4167ea58b884751eaf830a5effea3e0ff29622e14b640a` |
| H-MIXER-00-OLD-K16 | `83fff0ae64bd04539866586ed1072fb25428d2504e61ed23cc64dda931ce33b1` |
| H-MIXER-00-OLD-K20 | `f83624cf92d050d4eb7da641b29b3e3839987058b5762179d1af1fa9e55a4fc5` |
| H-MIXER-00-OLD-K24 | `42b8139fd4b8f073b407a81e5e61dc14696085f64e0625cd4e2d71cabf9a7489` |
| H-MIXER-00-OLD-K28 | `e6eb665ea7b00192f5d24c63a1535f7748000e92bcd7b55ab957a430088c9293` |
| H-MIXER-00-OLD-K32 | `602d203dee003cb15ead53d1ecd26078af0c1227db8dd70c14025938c1d2ee76` |
| H-MIXER-00-WS-K08 | `a3f8a0288eea84dacaed4b5a382b36279fe25250f36498de155bfab8cee09d02` |
| H-MIXER-00-WS-K12 | `722290dea95d9a66db04c55b0220c4fdaa2d8504e4c7cc2203a077a10a934005` |
| H-MIXER-00-WS-K16 | `26f44088930ad00dc535f5ede70e6b90f1949c908e6bae089fedec597596481b` |
| H-MIXER-00-WS-K20 | `34e94408990861ecc60d562b48d70787358919e3462c1bfc2f152057bbe411a4` |
| H-MIXER-00-WS-K24 | `ba16d06e75766248fb8e1fd1f61cd067307ea2309ac6d273843d11f4cf5356de` |
| H-MIXER-00-WS-K28 | `5690f9a6ab7b59d0c2fb3dbee2b7ceb970785168cb7a5cbaa193edcf0b414c9d` |
| H-MIXER-00-WS-K32 | `e4f17f739e2164bd598322f494bbee503ec5737355f6f804630bdaf279a9108e` |
| H-MIXER-00-SPLIT-K08 | `31ac743268b5a466df2fc190f9baf1a45f52244b3447f293c4e1b07ecdc291a8` |
| H-MIXER-00-SPLIT-K12 | `bac749256f900aa4fe912309b5605406ef31529be4bb9597fbbddb7ede7a6cc9` |
| H-MIXER-00-SPLIT-K16 | `7e9582826a7a8a3484e1a7f1ccb5939d6fd9c726a398c7b0daa851f96310d28f` |
| H-MIXER-00-SPLIT-K20 | `9cb620bf98fdb4a24886f66d26172e92bae410db7e32362c545ce9ddc08a617a` |
| H-MIXER-00-SPLIT-K24 | `05667721dd1bfb705c4a1452779c30046444739ad614e70220affae183a2a328` |
| H-MIXER-00-SPLIT-K28 | `a023f3a5f43151a8848b9a58139f4b0c8d9506a7bd122d3fda6ca2d160ee83f1` |
| H-MIXER-00-SPLIT-K32 | `4e53e180967b37e78c85b2a5d03a1581a4577476aee26013f5de52dfaae74a1b` |

## Deterministic rebuild control

The generated 21 challenge files plus manifest were hashed, the builder was rerun, and the
before/after hash listings were compared with `diff`.

Result:

- deterministic rebuild: `PASS`
- manifest remained:
  `c389308a185877d2fae3cedba84ddb03e9c2a4501d45ed13a3b4196366c8fc5d`

## Independent verifier KATs

Positive oracle controls:

- `H-MIXER-00-OLD-K08`: `PASS`
- `H-MIXER-00-WS-K08`: `PASS`
- `H-MIXER-00-SPLIT-K08`: `PASS`

Summary:

`POSITIVE_KATS=3/3`

Hidden-bit negative controls:

- OLD hidden bit mutation: rejected.
- WS hidden bit mutation: rejected.
- SPLIT old-state hidden bit mutation: rejected.
- SPLIT workspace hidden bit mutation: rejected.

Summary:

`NEGATIVE_HIDDEN_COMPONENT_KATS=4/4`

Published-bit negative control:

- OLD-K08 published old-state bit mutation: public-mask check failed and candidate was rejected.

Summary:

`NEGATIVE_PUBLISHED_BIT_KATS=1/1`

Final verifier control:

`PHASE_H_MIXER_REDUCED_VERIFIER_KAT=PASS`

## Interpretation

The campaign establishes a deterministic, oracle-isolated reduced benchmark interface for the
exact H-MIXER relation and an independent verifier that accepts known valid candidates and
rejects controlled one-bit mutations.

It does not establish the feasibility of the full 5,440-bit H-MIXER inversion and does not
establish forensic recovery from seized-system artifacts.

## Verdict

`PHASE_H_MIXER_REDUCED=PASS`
