#!/usr/bin/env python3
"""
CPU exhaustive-search baseline for inverse-benchmark-v2.

Solver input:
  - reduced challenge JSON
  - one instance id

The solver reads no CGR640 trace, no AUX oracle, and no v1 challenge.
It enumerates exactly the k unknown XVAL bits. Candidate evaluation uses
G(xval) against out_a; any hit is passed to the independent Phase-B verifier
for the full mask/out_a/out_b verdict.

This Python implementation is the correctness/performance baseline, not the
optimized CPU implementation.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import time
from pathlib import Path

DEFAULT_ROOT = Path("/home/hal/xp-cgr-lab")
DEFAULT_CHALLENGE = (
    DEFAULT_ROOT / "evidence/inverse-benchmark-v2/reduced-challenges.json"
)
DEFAULT_VERIFIER = DEFAULT_ROOT / "tools/verify_inverse_candidate.py"


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("inverse_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import verifier: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_instance(path: Path, instance_id: str) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "cgr640-provider-reduced-preimage-v2":
        raise ValueError("unexpected challenge schema")
    matches = [x for x in data.get("instances", []) if x.get("id") == instance_id]
    if len(matches) != 1:
        raise ValueError(f"expected one instance {instance_id}, got {len(matches)}")
    return matches[0]


def deposit_bits(counter: int, positions: list[int]) -> int:
    value = 0
    for src_bit, dst_bit in enumerate(positions):
        if (counter >> src_bit) & 1:
            value |= 1 << dst_bit
    return value


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id", nargs="?", default="B00-K08")
    ap.add_argument("--challenge", type=Path, default=DEFAULT_CHALLENGE)
    ap.add_argument("--verifier", type=Path, default=DEFAULT_VERIFIER)
    ap.add_argument(
        "--max-candidates",
        type=int,
        default=None,
        help="optional bounded run; omit for exhaustive search",
    )
    args = ap.parse_args()

    if not args.challenge.is_file():
        raise SystemExit(f"FAIL missing challenge: {args.challenge}")
    if not args.verifier.is_file():
        raise SystemExit(f"FAIL missing verifier: {args.verifier}")

    verifier = load_module(args.verifier)
    inst = load_instance(args.challenge, args.instance_id)
    verifier.validate_instance(inst)

    k = inst["k"]
    positions = inst["unknown_positions"]
    if len(positions) != k:
        raise SystemExit("FAIL unknown-position cardinality")

    known_value = int(inst["known_value_hex"], 16)
    target_a = bytes.fromhex(inst["out_a_hex"])
    search_space = 1 << k
    limit = search_space
    if args.max_candidates is not None:
        if args.max_candidates <= 0:
            raise SystemExit("FAIL --max-candidates must be positive")
        limit = min(search_space, args.max_candidates)

    print(f"INSTANCE={args.instance_id}")
    print(f"K={k}")
    print(f"SEARCH_SPACE={search_space}")
    print(f"RUN_LIMIT={limit}")

    start = time.perf_counter()
    tested = 0
    solution_counter = None
    solution = None

    for counter in range(limit):
        cand_int = known_value | deposit_bits(counter, positions)
        candidate = cand_int.to_bytes(20, "big")
        tested += 1

        if verifier.G(candidate) != target_a:
            continue

        result = verifier.verify_candidate(inst, candidate)
        if result["VERDICT"]:
            solution_counter = counter
            solution = candidate
            break

    elapsed = time.perf_counter() - start
    rate = tested / elapsed if elapsed > 0 else float("inf")

    print(f"TESTED={tested}")
    print(f"ELAPSED_SECONDS={elapsed:.9f}")
    print(f"CANDIDATES_PER_SECOND={rate:.3f}")

    if solution is None:
        if limit < search_space:
            print("SEARCH_STATUS=BOUNDED_NO_SOLUTION")
            print("PHASE_C_BASELINE=INCOMPLETE")
            return 2
        print("SEARCH_STATUS=EXHAUSTED_NO_SOLUTION")
        print("PHASE_C_BASELINE=FAIL")
        return 1

    print(f"SOLUTION_COUNTER={solution_counter}")
    print(f"SOLUTION_XVAL={solution.hex()}")

    final = verifier.verify_candidate(inst, solution)
    print(f"FINAL_KNOWN_MASK={'PASS' if final['KNOWN_MASK_MATCH'] else 'FAIL'}")
    print(f"FINAL_OUT_A={'PASS' if final['OUT_A_MATCH'] else 'FAIL'}")
    print(f"FINAL_OUT_B={'PASS' if final['OUT_B_MATCH'] else 'FAIL'}")
    print(f"FINAL_VERDICT={'PASS' if final['VERDICT'] else 'FAIL'}")
    print(f"PHASE_C_BASELINE={'PASS' if final['VERDICT'] else 'FAIL'}")
    return 0 if final["VERDICT"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
