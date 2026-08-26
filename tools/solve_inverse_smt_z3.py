#!/usr/bin/env python3
"""
Phase E SMT baseline for inverse-benchmark-v2 using Z3.

Oracle-free solver:
- reads only reduced-challenges.json
- reads only the independent Phase-B verifier
- does not read events.jsonl, AUX, or inverse-benchmark-v1

Encodes the full reduced relation:
  out_a = G(xval)
  out_b = G((xval + out_a + 1) mod 2^160)

G is SHA-1 compression of xval || 44 zero bytes, standard SHA-1 IV,
with no SHA-1 message padding.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import time
from pathlib import Path

import z3

ROOT = Path("/home/hal/xp-cgr-lab")
DEFAULT_CHALLENGE = ROOT / "evidence/inverse-benchmark-v2/reduced-challenges.json"
DEFAULT_VERIFIER = ROOT / "tools/verify_inverse_candidate.py"

MASK32 = 0xFFFFFFFF


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


def words_be160(value: int) -> list[int]:
    return [((value >> (32 * (4 - i))) & MASK32) for i in range(5)]


def sha1_compress_symbolic(xwords):
    w = list(xwords) + [z3.BitVecVal(0, 32) for _ in range(11)]

    for t in range(16, 80):
        w.append(
            z3.RotateLeft(
                w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16],
                1,
            )
        )

    h0 = z3.BitVecVal(0x67452301, 32)
    h1 = z3.BitVecVal(0xEFCDAB89, 32)
    h2 = z3.BitVecVal(0x98BADCFE, 32)
    h3 = z3.BitVecVal(0x10325476, 32)
    h4 = z3.BitVecVal(0xC3D2E1F0, 32)

    a, b, c, d, e = h0, h1, h2, h3, h4

    for t in range(80):
        if t < 20:
            f = (b & c) | ((~b) & d)
            k = z3.BitVecVal(0x5A827999, 32)
        elif t < 40:
            f = b ^ c ^ d
            k = z3.BitVecVal(0x6ED9EBA1, 32)
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = z3.BitVecVal(0x8F1BBCDC, 32)
        else:
            f = b ^ c ^ d
            k = z3.BitVecVal(0xCA62C1D6, 32)

        temp = z3.RotateLeft(a, 5) + f + e + k + w[t]
        e = d
        d = c
        c = z3.RotateLeft(b, 30)
        b = a
        a = temp

    return [h0 + a, h1 + b, h2 + c, h3 + d, h4 + e]


def build_xval_words(known_value: int, positions: list[int], u):
    words = [z3.BitVecVal(v, 32) for v in words_be160(known_value)]

    for src_bit, pos in enumerate(positions):
        wi = 4 - (pos // 32)
        bi = pos % 32
        bit32 = z3.ZeroExt(31, z3.Extract(src_bit, src_bit, u))
        words[wi] = words[wi] | (bit32 << bi)

    return words


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id", nargs="?", default="B00-K08")
    ap.add_argument("--challenge", type=Path, default=DEFAULT_CHALLENGE)
    ap.add_argument("--verifier", type=Path, default=DEFAULT_VERIFIER)
    ap.add_argument("--timeout-ms", type=int, default=300000)
    args = ap.parse_args()

    verifier = load_module(args.verifier)
    inst = load_instance(args.challenge, args.instance_id)
    verifier.validate_instance(inst)

    k = inst["k"]
    positions = inst["unknown_positions"]
    if not (1 <= k <= 32):
        raise SystemExit("FAIL Phase-E baseline supports 1<=k<=32")
    if len(positions) != k:
        raise SystemExit("FAIL unknown-position cardinality")

    known_value = int(inst["known_value_hex"], 16)
    target_a = int(inst["out_a_hex"], 16)
    target_b = int(inst["out_b_hex"], 16)

    u = z3.BitVec("unknown_bits", k)
    xwords = build_xval_words(known_value, positions, u)

    solver = z3.Solver()
    if args.timeout_ms > 0:
        solver.set(timeout=args.timeout_ms)

    out_a_sym = sha1_compress_symbolic(xwords)
    for sym, target in zip(out_a_sym, words_be160(target_a)):
        solver.add(sym == z3.BitVecVal(target, 32))

    x160 = z3.Concat(*xwords)
    xval_b160 = x160 + z3.BitVecVal(target_a, 160) + z3.BitVecVal(1, 160)
    xb_words = [
        z3.Extract(159 - 32 * i, 128 - 32 * i, xval_b160)
        for i in range(5)
    ]

    out_b_sym = sha1_compress_symbolic(xb_words)
    for sym, target in zip(out_b_sym, words_be160(target_b)):
        solver.add(sym == z3.BitVecVal(target, 32))

    print(f"INSTANCE={args.instance_id}")
    print(f"K={k}")
    print(f"SEARCH_SPACE={1 << k}")
    print(f"Z3_VERSION={z3.get_version_string()}")
    print(f"TIMEOUT_MS={args.timeout_ms}")
    print("RELATION=FULL_OUT_A_OUT_B")

    t0 = time.perf_counter()
    status = solver.check()
    elapsed = time.perf_counter() - t0

    print(f"SMT_STATUS={status}")
    print(f"ELAPSED_SECONDS={elapsed:.9f}")

    if status == z3.unknown:
        print("UNKNOWN_REASON=" + solver.reason_unknown())
        print("PHASE_E_SMT=INCOMPLETE")
        return 2

    if status != z3.sat:
        print("PHASE_E_SMT=FAIL")
        return 1

    model = solver.model()
    uval = model.eval(u, model_completion=True).as_long()

    xval_int = known_value
    for src_bit, pos in enumerate(positions):
        if (uval >> src_bit) & 1:
            xval_int |= 1 << pos

    xval = xval_int.to_bytes(20, "big")
    print(f"SOLUTION_COUNTER={uval}")
    print("SOLUTION_XVAL=" + xval.hex())

    final = verifier.verify_candidate(inst, xval)
    print(f"FINAL_KNOWN_MASK={'PASS' if final['KNOWN_MASK_MATCH'] else 'FAIL'}")
    print(f"FINAL_OUT_A={'PASS' if final['OUT_A_MATCH'] else 'FAIL'}")
    print(f"FINAL_OUT_B={'PASS' if final['OUT_B_MATCH'] else 'FAIL'}")
    print(f"FINAL_VERDICT={'PASS' if final['VERDICT'] else 'FAIL'}")
    print(f"PHASE_E_SMT={'PASS' if final['VERDICT'] else 'FAIL'}")

    return 0 if final["VERDICT"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
