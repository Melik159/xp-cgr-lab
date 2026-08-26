#!/usr/bin/env python3
"""
Independent verifier for inverse-benchmark-v2 candidates.

Inputs:
  - reduced-challenges.json
  - instance id
  - candidate XVAL (20 bytes / 40 hex chars)

This verifier is solver-neutral and oracle-free. It does not read
CGR640_FULL_01 events, inverse-benchmark-v1, or any captured AUX value.

G(x) is implemented locally as one SHA-1 compression of:
    x || 44 zero bytes
using the standard SHA-1 IV and no message padding.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

MOD160 = 1 << 160
FULL160 = MOD160 - 1
DEFAULT_CHALLENGE = Path(
    "/home/hal/xp-cgr-lab/evidence/inverse-benchmark-v2/reduced-challenges.json"
)

def rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def sha1_compress_one(block: bytes) -> bytes:
    if len(block) != 64:
        raise ValueError("SHA-1 compression input must be exactly 64 bytes")

    w = [0] * 80
    for t in range(16):
        w[t] = int.from_bytes(block[t * 4:(t + 1) * 4], "big")
    for t in range(16, 80):
        w[t] = rol32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)

    h0, h1, h2, h3, h4 = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )
    a, b, c, d, e = h0, h1, h2, h3, h4

    for t in range(80):
        if t < 20:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif t < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = (rol32(a, 5) + f + e + k + w[t]) & 0xFFFFFFFF
        e = d
        d = c
        c = rol32(b, 30)
        b = a
        a = temp

    words = (
        (h0 + a) & 0xFFFFFFFF,
        (h1 + b) & 0xFFFFFFFF,
        (h2 + c) & 0xFFFFFFFF,
        (h3 + d) & 0xFFFFFFFF,
        (h4 + e) & 0xFFFFFFFF,
    )
    return b"".join(x.to_bytes(4, "big") for x in words)

def G(xval: bytes) -> bytes:
    if len(xval) != 20:
        raise ValueError("XVAL must be exactly 20 bytes")
    return sha1_compress_one(xval + b"\x00" * 44)

def _decode20_hex(value: str, field: str) -> bytes:
    try:
        b = bytes.fromhex(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field}: invalid hex") from exc
    if len(b) != 20:
        raise ValueError(f"{field}: expected 20 bytes")
    return b

def validate_instance(inst: dict) -> None:
    k = inst.get("k")
    positions = inst.get("unknown_positions")
    if not isinstance(k, int) or not (1 <= k <= 159):
        raise ValueError("invalid k")
    if not isinstance(positions, list) or len(positions) != k:
        raise ValueError("unknown_positions cardinality mismatch")
    if len(set(positions)) != k or any(
        not isinstance(p, int) or not (0 <= p < 160) for p in positions
    ):
        raise ValueError("invalid unknown_positions")

    known_mask = int.from_bytes(
        _decode20_hex(inst["known_mask_hex"], "known_mask_hex"), "big"
    )
    known_value = int.from_bytes(
        _decode20_hex(inst["known_value_hex"], "known_value_hex"), "big"
    )
    expected_unknown = 0
    for p in positions:
        expected_unknown |= 1 << p
    expected_known = FULL160 ^ expected_unknown

    if known_mask != expected_known:
        raise ValueError("known_mask does not match unknown_positions")
    if known_mask.bit_count() != 160 - k:
        raise ValueError("known_mask cardinality mismatch")
    if known_value & ~known_mask:
        raise ValueError("known_value sets an unknown bit")

    _decode20_hex(inst["out_a_hex"], "out_a_hex")
    _decode20_hex(inst["out_b_hex"], "out_b_hex")
    _decode20_hex(inst["xkey_before_hex"], "xkey_before_hex")

def verify_candidate(inst: dict, candidate: bytes) -> dict:
    validate_instance(inst)
    if len(candidate) != 20:
        raise ValueError("candidate must be exactly 20 bytes")

    cand_int = int.from_bytes(candidate, "big")
    known_mask = int(inst["known_mask_hex"], 16)
    known_value = int(inst["known_value_hex"], 16)
    target_a = bytes.fromhex(inst["out_a_hex"])
    target_b = bytes.fromhex(inst["out_b_hex"])

    mask_match = (cand_int & known_mask) == known_value

    calc_a = G(candidate)
    out_a_match = calc_a == target_a

    xval_b = (
        cand_int + int.from_bytes(calc_a, "big") + 1
    ) % MOD160
    calc_b = G(xval_b.to_bytes(20, "big"))
    out_b_match = calc_b == target_b

    verdict = mask_match and out_a_match and out_b_match
    return {
        "KNOWN_MASK_MATCH": mask_match,
        "OUT_A_MATCH": out_a_match,
        "OUT_B_MATCH": out_b_match,
        "VERDICT": verdict,
    }

def load_instance(challenge_path: Path, instance_id: str) -> dict:
    data = json.loads(challenge_path.read_text(encoding="utf-8"))
    if data.get("schema") != "cgr640-provider-reduced-preimage-v2":
        raise ValueError("unexpected challenge schema")
    matches = [x for x in data.get("instances", []) if x.get("id") == instance_id]
    if len(matches) != 1:
        raise ValueError(f"expected one instance {instance_id}, got {len(matches)}")
    return matches[0]

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id")
    ap.add_argument("xval_hex")
    ap.add_argument("--challenge", type=Path, default=DEFAULT_CHALLENGE)
    args = ap.parse_args()

    candidate = _decode20_hex(args.xval_hex, "xval_hex")
    inst = load_instance(args.challenge, args.instance_id)
    result = verify_candidate(inst, candidate)

    print(f"INSTANCE={args.instance_id}")
    for key in ("KNOWN_MASK_MATCH", "OUT_A_MATCH", "OUT_B_MATCH"):
        print(f"{key}={'PASS' if result[key] else 'FAIL'}")
    print(f"VERDICT={'PASS' if result['VERDICT'] else 'FAIL'}")
    return 0 if result["VERDICT"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
