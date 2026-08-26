#!/usr/bin/env python3
"""
Independent verifier for the frozen FULL-160 provider preimage challenge.

Security / methodology properties:
- accepts only the exact frozen challenge SHA-256;
- implements G locally;
- does not read CGR640_FULL_01 events;
- does not read AUX captures;
- does not read inverse-benchmark-v2;
- does not contain any known XVAL/oracle candidate.

Challenge relation for one instance:
    out_a = G(xval)
    out_b = G((xval + out_a + 1) mod 2^160)

G(x) is one SHA-1 compression of:
    x || 44 zero bytes
using the standard SHA-1 IV and no SHA-1 message padding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MOD160 = 1 << 160
EXPECTED_CHALLENGE_SHA256 = (
    "2e0e101f80d28a033f4231a7a083ee506fdf2907ea64a546c79e75c4e0d7751c"
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


def decode20(value: str, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field}: invalid hex") from exc
    if len(raw) != 20:
        raise ValueError(f"{field}: expected exactly 20 bytes")
    return raw


def load_frozen_challenge(path: Path) -> dict:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_CHALLENGE_SHA256:
        raise ValueError(
            "challenge SHA-256 mismatch: "
            f"expected {EXPECTED_CHALLENGE_SHA256}, got {digest}"
        )

    data = json.loads(raw.decode("utf-8"))
    if data.get("schema") != "cgr640-provider-preimage-v1":
        raise ValueError("unexpected challenge schema")

    instances = data.get("instances")
    if not isinstance(instances, list) or len(instances) != 16:
        raise ValueError("expected exactly 16 challenge instances")

    seen = set()
    for inst in instances:
        idx = inst.get("index")
        if not isinstance(idx, int) or not (0 <= idx < 16) or idx in seen:
            raise ValueError("invalid or duplicate instance index")
        seen.add(idx)

        xkey = decode20(inst.get("xkey_before_hex"), "xkey_before_hex")
        out_a = decode20(inst.get("out_a_hex"), "out_a_hex")
        out_b = decode20(inst.get("out_b_hex"), "out_b_hex")

        expected_out40_sha = hashlib.sha256(out_a + out_b).hexdigest()
        if inst.get("out40_sha256") != expected_out40_sha:
            raise ValueError(f"instance {idx}: out40 SHA-256 mismatch")

        # xkey is intentionally public challenge data.  It is validated here
        # for serialization integrity; no captured AUX is needed or consulted.
        if len(xkey) != 20:
            raise AssertionError("unreachable")

    if seen != set(range(16)):
        raise ValueError("instance index set is not exactly 0..15")

    return data


def select_instance(data: dict, index: int) -> dict:
    matches = [x for x in data["instances"] if x["index"] == index]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one instance {index}")
    return matches[0]


def verify_candidate(inst: dict, candidate: bytes) -> dict:
    if len(candidate) != 20:
        raise ValueError("candidate must be exactly 20 bytes")

    target_a = decode20(inst["out_a_hex"], "out_a_hex")
    target_b = decode20(inst["out_b_hex"], "out_b_hex")

    calc_a = G(candidate)
    out_a_match = calc_a == target_a

    xval_b_int = (
        int.from_bytes(candidate, "big")
        + int.from_bytes(calc_a, "big")
        + 1
    ) % MOD160
    calc_b = G(xval_b_int.to_bytes(20, "big"))
    out_b_match = calc_b == target_b

    return {
        "OUT_A_MATCH": out_a_match,
        "OUT_B_MATCH": out_b_match,
        "VERDICT": out_a_match and out_b_match,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("index", type=int)
    ap.add_argument("xval_hex")
    ap.add_argument("--challenge", type=Path, required=True)
    args = ap.parse_args()

    if not (0 <= args.index < 16):
        raise SystemExit("FAIL: index must be in 0..15")

    candidate = decode20(args.xval_hex, "xval_hex")
    data = load_frozen_challenge(args.challenge)
    inst = select_instance(data, args.index)
    result = verify_candidate(inst, candidate)

    print("CHALLENGE_SHA256=" + EXPECTED_CHALLENGE_SHA256)
    print(f"INSTANCE={args.index}")
    print(f"OUT_A_MATCH={'PASS' if result['OUT_A_MATCH'] else 'FAIL'}")
    print(f"OUT_B_MATCH={'PASS' if result['OUT_B_MATCH'] else 'FAIL'}")
    print(f"VERDICT={'PASS' if result['VERDICT'] else 'FAIL'}")
    return 0 if result["VERDICT"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
