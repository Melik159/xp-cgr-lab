#!/usr/bin/env python3
"""
Independent verifier for Phase-H reduced RC4-KSA candidates.

Reads only the reduced challenge and the supplied 80-byte candidate.
It does not read the CGR640 event log or any serialized oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DEFAULT_CHALLENGE = Path(
    "/home/hal/xp-cgr-lab/evidence/inverse-benchmark-v2/"
    "phase-h-ksa-reduced-challenges.json"
)


def rc4_ksa(key: bytes) -> bytes:
    if len(key) != 80:
        raise ValueError("expected exactly 80 key bytes")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    return bytes(state) + b"\x00\x00"


def decode_hex(value, expected_len: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field}: missing hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field}: invalid hex") from exc
    if len(raw) != expected_len:
        raise ValueError(
            f"{field}: expected {expected_len} bytes, got {len(raw)}"
        )
    return raw


def load_instance(path: Path, instance_id: str) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "cgr640-h-ksa-reduced-v1":
        raise ValueError("unexpected challenge schema")
    matches = [
        inst
        for inst in data.get("instances", [])
        if inst.get("id") == instance_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one instance {instance_id}, got {len(matches)}"
        )
    return matches[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id")
    ap.add_argument("candidate_new_state_hex")
    ap.add_argument("--challenge", type=Path, default=DEFAULT_CHALLENGE)
    args = ap.parse_args()

    inst = load_instance(args.challenge, args.instance_id)
    candidate = decode_hex(
        args.candidate_new_state_hex, 80, "candidate_new_state_hex"
    )
    known_mask = decode_hex(
        inst.get("known_mask_hex"), 80, "known_mask_hex"
    )
    known_value = decode_hex(
        inst.get("known_value_hex"), 80, "known_value_hex"
    )
    target = decode_hex(
        inst.get("target_post_ksa_hex"), 258, "target_post_ksa_hex"
    )

    if hashlib.sha256(target).hexdigest() != inst.get(
        "target_post_ksa_sha256"
    ):
        raise ValueError("target SHA-256 mismatch")

    cand_int = int.from_bytes(candidate, "big")
    mask_int = int.from_bytes(known_mask, "big")
    value_int = int.from_bytes(known_value, "big")

    mask_ok = (cand_int & mask_int) == value_int
    crypto_ok = rc4_ksa(candidate) == target
    verdict = mask_ok and crypto_ok

    print(f"INSTANCE={args.instance_id}")
    print(f"K={inst.get('k')}")
    print(f"KNOWN_MASK_MATCH={'PASS' if mask_ok else 'FAIL'}")
    print(f"RC4_KSA_MATCH={'PASS' if crypto_ok else 'FAIL'}")
    print(f"VERDICT={'PASS' if verdict else 'FAIL'}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
