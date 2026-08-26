#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DEFAULT_CHALLENGE = Path(
    "/home/hal/xp-cgr-lab/evidence/inverse-benchmark-v2/phase-h-ksa-challenge.json"
)

def rc4_ksa(key: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key must not be empty")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    return bytes(state) + b"\x00\x00"

def decode_hex(value: str, expected_len: int, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field}: invalid hex") from exc
    if len(raw) != expected_len:
        raise ValueError(f"{field}: expected {expected_len} bytes, got {len(raw)}")
    return raw

def load_instance(path: Path, instance_id: str) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "cgr640-h-ksa-v1":
        raise ValueError("unexpected challenge schema")
    matches = [inst for inst in data.get("instances", []) if inst.get("id") == instance_id]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one instance {instance_id}, got {len(matches)}")
    inst = matches[0]
    if inst.get("key_len_bytes") != 80:
        raise ValueError("unexpected key length")
    target = decode_hex(inst.get("target_post_ksa_hex"), 258, "target_post_ksa_hex")
    if hashlib.sha256(target).hexdigest() != inst.get("target_post_ksa_sha256"):
        raise ValueError("target SHA-256 mismatch")
    return inst

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id")
    ap.add_argument("candidate_new_state_hex")
    ap.add_argument("--challenge", type=Path, default=DEFAULT_CHALLENGE)
    args = ap.parse_args()

    candidate = decode_hex(args.candidate_new_state_hex, 80, "candidate_new_state_hex")
    inst = load_instance(args.challenge, args.instance_id)
    target = bytes.fromhex(inst["target_post_ksa_hex"])
    match = rc4_ksa(candidate) == target

    print(f"INSTANCE={args.instance_id}")
    print("CANDIDATE_LEN=80")
    print(f"TARGET_SHA256={inst['target_post_ksa_sha256']}")
    print(f"RC4_KSA_MATCH={'PASS' if match else 'FAIL'}")
    print(f"VERDICT={'PASS' if match else 'FAIL'}")
    return 0 if match else 1

if __name__ == "__main__":
    raise SystemExit(main())
