#!/usr/bin/env python3
"""
Independent verifier for Phase-H KSec mixer candidates.

Reads only:
  - the serialized Phase-H mixer challenge;
  - candidate old_state (80 bytes);
  - candidate workspace prefix (exactly `used` bytes).

It does not read the CGR640 event log and does not import the upstream checker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DEFAULT_CHALLENGE = Path(
    "/home/hal/xp-cgr-lab/evidence/inverse-benchmark-v2/"
    "phase-h-mixer-challenge.json"
)


def rol32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def sha1_compress(
    state: tuple[int, ...], block: bytes, endian: str
) -> tuple[int, ...]:
    if len(block) != 64:
        raise ValueError("SHA-1 block must contain 64 bytes")
    words = [
        int.from_bytes(block[offset:offset + 4], endian)
        for offset in range(0, 64, 4)
    ]
    for index in range(16, 80):
        words.append(
            rol32(
                words[index - 3]
                ^ words[index - 8]
                ^ words[index - 14]
                ^ words[index - 16],
                1,
            )
        )

    a, b, c, d, e = state
    for index in range(80):
        if index < 20:
            function = (b & c) | ((~b) & d)
            constant = 0x5A827999
        elif index < 40:
            function = b ^ c ^ d
            constant = 0x6ED9EBA1
        elif index < 60:
            function = (b & c) | (b & d) | (c & d)
            constant = 0x8F1BBCDC
        else:
            function = b ^ c ^ d
            constant = 0xCA62C1D6

        temporary = (
            rol32(a, 5) + function + e + constant + words[index]
        ) & 0xFFFFFFFF
        e, d, c, b, a = d, c, rol32(b, 30), a, temporary

    return tuple(
        (old + new) & 0xFFFFFFFF
        for old, new in zip(state, (a, b, c, d, e))
    )


def ksec_mixer_hash(message: bytes) -> bytes:
    state = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

    complete = len(message) // 64
    for index in range(complete):
        state = sha1_compress(
            state,
            message[index * 64:(index + 1) * 64],
            "little",
        )

    remainder = message[complete * 64:]
    padding_length = 64 - (len(message) & 0x3F)
    if padding_length <= 8:
        padding_length += 64

    bit_length = len(message) * 8
    padding = (
        b"\x80"
        + bytes(padding_length - 9)
        + (bit_length >> 32).to_bytes(4, "little")
        + (bit_length & 0xFFFFFFFF).to_bytes(4, "little")
    )

    final_blocks = remainder + padding
    if len(final_blocks) % 64:
        raise AssertionError("internal padding error")

    for offset in range(0, len(final_blocks), 64):
        state = sha1_compress(
            state,
            final_blocks[offset:offset + 64],
            "big",
        )

    return b"".join(word.to_bytes(4, "little") for word in state)


def replay_mixer(
    workspace_prefix: bytes, used: int, old_state: bytes
) -> bytes:
    if len(workspace_prefix) != used:
        raise ValueError("workspace prefix length does not equal used")
    if len(old_state) != 80:
        raise ValueError("old_state must contain 80 bytes")
    if used <= 0 or used % 4:
        raise ValueError("used must be positive and divisible by 4")

    quarter = used // 4
    quarters = [
        workspace_prefix[index * quarter:(index + 1) * quarter]
        for index in range(4)
    ]
    states = [
        old_state[index * 20:(index + 1) * 20]
        for index in range(4)
    ]

    digest_a = ksec_mixer_hash(
        states[0] + quarters[0] + states[1] + quarters[1]
    )
    digest_b = ksec_mixer_hash(
        states[1] + quarters[1] + states[0] + quarters[0]
    )
    digest_c = ksec_mixer_hash(
        states[2] + quarters[2] + states[3] + quarters[3]
    )
    digest_d = ksec_mixer_hash(
        states[3] + quarters[3] + states[2] + quarters[2]
    )

    return (
        ksec_mixer_hash(digest_a + digest_c)
        + ksec_mixer_hash(digest_b + digest_d)
        + ksec_mixer_hash(digest_c + digest_a)
        + ksec_mixer_hash(digest_d + digest_b)
    )


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
    if data.get("schema") != "cgr640-h-mixer-v1":
        raise ValueError("unexpected challenge schema")

    matches = [
        inst
        for inst in data.get("instances", [])
        if inst.get("id") == instance_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one instance {instance_id}, "
            f"got {len(matches)}"
        )
    return matches[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id")
    ap.add_argument("candidate_old_state_hex")
    ap.add_argument("candidate_workspace_prefix_hex")
    ap.add_argument("--challenge", type=Path, default=DEFAULT_CHALLENGE)
    args = ap.parse_args()

    inst = load_instance(args.challenge, args.instance_id)

    used = inst.get("used")
    if not isinstance(used, int) or used <= 0 or used % 4:
        raise ValueError("invalid used in challenge")

    old_state = decode_hex(
        args.candidate_old_state_hex,
        80,
        "candidate_old_state_hex",
    )
    workspace = decode_hex(
        args.candidate_workspace_prefix_hex,
        used,
        "candidate_workspace_prefix_hex",
    )
    target = decode_hex(
        inst.get("target_new_state_hex"),
        80,
        "target_new_state_hex",
    )

    if hashlib.sha256(target).hexdigest() != inst.get(
        "target_new_state_sha256"
    ):
        raise ValueError("target SHA-256 mismatch")

    calc = replay_mixer(workspace, used, old_state)
    match = calc == target

    print(f"INSTANCE={args.instance_id}")
    print(f"USED={used}")
    print("OLD_STATE_LEN=80")
    print(f"WORKSPACE_PREFIX_LEN={len(workspace)}")
    print(f"MIXER_MATCH={'PASS' if match else 'FAIL'}")
    print(f"VERDICT={'PASS' if match else 'FAIL'}")
    return 0 if match else 1


if __name__ == "__main__":
    raise SystemExit(main())
