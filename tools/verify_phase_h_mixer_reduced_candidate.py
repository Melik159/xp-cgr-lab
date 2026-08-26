#!/usr/bin/env python3
"""
Independent verifier for one per-instance reduced Phase-H KSec mixer challenge.

Reads only:
  - one serialized reduced challenge file;
  - a complete 80-byte candidate old_state;
  - a complete `used`-byte candidate workspace prefix.

It does not read the CGR640 event log, sibling reduced challenges, the reduced
manifest, the parent verifier, or the upstream checker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DEFAULT_CHALLENGE = Path(
    "evidence/inverse-benchmark-v2/phase-h-mixer-reduced/"
    "H-MIXER-00-OLD-K08.json"
)
EXPECTED_SCHEMA = "cgr640-h-mixer-reduced-v2"


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
        raise ValueError(f"{field}: expected {expected_len} bytes, got {len(raw)}")
    return raw


def bit_count(raw: bytes) -> int:
    return sum(byte.bit_count() for byte in raw)


def public_bits_match(
    candidate: bytes, known_mask: bytes, known_value: bytes
) -> bool:
    return all(
        (candidate_byte & mask_byte) == value_byte
        for candidate_byte, mask_byte, value_byte
        in zip(candidate, known_mask, known_value)
    )


def load_instance(path: Path, instance_id: str) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))

    if data.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("unexpected reduced challenge schema")
    if data.get("isolation") != "single-reduced-instance":
        raise ValueError("challenge is not single-instance isolated")

    instances = data.get("instances", [])
    if not isinstance(instances, list) or len(instances) != 1:
        raise ValueError("reduced challenge must contain exactly one instance")
    inst = instances[0]
    if inst.get("id") != instance_id:
        raise ValueError(
            f"challenge instance is {inst.get('id')!r}, requested {instance_id!r}"
        )
    return inst


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
    if inst.get("old_state_len_bytes") != 80:
        raise ValueError("invalid old-state length metadata")
    if inst.get("workspace_prefix_len_bytes") != used:
        raise ValueError("invalid workspace length metadata")

    old_state = decode_hex(
        args.candidate_old_state_hex, 80, "candidate_old_state_hex"
    )
    workspace = decode_hex(
        args.candidate_workspace_prefix_hex,
        used,
        "candidate_workspace_prefix_hex",
    )
    old_known_mask = decode_hex(
        inst.get("old_state_known_mask_hex"), 80, "old_state_known_mask_hex"
    )
    old_known_value = decode_hex(
        inst.get("old_state_known_value_hex"), 80, "old_state_known_value_hex"
    )
    ws_known_mask = decode_hex(
        inst.get("workspace_known_mask_hex"), used, "workspace_known_mask_hex"
    )
    ws_known_value = decode_hex(
        inst.get("workspace_known_value_hex"), used, "workspace_known_value_hex"
    )
    target = decode_hex(
        inst.get("target_new_state_hex"), 80, "target_new_state_hex"
    )

    if any(
        value & (~mask & 0xFF)
        for value, mask in zip(old_known_value, old_known_mask)
    ):
        raise ValueError("old-state known_value sets an unknown bit")
    if any(
        value & (~mask & 0xFF)
        for value, mask in zip(ws_known_value, ws_known_mask)
    ):
        raise ValueError("workspace known_value sets an unknown bit")

    old_unknown_bits = 80 * 8 - bit_count(old_known_mask)
    ws_unknown_bits = used * 8 - bit_count(ws_known_mask)
    total_unknown_bits = old_unknown_bits + ws_unknown_bits

    if old_unknown_bits != inst.get("unknown_bits_old_state"):
        raise ValueError("old-state unknown-bit metadata mismatch")
    if ws_unknown_bits != inst.get("unknown_bits_workspace"):
        raise ValueError("workspace unknown-bit metadata mismatch")
    if total_unknown_bits != inst.get("unknown_bits_total"):
        raise ValueError("total unknown-bit metadata mismatch")
    if total_unknown_bits != inst.get("k"):
        raise ValueError("k does not equal total unknown bits")

    target_hash_ok = (
        hashlib.sha256(target).hexdigest()
        == inst.get("target_new_state_sha256")
    )
    old_public_ok = public_bits_match(
        old_state, old_known_mask, old_known_value
    )
    ws_public_ok = public_bits_match(
        workspace, ws_known_mask, ws_known_value
    )
    public_ok = old_public_ok and ws_public_ok

    calc = replay_mixer(workspace, used, old_state)
    mixer_match = calc == target
    verdict = target_hash_ok and public_ok and mixer_match

    print(f"INSTANCE={args.instance_id}")
    print(f"PROFILE={inst.get('profile')}")
    print(f"K={inst.get('k')}")
    print(f"USED={used}")
    print(f"OLD_UNKNOWN_BITS={old_unknown_bits}")
    print(f"WORKSPACE_UNKNOWN_BITS={ws_unknown_bits}")
    print(f"TARGET_HASH_CHECK={'PASS' if target_hash_ok else 'FAIL'}")
    print(f"OLD_PUBLIC_BITS_MATCH={'PASS' if old_public_ok else 'FAIL'}")
    print(f"WORKSPACE_PUBLIC_BITS_MATCH={'PASS' if ws_public_ok else 'FAIL'}")
    print(f"PUBLIC_BITS_MATCH={'PASS' if public_ok else 'FAIL'}")
    print(f"MIXER_MATCH={'PASS' if mixer_match else 'FAIL'}")
    print(f"VERDICT={'PASS' if verdict else 'FAIL'}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
