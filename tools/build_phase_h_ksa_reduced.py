#!/usr/bin/env python3
"""
Build Phase-H reduced RC4-KSA inverse benchmarks.

For each of the 8 H-KSA instances and each k in:
    8, 12, 16, 20, 24, 28, 32

exactly k bit positions of the 640-bit new_state are hidden. The remaining
640-k bits are serialized as a known-mask / known-value constraint.

The captured 80-byte new_state oracle is used only for generator self-checks.
It is never serialized as a complete value into the reduced challenge.

Bit numbering:
    bit 0 = least-significant bit of the 640-bit big-endian new_state integer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

K_VALUES = (8, 12, 16, 20, 24, 28, 32)
MOD640 = 1 << 640
FULL640 = MOD640 - 1

EXPECTED_EVENTS_SHA256 = (
    "f0ceb2775e3458ff5c204bd353c39cc7efe835f8a4fa972323a44d594b7a3acf"
)
EXPECTED_PARENT_SHA256 = (
    "78867366dc5f0659375ffdf16d8a9881cf10a99e3a26e069659dd45568ff5b35"
)

DEFAULT_ROOT = Path("/home/hal/xp-cgr-lab")
DROP = {"seq", "host_time_ns", "accepted_block_index"}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fp(e: dict) -> str:
    return json.dumps(
        {k: v for k, v in e.items() if k not in DROP},
        sort_keys=True,
        separators=(",", ":"),
    )


def canonicalize(events: list[dict]) -> list[dict]:
    out = []
    i = 0
    while i < len(events):
        e = events[i]
        j = i + 1
        while (
            j < len(events)
            and events[j].get("kind") == e.get("kind")
            and fp(events[j]) == fp(e)
        ):
            j += 1
        out.append(e)
        i = j
    return out


def rc4_ksa(key: bytes) -> bytes:
    if len(key) != 80:
        raise ValueError("expected exactly 80 key bytes")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    return bytes(state) + b"\x00\x00"


def deterministic_unknown_positions(
    parent_sha: str, instance_id: str, k: int
) -> list[int]:
    seed = f"{parent_sha}:{instance_id}:k={k}".encode("ascii")
    ranked = sorted(
        range(640),
        key=lambda pos: hashlib.sha256(
            seed + b":bit=" + str(pos).encode("ascii")
        ).digest(),
    )
    return sorted(ranked[:k])


def masks_from_positions(positions: list[int]) -> tuple[int, int]:
    unknown_mask = 0
    for pos in positions:
        unknown_mask |= 1 << pos
    return FULL640 ^ unknown_mask, unknown_mask


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--output", type=Path, default=None)
    args = ap.parse_args()

    root = args.root
    events_path = root / "evidence/cgr640-full-01/events.jsonl"
    parent_path = (
        root / "evidence/inverse-benchmark-v2/phase-h-ksa-challenge.json"
    )
    output_path = args.output or (
        root
        / "evidence/inverse-benchmark-v2"
        / "phase-h-ksa-reduced-challenges.json"
    )

    for p in (events_path, parent_path):
        if not p.is_file():
            raise SystemExit(f"FAIL missing input: {p}")

    events_sha = sha256_file(events_path)
    parent_sha = sha256_file(parent_path)
    if events_sha != EXPECTED_EVENTS_SHA256:
        raise SystemExit(f"FAIL source events SHA-256 mismatch: {events_sha}")
    if parent_sha != EXPECTED_PARENT_SHA256:
        raise SystemExit(f"FAIL parent challenge SHA-256 mismatch: {parent_sha}")

    parent = json.loads(parent_path.read_text(encoding="utf-8"))
    parent_instances = parent.get("instances")
    if not isinstance(parent_instances, list) or len(parent_instances) != 8:
        raise SystemExit("FAIL expected exactly 8 parent H-KSA instances")

    raw = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ev = canonicalize(raw)
    k16 = [
        e
        for e in ev
        if e.get("kind") == "K16_FINAL_RC4_KSA"
        and e.get("seq", 10**9) < 260
    ]
    if len(k16) != 8:
        raise SystemExit(f"FAIL expected 8 canonical K16 events, got {len(k16)}")

    out = {
        "schema": "cgr640-h-ksa-reduced-v1",
        "bit_numbering": (
            "bit 0 is the least-significant bit of the 640-bit "
            "big-endian new_state integer"
        ),
        "source_events_sha256": events_sha,
        "parent_h_ksa_challenge_sha256": parent_sha,
        "k_values": list(K_VALUES),
        "solver_contract": {
            "unknown": (
                "exactly k new_state bits selected by unknown_positions"
            ),
            "known_constraint": (
                "(new_state & known_mask) == known_value"
            ),
            "crypto_constraint": (
                "RC4_KSA(new_state_80) == target_post_ksa_258"
            ),
            "key_len_bytes": 80,
        },
        "instances": [],
    }

    forbidden_oracles: list[str] = []

    for idx, (parent_inst, event) in enumerate(zip(parent_instances, k16)):
        expected_id = f"H-KSA-{idx:02d}"
        if parent_inst.get("id") != expected_id:
            raise SystemExit(
                f"FAIL parent instance {idx}: id={parent_inst.get('id')}"
            )

        oracle_hex = event.get("global_state_50_hex")
        if not isinstance(oracle_hex, str):
            raise SystemExit(f"FAIL {expected_id}: missing oracle")
        oracle = bytes.fromhex(oracle_hex)
        if len(oracle) != 80:
            raise SystemExit(
                f"FAIL {expected_id}: oracle length={len(oracle)}"
            )

        target = bytes.fromhex(parent_inst["target_post_ksa_hex"])
        if len(target) != 258:
            raise SystemExit(
                f"FAIL {expected_id}: target length={len(target)}"
            )
        if rc4_ksa(oracle) != target:
            raise SystemExit(
                f"FAIL {expected_id}: parent/oracle KSA mismatch"
            )

        forbidden_oracles.append(oracle.hex())
        oracle_int = int.from_bytes(oracle, "big")

        for k in K_VALUES:
            unknown_positions = deterministic_unknown_positions(
                parent_sha, expected_id, k
            )
            known_mask, unknown_mask = masks_from_positions(
                unknown_positions
            )
            known_value = oracle_int & known_mask

            if unknown_mask.bit_count() != k:
                raise SystemExit("FAIL unknown-mask cardinality")
            if known_mask.bit_count() != 640 - k:
                raise SystemExit("FAIL known-mask cardinality")
            if (oracle_int & known_mask) != known_value:
                raise SystemExit("FAIL known-mask relation")

            out["instances"].append(
                {
                    "id": f"{expected_id}-K{k:02d}",
                    "parent_id": expected_id,
                    "k": k,
                    "key_len_bytes": 80,
                    "target_post_ksa_hex": target.hex(),
                    "target_post_ksa_sha256": hashlib.sha256(
                        target
                    ).hexdigest(),
                    "known_mask_hex": known_mask.to_bytes(
                        80, "big"
                    ).hex(),
                    "known_value_hex": known_value.to_bytes(
                        80, "big"
                    ).hex(),
                    "unknown_positions": unknown_positions,
                }
            )

    expected = 8 * len(K_VALUES)
    if len(out["instances"]) != expected:
        raise SystemExit(
            f"FAIL instance count={len(out['instances'])}, "
            f"expected={expected}"
        )

    serialized = json.dumps(out, sort_keys=True).lower()
    for oracle_hex in forbidden_oracles:
        if oracle_hex.lower() in serialized:
            raise SystemExit("FAIL full oracle leaked into reduced challenge")
    for token in ('"oracle"', "global_state_50_hex"):
        if token in serialized:
            raise SystemExit(f"FAIL oracle leakage token present: {token}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("K_VALUES=" + ",".join(map(str, K_VALUES)))
    print("PARENT_INSTANCES=8")
    print(f"INSTANCE_COUNT={expected}")
    print("ORACLE_SELF_CHECK=PASS")
    print("ORACLE_SERIALIZATION_CHECK=PASS")
    print("CHALLENGE=" + str(output_path))
    print("CHALLENGE_SHA256=" + sha256_file(output_path))
    print("PHASE_H_KSA_REDUCED=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
