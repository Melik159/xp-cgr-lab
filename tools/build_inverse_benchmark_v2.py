#!/usr/bin/env python3
"""
Build inverse-benchmark-v2 reduced provider preimage challenges.

For each of the 16 provider blocks and each k in:
    8, 12, 16, 20, 24, 28, 32

exactly k bit positions of the 160-bit XVAL are hidden. The remaining
160-k bits are published through a known-mask / known-value pair.

The full XVAL oracle is reconstructed from the frozen CGR640_FULL_01 trace
only for generator self-checks. It is never serialized into the reduced
challenge JSON.

Bit numbering:
    bit 0 = least-significant bit of the 160-bit big-endian integer.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

K_VALUES = (8, 12, 16, 20, 24, 28, 32)
MOD160 = 1 << 160
FULL160 = MOD160 - 1

DEFAULT_ROOT = Path("/home/hal/xp-cgr-lab")
DEFAULT_STRICT = Path(
    "/home/hal/Téléchargements/xp-cgr-replay-release/"
    "deterministic-replay/tools/check_strict_e2e.py"
)

DROP = {"seq", "host_time_ns", "accepted_block_index"}

def fp(e):
    return json.dumps(
        {k: v for k, v in e.items() if k not in DROP},
        sort_keys=True,
        separators=(",", ":"),
    )

def canonicalize(events):
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

def load_strict(path):
    spec = importlib.util.spec_from_file_location("strict_e2e", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def add160(a, b):
    return (
        (int.from_bytes(a, "big") + int.from_bytes(b, "big")) % MOD160
    ).to_bytes(20, "big")

def G(strict, xval):
    return strict.sha1_compress_one(xval + b"\x00" * 44)

def deterministic_unknown_positions(source_sha, block_index, k):
    seed = f"{source_sha}:block={block_index}:k={k}".encode("ascii")
    ranked = sorted(
        range(160),
        key=lambda pos: hashlib.sha256(
            seed + b":bit=" + str(pos).encode("ascii")
        ).digest(),
    )
    return sorted(ranked[:k])

def mask_from_unknown_positions(positions):
    unknown_mask = 0
    for pos in positions:
        unknown_mask |= 1 << pos
    known_mask = FULL160 ^ unknown_mask
    return known_mask, unknown_mask

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--strict", type=Path, default=DEFAULT_STRICT)
    ap.add_argument(
        "--output",
        type=Path,
        default=None,
        help="default: <root>/evidence/inverse-benchmark-v2/reduced-challenges.json",
    )
    args = ap.parse_args()

    root = args.root
    full_path = root / "evidence/inverse-benchmark-v1/provider-preimage-challenge.json"
    events_path = root / "evidence/cgr640-full-01/events.jsonl"
    output_path = args.output or (
        root / "evidence/inverse-benchmark-v2/reduced-challenges.json"
    )

    for p in (full_path, events_path, args.strict):
        if not p.is_file():
            raise SystemExit(f"FAIL missing input: {p}")

    strict = load_strict(args.strict)
    full = json.loads(full_path.read_text(encoding="utf-8"))

    instances_v1 = full.get("instances")
    if not isinstance(instances_v1, list) or len(instances_v1) != 16:
        raise SystemExit("FAIL expected exactly 16 v1 instances")

    raw = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ev = canonicalize(raw)
    b12 = [
        e for e in ev
        if e.get("kind") == "B12_PROVIDER_FIPS_ENTRY"
        and 260 <= e.get("seq", -1) <= 410
    ]
    if len(b12) != 16:
        raise SystemExit(f"FAIL oracle B12 count={len(b12)}")

    source_sha = sha256_file(events_path)
    full_sha = sha256_file(full_path)

    out = {
        "schema": "cgr640-provider-reduced-preimage-v2",
        "bit_numbering": (
            "bit 0 is the least-significant bit of the 160-bit big-endian XVAL integer"
        ),
        "source_events_sha256": source_sha,
        "parent_full_challenge_sha256": full_sha,
        "strict_model_sha256": sha256_file(args.strict),
        "k_values": list(K_VALUES),
        "solver_contract": {
            "unknown": "exactly k XVAL bits selected by unknown_positions",
            "known_constraint": "(xval & known_mask) == known_value",
            "out_a": "G(xval)",
            "out_b": "G((xval + out_a + 1) mod 2^160)",
            "G": (
                "SHA1 compression, standard IV, one 64-byte block "
                "xval||44*00; no SHA1 message padding"
            ),
        },
        "instances": [],
    }

    selfcheck_count = 0

    for block_index, inst in enumerate(instances_v1):
        if inst.get("index") != block_index:
            raise SystemExit(
                f"FAIL unexpected v1 index at slot {block_index}: {inst.get('index')}"
            )

        xkey_before = bytes.fromhex(inst["xkey_before_hex"])
        out_a = bytes.fromhex(inst["out_a_hex"])
        out_b = bytes.fromhex(inst["out_b_hex"])
        aux = bytes.fromhex(b12[block_index]["aux_final_20_hex"][:40])

        if not all(len(x) == 20 for x in (xkey_before, out_a, out_b, aux)):
            raise SystemExit(f"FAIL malformed block {block_index}")

        xval = add160(xkey_before, aux)
        if G(strict, xval) != out_a:
            raise SystemExit(f"FAIL block {block_index}: oracle out_a mismatch")

        xval_b_int = (
            int.from_bytes(xval, "big")
            + int.from_bytes(out_a, "big")
            + 1
        ) % MOD160
        xval_b = xval_b_int.to_bytes(20, "big")
        if G(strict, xval_b) != out_b:
            raise SystemExit(f"FAIL block {block_index}: oracle out_b mismatch")

        xval_int = int.from_bytes(xval, "big")

        for k in K_VALUES:
            unknown_positions = deterministic_unknown_positions(
                source_sha, block_index, k
            )
            known_mask, unknown_mask = mask_from_unknown_positions(
                unknown_positions
            )
            known_value = xval_int & known_mask

            if (xval_int & known_mask) != known_value:
                raise SystemExit("FAIL internal known-mask relation")
            if unknown_mask.bit_count() != k:
                raise SystemExit("FAIL internal unknown-mask cardinality")
            if known_mask.bit_count() != 160 - k:
                raise SystemExit("FAIL internal known-mask cardinality")

            out["instances"].append({
                "id": f"B{block_index:02d}-K{k:02d}",
                "block_index": block_index,
                "k": k,
                "xkey_before_hex": xkey_before.hex(),
                "out_a_hex": out_a.hex(),
                "out_b_hex": out_b.hex(),
                "known_mask_hex": known_mask.to_bytes(20, "big").hex(),
                "known_value_hex": known_value.to_bytes(20, "big").hex(),
                "unknown_positions": unknown_positions,
            })
            selfcheck_count += 1

    expected = 16 * len(K_VALUES)
    if selfcheck_count != expected or len(out["instances"]) != expected:
        raise SystemExit(
            f"FAIL instance count={len(out['instances'])}, expected={expected}"
        )

    serialized = json.dumps(out, sort_keys=True)
    for token in ("aux_final", '"xval_hex"', '"oracle"'):
        if token in serialized:
            raise SystemExit(f"FAIL oracle leakage token present: {token}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"K_VALUES={','.join(map(str, K_VALUES))}")
    print("BLOCKS=16")
    print(f"INSTANCE_COUNT={expected}")
    print("ORACLE_SELF_CHECK=PASS")
    print("ORACLE_SERIALIZATION_CHECK=PASS")
    print(f"CHALLENGE={output_path}")
    print(f"CHALLENGE_SHA256={sha256_file(output_path)}")

if __name__ == "__main__":
    raise SystemExit(main())
