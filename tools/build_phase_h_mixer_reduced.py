#!/usr/bin/env python3
"""
Build 21 deterministic, per-instance Phase-H KSec mixer reduced challenges.

IMPORTANT ISOLATION RULE
------------------------
All reduced tasks are derived from the same H-MIXER-00 oracle. Therefore profiles and
k-levels MUST NOT be co-serialized in one solver input:

- OLD publishes the workspace that WS/SPLIT may hide.
- WS publishes the old_state that OLD/SPLIT may hide.
- K08 publishes bits that K12/K16/... designate hidden.

This builder writes exactly ONE reduced instance per challenge file. A solver's input
contract is the selected file only; sibling reduced challenge files, event logs, and
oracle/KAT material are excluded.

The builder may read the captured event log solely to recover the oracle candidate and
perform generation self-checks.

Reduced profiles:
  OLD-Kxx   : k low bits of old_state are unknown.
  WS-Kxx    : k low bits of workspace_prefix are unknown.
  SPLIT-Kxx : ceil(k/2) low bits of old_state and floor(k/2) low bits of
               workspace_prefix are unknown.

Bit numbering: each complete byte string is interpreted as a big-endian integer;
bit 0 is the least-significant bit of that complete component.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

EXPECTED_PARENT_CHALLENGE_SHA256 = (
    "6c7b6f5eae09dbc3844f225872f7bf424cc64d4c0d184244a94c660d35b4a28c"
)
EXPECTED_EVENTS_SHA256 = (
    "f0ceb2775e3458ff5c204bd353c39cc7efe835f8a4fa972323a44d594b7a3acf"
)
EXPECTED_PARENT_VERIFIER_SHA256 = (
    "9b0f6f3d49330b2c9eedcd7c689c1a45c8b8d0aab3d52c27d30e0d2b0d225ef6"
)
K_VALUES = (8, 12, 16, 20, 24, 28, 32)
PROFILES = ("OLD", "WS", "SPLIT")
DROP = {"seq", "host_time_ns", "accepted_block_index"}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fp(event: dict) -> str:
    return json.dumps(
        {k: v for k, v in event.items() if k not in DROP},
        sort_keys=True,
        separators=(",", ":"),
    )


def canonicalize(events: list[dict]) -> list[dict]:
    out: list[dict] = []
    i = 0
    while i < len(events):
        event = events[i]
        j = i + 1
        while (
            j < len(events)
            and events[j].get("kind") == event.get("kind")
            and fp(events[j]) == fp(event)
        ):
            j += 1
        out.append(event)
        i = j
    return out


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("phase_h_mixer_parent_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def unknown_mask(length: int, hidden_low_bits: int) -> bytes:
    if not 0 <= hidden_low_bits <= length * 8:
        raise ValueError("invalid hidden bit count")
    value = (1 << hidden_low_bits) - 1 if hidden_low_bits else 0
    return value.to_bytes(length, "big")


def known_mask_from_unknown(mask: bytes) -> bytes:
    return bytes((~byte) & 0xFF for byte in mask)


def masked_public_value(oracle: bytes, known_mask: bytes) -> bytes:
    return bytes(value & mask for value, mask in zip(oracle, known_mask))


def bit_count(raw: bytes) -> int:
    return sum(byte.bit_count() for byte in raw)


def profile_bits(profile: str, k: int) -> tuple[int, int]:
    if profile == "OLD":
        return k, 0
    if profile == "WS":
        return 0, k
    if profile == "SPLIT":
        return (k + 1) // 2, k // 2
    raise ValueError(f"unknown profile {profile}")


def component_is_safely_masked(
    oracle: bytes,
    known_mask: bytes,
    known_value: bytes,
    hidden_bits: int,
) -> bool:
    if len(oracle) != len(known_mask) or len(oracle) != len(known_value):
        return False
    if bit_count(known_mask) != len(oracle) * 8 - hidden_bits:
        return False
    if any(value & (~mask & 0xFF) for value, mask in zip(known_value, known_mask)):
        return False
    if any((oracle_byte & mask) != public_byte
           for oracle_byte, mask, public_byte
           in zip(oracle, known_mask, known_value)):
        return False
    return True


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parent_challenge_path = (
        root / "evidence/inverse-benchmark-v2/phase-h-mixer-challenge.json"
    )
    events_path = root / "evidence/cgr640-full-01/events.jsonl"
    parent_verifier_path = root / "tools/verify_phase_h_mixer_candidate.py"
    output_dir = (
        root / "evidence/inverse-benchmark-v2/phase-h-mixer-reduced"
    )
    manifest_path = (
        root / "evidence/inverse-benchmark-v2/phase-h-mixer-reduced-manifest.json"
    )

    pinned = (
        (parent_challenge_path, EXPECTED_PARENT_CHALLENGE_SHA256, "parent challenge"),
        (events_path, EXPECTED_EVENTS_SHA256, "events"),
        (parent_verifier_path, EXPECTED_PARENT_VERIFIER_SHA256, "parent verifier"),
    )
    for path, expected, label in pinned:
        if not path.is_file():
            raise SystemExit(f"FAIL missing {label}: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise SystemExit(
                f"FAIL {label} SHA-256 mismatch: expected={expected} actual={actual}"
            )

    parent = json.loads(parent_challenge_path.read_text(encoding="utf-8"))
    if parent.get("schema") != "cgr640-h-mixer-v1":
        raise SystemExit("FAIL unexpected parent challenge schema")
    parent_instances = parent.get("instances", [])
    if len(parent_instances) != 1 or parent_instances[0].get("id") != "H-MIXER-00":
        raise SystemExit("FAIL parent challenge must contain only H-MIXER-00")
    parent_inst = parent_instances[0]

    used = parent_inst.get("used")
    if used != 600:
        raise SystemExit(f"FAIL expected H-MIXER-00 used=600, got {used!r}")
    target = decode_hex(
        parent_inst.get("target_new_state_hex"), 80, "target_new_state_hex"
    )
    if hashlib.sha256(target).hexdigest() != parent_inst.get(
        "target_new_state_sha256"
    ):
        raise SystemExit("FAIL parent target SHA-256 mismatch")

    raw_events = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    events = canonicalize(raw_events)
    source_pre_seq = parent_inst.get("source_pre_seq")
    pre_matches = [
        event
        for event in events
        if event.get("kind") == "K13_PRE_MIX"
        and event.get("seq") == source_pre_seq
    ]
    if len(pre_matches) != 1:
        raise SystemExit(
            f"FAIL expected exactly one canonical K13_PRE_MIX seq={source_pre_seq}, "
            f"got {len(pre_matches)}"
        )
    pre = pre_matches[0]

    old_state = decode_hex(
        pre.get("global_state_before_50_hex"), 80, "global_state_before_50_hex"
    )
    workspace_full = decode_hex(
        pre.get("workspace_pre_mix_e00_hex"), 0xE00, "workspace_pre_mix_e00_hex"
    )
    workspace = workspace_full[:used]

    parent_verifier = load_module(parent_verifier_path)
    replay = parent_verifier.replay_mixer(workspace, used, old_state)
    if replay != target:
        raise SystemExit("FAIL H-MIXER-00 oracle self-check against parent verifier")
    print("PARENT_ORACLE_SELF_CHECK=PASS")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Remove only files produced by this builder, so stale per-instance files cannot
    # survive a change in the campaign matrix.
    for stale in output_dir.glob("H-MIXER-00-*-K*.json"):
        stale.unlink()

    manifest_instances: list[dict] = []

    for profile in PROFILES:
        for k in K_VALUES:
            old_hidden, ws_hidden = profile_bits(profile, k)

            old_unknown = unknown_mask(len(old_state), old_hidden)
            ws_unknown = unknown_mask(len(workspace), ws_hidden)
            old_known = known_mask_from_unknown(old_unknown)
            ws_known = known_mask_from_unknown(ws_unknown)
            old_public = masked_public_value(old_state, old_known)
            ws_public = masked_public_value(workspace, ws_known)

            if not component_is_safely_masked(
                old_state, old_known, old_public, old_hidden
            ):
                raise SystemExit(f"FAIL {profile}-K{k:02d} old-state mask")
            if not component_is_safely_masked(
                workspace, ws_known, ws_public, ws_hidden
            ):
                raise SystemExit(f"FAIL {profile}-K{k:02d} workspace mask")

            instance_id = f"H-MIXER-00-{profile}-K{k:02d}"
            instance = {
                "id": instance_id,
                "parent_instance": "H-MIXER-00",
                "profile": profile,
                "k": k,
                "used": used,
                "old_state_len_bytes": 80,
                "workspace_prefix_len_bytes": used,
                "unknown_bits_total": k,
                "unknown_bits_old_state": old_hidden,
                "unknown_bits_workspace": ws_hidden,
                "old_state_known_mask_hex": old_known.hex(),
                "old_state_known_value_hex": old_public.hex(),
                "workspace_known_mask_hex": ws_known.hex(),
                "workspace_known_value_hex": ws_public.hex(),
                "target_new_state_hex": target.hex(),
                "target_new_state_sha256": hashlib.sha256(target).hexdigest(),
            }

            challenge = {
                "schema": "cgr640-h-mixer-reduced-v2",
                "parent_challenge_sha256": EXPECTED_PARENT_CHALLENGE_SHA256,
                "source_events_sha256": EXPECTED_EVENTS_SHA256,
                "parent_verifier_sha256": EXPECTED_PARENT_VERIFIER_SHA256,
                "parent_instance": "H-MIXER-00",
                "isolation": "single-reduced-instance",
                "isolation_reason": (
                    "All reduced profiles and k-levels derive from the same oracle. "
                    "Co-serializing them leaks bits hidden by one task through another."
                ),
                "bit_numbering": (
                    "Each component is interpreted as one big-endian integer; bit 0 "
                    "is the least-significant bit of that complete component."
                ),
                "mask_semantics": (
                    "known_mask bit 1 means public/required; bit 0 means unknown. "
                    "known_value has unknown positions cleared to zero."
                ),
                "counter_semantics": (
                    "For OLD, counter low bits map to old_state bits 0..k-1. "
                    "For WS, counter low bits map to workspace bits 0..k-1. "
                    "For SPLIT, the lowest ceil(k/2) counter bits map to old_state "
                    "bits 0..ceil(k/2)-1 and the remaining floor(k/2) bits map to "
                    "workspace bits 0..floor(k/2)-1."
                ),
                "solver_input_contract": (
                    "Solver may read this selected challenge file only. Sibling "
                    "reduced challenge files, the reduced manifest, captured event "
                    "logs, the full H-MIXER challenge, and oracle/KAT helpers are excluded."
                ),
                "relation": (
                    "Candidate must match all published known bits and "
                    "replay_mixer(workspace_prefix, used, old_state_80) "
                    "must equal target_new_state_80."
                ),
                "instances": [instance],
            }

            # Object-level oracle isolation is semantic, not exact-string based.
            # If all hidden oracle bits happen to be zero, the masked public byte
            # string can equal the oracle byte string by coincidence. That is NOT
            # a leak because the corresponding known_mask bits are zero and the
            # solver is explicitly forbidden from treating known_value bits at
            # unknown positions as semantic information.
            #
            # What matters is:
            #   - exactly the requested number of mask bits are zero;
            #   - all known_value bits at unknown positions are zero;
            #   - all known positions equal the oracle.
            # Those invariants are already enforced by component_is_safely_masked().

            serialized = json.dumps(challenge, indent=2, sort_keys=True) + "\n"
            low = serialized.lower()
            for forbidden in (
                "global_state_before_50_hex",
                "workspace_pre_mix_e00_hex",
                '"candidate_old_state_hex"',
                '"candidate_workspace_prefix_hex"',
            ):
                if forbidden in low:
                    raise SystemExit(
                        f"FAIL {instance_id}: oracle leakage token present: {forbidden}"
                    )

            filename = f"{instance_id}.json"
            path = output_dir / filename
            path.write_text(serialized, encoding="utf-8")
            challenge_sha = sha256_file(path)

            manifest_instances.append(
                {
                    "id": instance_id,
                    "profile": profile,
                    "k": k,
                    "unknown_bits_old_state": old_hidden,
                    "unknown_bits_workspace": ws_hidden,
                    "path": str(path.relative_to(root)),
                    "sha256": challenge_sha,
                }
            )

            print(
                f"{instance_id} old_unknown={old_hidden} "
                f"workspace_unknown={ws_hidden} "
                f"ORACLE_SELF_CHECK=PASS ISOLATION_CHECK=PASS "
                f"SHA256={challenge_sha}"
            )

    if len(manifest_instances) != 21:
        raise AssertionError("expected 21 reduced instances")

    manifest = {
        "schema": "cgr640-h-mixer-reduced-manifest-v1",
        "parent_challenge_sha256": EXPECTED_PARENT_CHALLENGE_SHA256,
        "instance_count": 21,
        "profiles": list(PROFILES),
        "k_values": list(K_VALUES),
        "solver_input_warning": (
            "The manifest is provenance/index metadata only and is excluded from "
            "solver input. Each benchmark run receives exactly one per-instance "
            "challenge file."
        ),
        "instances": manifest_instances,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("INSTANCE_COUNT=21")
    print("SERIALIZATION_MODE=ONE_INSTANCE_PER_FILE")
    print("CROSS_INSTANCE_LEAKAGE_GUARD=PASS")
    print("ORACLE_SERIALIZATION_CHECK=PASS")
    print(f"MANIFEST={manifest_path}")
    print(f"MANIFEST_SHA256={sha256_file(manifest_path)}")
    print("PHASE_H_MIXER_REDUCED_BUILD=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
