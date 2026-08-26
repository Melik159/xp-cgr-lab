#!/usr/bin/env python3
"""
KAT driver for the independent reduced H-MIXER verifier.

This helper is allowed to read oracle material solely to test the verifier.
It is NOT part of the solver input contract.

Controls:
  - positive oracle KAT for OLD-K08, WS-K08, SPLIT-K08;
  - hidden-bit negative KAT for each hidden component;
  - published-bit mutation rejection.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

EXPECTED_EVENTS_SHA256 = (
    "f0ceb2775e3458ff5c204bd353c39cc7efe835f8a4fa972323a44d594b7a3acf"
)
EXPECTED_VERIFIER_SHA256 = (
    "c59e87e857c00d2ee936907b0a539cfa055025731e11b207b8f038d2717d67a1"
)
EXPECTED_MANIFEST_SHA256 = (
    "c389308a185877d2fae3cedba84ddb03e9c2a4501d45ed13a3b4196366c8fc5d"
)
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
    out = []
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


def load_oracle(events_path: Path) -> tuple[bytes, bytes]:
    raw = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    events = canonicalize(raw)
    matches = [
        event for event in events
        if event.get("kind") == "K13_PRE_MIX" and event.get("seq") == 24
    ]
    if len(matches) != 1:
        raise SystemExit(f"FAIL expected canonical K13 seq=24, got {len(matches)}")
    event = matches[0]
    used = event.get("used")
    if used != 600:
        raise SystemExit(f"FAIL expected used=600, got {used!r}")
    old_state = bytes.fromhex(event["global_state_before_50_hex"])
    workspace = bytes.fromhex(event["workspace_pre_mix_e00_hex"])[:used]
    if len(old_state) != 80 or len(workspace) != 600:
        raise SystemExit("FAIL oracle lengths")
    return old_state, workspace


def first_bit(mask: bytes, wanted_known: bool) -> tuple[int, int]:
    # Return byte index and one-bit mask.
    for byte_index, value in enumerate(mask):
        for bit in range(8):
            bitmask = 1 << bit
            is_known = bool(value & bitmask)
            if is_known == wanted_known:
                return byte_index, bitmask
    raise ValueError("requested bit class not found")


def mutate(raw: bytes, byte_index: int, bitmask: int) -> bytes:
    out = bytearray(raw)
    out[byte_index] ^= bitmask
    return bytes(out)


def run_case(
    verifier: Path,
    challenge: Path,
    instance_id: str,
    old_state: bytes,
    workspace: bytes,
    expected_rc: int,
    label: str,
) -> None:
    proc = subprocess.run(
        [
            "python3",
            str(verifier),
            instance_id,
            old_state.hex(),
            workspace.hex(),
            "--challenge",
            str(challenge),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print(f"--- {label} ---")
    print(proc.stdout.rstrip())
    print(f"{label}_EXIT={proc.returncode}")
    if proc.returncode != expected_rc:
        raise SystemExit(
            f"FAIL {label}: expected exit {expected_rc}, got {proc.returncode}"
        )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    events_path = root / "evidence/cgr640-full-01/events.jsonl"
    verifier = root / "tools/verify_phase_h_mixer_reduced_candidate.py"
    manifest = (
        root
        / "evidence/inverse-benchmark-v2/phase-h-mixer-reduced-manifest.json"
    )
    challenge_dir = (
        root / "evidence/inverse-benchmark-v2/phase-h-mixer-reduced"
    )

    pins = (
        (events_path, EXPECTED_EVENTS_SHA256, "events"),
        (verifier, EXPECTED_VERIFIER_SHA256, "verifier"),
        (manifest, EXPECTED_MANIFEST_SHA256, "manifest"),
    )
    for path, expected, label in pins:
        actual = sha256_file(path)
        if actual != expected:
            raise SystemExit(
                f"FAIL {label} SHA-256 mismatch: expected={expected} actual={actual}"
            )

    old_oracle, ws_oracle = load_oracle(events_path)

    ids = (
        "H-MIXER-00-OLD-K08",
        "H-MIXER-00-WS-K08",
        "H-MIXER-00-SPLIT-K08",
    )

    # Positive oracle KATs.
    for instance_id in ids:
        challenge = challenge_dir / f"{instance_id}.json"
        run_case(
            verifier,
            challenge,
            instance_id,
            old_oracle,
            ws_oracle,
            0,
            f"POS_{instance_id}",
        )

    # Hidden-bit negative KATs, driven by each challenge's masks.
    for instance_id in ids:
        challenge = challenge_dir / f"{instance_id}.json"
        data = json.loads(challenge.read_text(encoding="utf-8"))
        inst = data["instances"][0]
        old_mask = bytes.fromhex(inst["old_state_known_mask_hex"])
        ws_mask = bytes.fromhex(inst["workspace_known_mask_hex"])

        if inst["unknown_bits_old_state"] > 0:
            bi, bm = first_bit(old_mask, wanted_known=False)
            run_case(
                verifier,
                challenge,
                instance_id,
                mutate(old_oracle, bi, bm),
                ws_oracle,
                1,
                f"NEG_HIDDEN_OLD_{instance_id}",
            )

        if inst["unknown_bits_workspace"] > 0:
            bi, bm = first_bit(ws_mask, wanted_known=False)
            run_case(
                verifier,
                challenge,
                instance_id,
                old_oracle,
                mutate(ws_oracle, bi, bm),
                1,
                f"NEG_HIDDEN_WS_{instance_id}",
            )

    # Published-bit mutation: use OLD-K08 and flip one known old-state bit.
    instance_id = "H-MIXER-00-OLD-K08"
    challenge = challenge_dir / f"{instance_id}.json"
    data = json.loads(challenge.read_text(encoding="utf-8"))
    inst = data["instances"][0]
    old_mask = bytes.fromhex(inst["old_state_known_mask_hex"])
    bi, bm = first_bit(old_mask, wanted_known=True)
    run_case(
        verifier,
        challenge,
        instance_id,
        mutate(old_oracle, bi, bm),
        ws_oracle,
        1,
        "NEG_PUBLISHED_OLD_OLD_K08",
    )

    print("POSITIVE_KATS=3/3")
    print("NEGATIVE_HIDDEN_COMPONENT_KATS=4/4")
    print("NEGATIVE_PUBLISHED_BIT_KATS=1/1")
    print("PHASE_H_MIXER_REDUCED_VERIFIER_KAT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
