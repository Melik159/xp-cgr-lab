#!/usr/bin/env python3
"""
Build one oracle-isolated Phase-H KSec mixer challenge.

Important: the eight captured KSec mixer invocations form a state chain:
    old_state[i] == new_state[i-1]  for i=1..7

Therefore serializing all eight target new_state values in one challenge would
reveal the old_state oracle for instances 1..7. This builder deliberately
serializes exactly one selected instance per challenge file.

The captured old_state and workspace prefix are used only for self-checks and
are never serialized.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

EXPECTED_EVENTS_SHA256 = (
    "f0ceb2775e3458ff5c204bd353c39cc7efe835f8a4fa972323a44d594b7a3acf"
)
EXPECTED_UPSTREAM_SHA256 = (
    "13be039ed472d794cbbc3bec33a6f6c9e6bedff44af01333c5dae52eaf52d4fa"
)

DEFAULT_ROOT = Path("/home/hal/xp-cgr-lab")
DEFAULT_UPSTREAM = Path(
    "/home/hal/Téléchargements/xp-cgr-replay-release/"
    "deterministic-replay/tools/check_kernel_fullchain.py"
)

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


def load_upstream(path: Path):
    spec = importlib.util.spec_from_file_location("phase_h_ksec_upstream", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def decode_hex(value, expected_len: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field}: missing hex string")
    raw = bytes.fromhex(value)
    if len(raw) != expected_len:
        raise ValueError(
            f"{field}: expected {expected_len} bytes, got {len(raw)}"
        )
    return raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--upstream", type=Path, default=DEFAULT_UPSTREAM)
    ap.add_argument("--instance-index", type=int, default=0)
    ap.add_argument("--output", type=Path, default=None)
    args = ap.parse_args()

    if not 0 <= args.instance_index < 8:
        raise SystemExit("FAIL instance-index must be 0..7")

    events_path = args.root / "evidence/cgr640-full-01/events.jsonl"
    output_path = args.output or (
        args.root
        / "evidence/inverse-benchmark-v2"
        / "phase-h-mixer-challenge.json"
    )

    if not events_path.is_file():
        raise SystemExit(f"FAIL missing input: {events_path}")
    if not args.upstream.is_file():
        raise SystemExit(f"FAIL missing upstream: {args.upstream}")

    events_sha = sha256_file(events_path)
    upstream_sha = sha256_file(args.upstream)

    if events_sha != EXPECTED_EVENTS_SHA256:
        raise SystemExit(f"FAIL events SHA-256 mismatch: {events_sha}")
    if upstream_sha != EXPECTED_UPSTREAM_SHA256:
        raise SystemExit(f"FAIL upstream SHA-256 mismatch: {upstream_sha}")

    upstream = load_upstream(args.upstream)

    raw = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ev = canonicalize(raw)

    pre = [
        e for e in ev
        if e.get("kind") == "K13_PRE_MIX"
        and e.get("seq", 10**9) < 260
    ]
    post = [
        e for e in ev
        if e.get("kind") == "K14_POST_MIX"
        and e.get("seq", 10**9) < 260
    ]

    if len(pre) != 8 or len(post) != 8:
        raise SystemExit(
            f"FAIL expected 8 K13 and 8 K14 events, got {len(pre)} / {len(post)}"
        )

    decoded = []
    all_ok = True

    for idx, (before, after) in enumerate(zip(pre, post)):
        used = before.get("used")
        if not isinstance(used, int) or not (0 < used <= 0xE00) or used % 4:
            raise SystemExit(f"FAIL H-MIXER-{idx:02d}: invalid used={used!r}")

        workspace = decode_hex(
            before.get("workspace_pre_mix_e00_hex"),
            0xE00,
            "workspace_pre_mix_e00_hex",
        )
        old_state = decode_hex(
            before.get("global_state_before_50_hex"),
            0x50,
            "global_state_before_50_hex",
        )
        new_state = decode_hex(
            after.get("state_after_mix_50_hex"),
            0x50,
            "state_after_mix_50_hex",
        )

        replay = upstream.replay_mixer(workspace, used, old_state)
        ok = replay == new_state
        all_ok &= ok
        print(
            f"H-MIXER-{idx:02d} used={used} "
            f"ORACLE_SELF_CHECK={'PASS' if ok else 'FAIL'}"
        )

        decoded.append((used, workspace, old_state, new_state, before, after))

    if not all_ok:
        raise SystemExit("FAIL mixer oracle self-check")

    chain_ok = all(
        decoded[i][2] == decoded[i - 1][3]
        for i in range(1, 8)
    )
    if not chain_ok:
        raise SystemExit("FAIL expected 7/7 KSec state-chain links")

    print("STATE_CHAIN_LINKS=7/7")
    print("CHAIN_CONTINUITY_CHECK=PASS")

    idx = args.instance_index
    used, workspace, old_state, new_state, before, after = decoded[idx]

    instance = {
        "id": f"H-MIXER-{idx:02d}",
        "source_pre_seq": before.get("seq"),
        "source_post_seq": after.get("seq"),
        "used": used,
        "old_state_len_bytes": 80,
        "workspace_prefix_len_bytes": used,
        "target_new_state_hex": new_state.hex(),
        "target_new_state_sha256": hashlib.sha256(new_state).hexdigest(),
    }

    challenge = {
        "schema": "cgr640-h-mixer-v1",
        "source_events_sha256": events_sha,
        "upstream_model_sha256": upstream_sha,
        "isolation": "single-sequential-instance",
        "isolation_reason": (
            "Captured mixer calls are state-chained: old_state[i] equals "
            "new_state[i-1]. Sequential targets must not be co-serialized "
            "when old_state is designated hidden."
        ),
        "solver_input_contract": (
            "Solver may read this challenge file only; captured event logs, "
            "other mixer challenge instances, and oracle files are excluded."
        ),
        "relation": (
            "replay_mixer(workspace_prefix, used, old_state_80) "
            "== target_new_state_80"
        ),
        "unknowns": [
            "old_state_80",
            "workspace_prefix_used",
        ],
        "instances": [instance],
    }

    serialized = json.dumps(challenge, indent=2, sort_keys=True) + "\n"
    low = serialized.lower()

    # Same-instance oracle leakage guard.
    if old_state.hex().lower() in low:
        raise SystemExit("FAIL selected old_state oracle leaked into challenge")
    if workspace[:used].hex().lower() in low:
        raise SystemExit("FAIL selected workspace oracle leaked into challenge")

    for token in (
        "global_state_before_50_hex",
        "workspace_pre_mix_e00_hex",
        '"old_state_hex"',
        '"workspace_prefix_hex"',
    ):
        if token in low:
            raise SystemExit(f"FAIL oracle leakage token present: {token}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(serialized, encoding="utf-8")

    print(f"SELECTED_INSTANCE=H-MIXER-{idx:02d}")
    print("SERIALIZED_INSTANCE_COUNT=1")
    print("ORACLE_SELF_CHECK=PASS")
    print("ORACLE_SERIALIZATION_CHECK=PASS")
    print("CHALLENGE=" + str(output_path))
    print("CHALLENGE_SHA256=" + sha256_file(output_path))
    print("PHASE_H_MIXER_CHALLENGE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
