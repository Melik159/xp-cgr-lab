#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DROP = {"seq", "host_time_ns", "accepted_block_index"}
EXPECTED_EVENTS_SHA256 = "f0ceb2775e3458ff5c204bd353c39cc7efe835f8a4fa972323a44d594b7a3acf"
DEFAULT_EVENTS = Path("/home/hal/xp-cgr-lab/evidence/cgr640-full-01/events.jsonl")
DEFAULT_OUTPUT = Path("/home/hal/xp-cgr-lab/evidence/inverse-benchmark-v2/phase-h-ksa-challenge.json")

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def fp(e: dict) -> str:
    return json.dumps({k: v for k, v in e.items() if k not in DROP},
                      sort_keys=True, separators=(",", ":"))

def canonicalize(events: list[dict]) -> list[dict]:
    out = []
    i = 0
    while i < len(events):
        e = events[i]
        j = i + 1
        while j < len(events) and events[j].get("kind") == e.get("kind") and fp(events[j]) == fp(e):
            j += 1
        out.append(e)
        i = j
    return out

def decode_hex(value, expected_len: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field}: missing hex string")
    raw = bytes.fromhex(value)
    if len(raw) != expected_len:
        raise ValueError(f"{field}: expected {expected_len} bytes, got {len(raw)}")
    return raw

def rc4_ksa(key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    return bytes(state) + b"\x00\x00"

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("events", nargs="?", type=Path, default=DEFAULT_EVENTS)
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = ap.parse_args()

    events_sha = sha256(args.events)
    if events_sha != EXPECTED_EVENTS_SHA256:
        raise SystemExit(f"FAIL events SHA-256 mismatch: {events_sha}")

    raw = [json.loads(line) for line in args.events.read_text(encoding="utf-8").splitlines() if line.strip()]
    ev = canonicalize(raw)
    k16 = [e for e in ev if e.get("kind") == "K16_FINAL_RC4_KSA" and e.get("seq", 10**9) < 260]
    if len(k16) != 8:
        raise SystemExit(f"FAIL expected 8 canonical K16 events, got {len(k16)}")

    instances = []
    oracle_ok = True
    forbidden = []

    for idx, e in enumerate(k16):
        oracle = decode_hex(e.get("global_state_50_hex"), 80, "global_state_50_hex")
        target = decode_hex(e.get("rc4_context_102_hex"), 258, "rc4_context_102_hex")
        ok = rc4_ksa(oracle) == target
        oracle_ok &= ok
        forbidden.append(oracle.hex())
        print(f"H-KSA-{idx:02d} ORACLE_SELF_CHECK={'PASS' if ok else 'FAIL'}")
        instances.append({
            "id": f"H-KSA-{idx:02d}",
            "source_seq": e.get("seq"),
            "key_len_bytes": 80,
            "target_post_ksa_hex": target.hex(),
            "target_post_ksa_sha256": hashlib.sha256(target).hexdigest(),
        })

    if not oracle_ok:
        raise SystemExit("FAIL H-KSA oracle self-check")

    challenge = {
        "schema": "cgr640-h-ksa-v1",
        "source_events_sha256": events_sha,
        "relation": "RC4_KSA(new_state_80) == target_post_ksa_258",
        "unknown": "new_state_80",
        "instances": instances,
    }
    serialized = json.dumps(challenge, indent=2, sort_keys=True) + "\n"
    low = serialized.lower()
    if any(x in low for x in forbidden):
        raise SystemExit("FAIL oracle new_state leaked into challenge")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(serialized, encoding="utf-8")

    print("INSTANCE_COUNT=8")
    print("ORACLE_SELF_CHECK=PASS")
    print("ORACLE_SERIALIZATION_CHECK=PASS")
    print("CHALLENGE=" + str(args.output))
    print("CHALLENGE_SHA256=" + sha256(args.output))
    print("PHASE_H_KSA_CHALLENGE=PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
