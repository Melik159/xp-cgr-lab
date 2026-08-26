#!/usr/bin/env python3
"""
Known-answer test harness for verify_inverse_candidate.py.

The verifier remains oracle-free. This harness alone reads the frozen
CGR640_FULL_01 trace to reconstruct the known XVAL and exercise:
  1) positive candidate -> PASS
  2) flip one known bit -> mask rejection
  3) flip one unknown bit -> mask preserved, cryptographic rejection

No oracle is written to disk.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path("/home/hal/xp-cgr-lab")
EVENTS = ROOT / "evidence/cgr640-full-01/events.jsonl"
V1 = ROOT / "evidence/inverse-benchmark-v1/provider-preimage-challenge.json"
V2 = ROOT / "evidence/inverse-benchmark-v2/reduced-challenges.json"
VERIFIER = ROOT / "tools/verify_inverse_candidate.py"
MOD160 = 1 << 160
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

def load_module(path):
    spec = importlib.util.spec_from_file_location("inverse_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main():
    for p in (EVENTS, V1, V2, VERIFIER):
        if not p.is_file():
            raise SystemExit(f"FAIL missing input: {p}")

    verifier = load_module(VERIFIER)
    v1 = json.loads(V1.read_text(encoding="utf-8"))
    v2 = json.loads(V2.read_text(encoding="utf-8"))

    raw = [
        json.loads(line)
        for line in EVENTS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ev = canonicalize(raw)
    b12 = [
        e for e in ev
        if e.get("kind") == "B12_PROVIDER_FIPS_ENTRY"
        and 260 <= e.get("seq", -1) <= 410
    ]
    if len(b12) != 16:
        raise SystemExit(f"FAIL B12 count={len(b12)}")

    oracle_by_block = {}
    for i, inst in enumerate(v1["instances"]):
        xkey = int(inst["xkey_before_hex"], 16)
        aux = int(b12[i]["aux_final_20_hex"][:40], 16)
        oracle_by_block[i] = ((xkey + aux) % MOD160).to_bytes(20, "big")

    pos_ok = 0
    neg_mask_ok = 0
    neg_crypto_ok = 0

    for inst in v2["instances"]:
        block = inst["block_index"]
        oracle = oracle_by_block[block]
        r = verifier.verify_candidate(inst, oracle)
        if r["VERDICT"]:
            pos_ok += 1

        unknown = set(inst["unknown_positions"])
        known_pos = next(p for p in range(160) if p not in unknown)
        bad_known_int = int.from_bytes(oracle, "big") ^ (1 << known_pos)
        r_known = verifier.verify_candidate(
            inst, bad_known_int.to_bytes(20, "big")
        )
        if (not r_known["KNOWN_MASK_MATCH"]) and (not r_known["VERDICT"]):
            neg_mask_ok += 1

        unknown_pos = inst["unknown_positions"][0]
        bad_unknown_int = int.from_bytes(oracle, "big") ^ (1 << unknown_pos)
        r_unknown = verifier.verify_candidate(
            inst, bad_unknown_int.to_bytes(20, "big")
        )
        if (
            r_unknown["KNOWN_MASK_MATCH"]
            and not r_unknown["VERDICT"]
            and (not r_unknown["OUT_A_MATCH"] or not r_unknown["OUT_B_MATCH"])
        ):
            neg_crypto_ok += 1

    total = len(v2["instances"])
    print(f"INSTANCE_COUNT={total}")
    print(f"POSITIVE_KAT={pos_ok}/{total}")
    print(f"NEGATIVE_MASK={neg_mask_ok}/{total}")
    print(f"NEGATIVE_CRYPTO={neg_crypto_ok}/{total}")

    verdict = (
        total == 112
        and pos_ok == total
        and neg_mask_ok == total
        and neg_crypto_ok == total
    )
    print(f"PHASE_B_VERIFIER={'PASS' if verdict else 'FAIL'}")
    return 0 if verdict else 1

if __name__ == "__main__":
    raise SystemExit(main())
