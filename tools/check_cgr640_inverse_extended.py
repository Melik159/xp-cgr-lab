#!/usr/bin/env python3
"""
Extended inverse baseline for CGR640_FULL_01.

Reconstructs backwards:
- rsaenh pre-runtime XKEY from final XKEY + the 640-byte returned output;
- each of the eight ADVAPI RC4 *KSA post-states* from only the final post-runtime
  RC4 state plus the known PRGA step count for that context.

Captured forward states are used only as oracles for equality checks.
Raw evidence is never modified.
"""

from __future__ import annotations
import argparse
import json
from pathlib import Path

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

def h20(v):
    b = bytes.fromhex(v[:40])
    if len(b) != 20:
        raise ValueError("expected 20 bytes")
    return b

def h258(v):
    b = bytes.fromhex(v)
    if len(b) != 258:
        raise ValueError(f"expected 258 bytes, got {len(b)}")
    return b

def provider_prev(state_after, out40):
    mod = 1 << 160
    x = int.from_bytes(state_after, "big")
    a = int.from_bytes(out40[:20], "big")
    b = int.from_bytes(out40[20:], "big")
    return ((x - a - b - 2) % mod).to_bytes(20, "big")

def rc4_reverse_steps(state258, steps):
    s = list(state258[:256])
    i, j = state258[256], state258[257]
    for _ in range(steps):
        s[i], s[j] = s[j], s[i]
        j = (j - s[i]) & 0xff
        i = (i - 1) & 0xff
    return bytes(s) + bytes((i, j))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "events", nargs="?", type=Path,
        default=Path("/home/hal/xp-cgr-lab/evidence/cgr640-full-01/events.jsonl")
    )
    args = ap.parse_args()

    raw = [
        json.loads(x)
        for x in args.events.read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]
    ev = canonicalize(raw)

    # -------- Provider: use only final XKEY and returned 640 bytes as inversion inputs.
    b14 = [
        e for e in ev
        if e.get("kind") == "B14_PROVIDER_RUNTIME_RETURN"
        and e.get("cgr_len") == 0x280
    ]
    b12 = [
        e for e in ev
        if e.get("kind") == "B12_PROVIDER_FIPS_ENTRY"
        and 260 <= e.get("seq", -1) <= 410
    ]
    if len(b14) != 1 or len(b12) != 16:
        raise SystemExit(f"FAIL provider shape B14={len(b14)} B12={len(b12)}")

    output640 = bytes.fromhex(b14[0]["output_hex"])
    final_xkey = h20(b14[0]["global_31958_hex"])
    if len(output640) != 640:
        raise SystemExit(f"FAIL final output length {len(output640)}")

    state = final_xkey
    recovered = [None] * 16
    provider_ok = True
    for idx in range(15, -1, -1):
        out40 = output640[idx*40:(idx+1)*40]
        state = provider_prev(state, out40)
        recovered[idx] = state
        oracle = h20(b12[idx]["state_before_20_hex"])
        provider_ok &= (state == oracle)

    print("PROVIDER_PRE_RUNTIME_XKEY=" + recovered[0].hex())
    print("PROVIDER_FROM_FINAL_OUTPUT=" + ("PASS" if provider_ok else "FAIL"))

    # -------- RC4: recover all eight KSA post-states from final states.
    # Canonical lifetime observed for this execution/model:
    # C0: 20 + 256 pre-runtime, then 20 + 20 runtime = 316 steps.
    # C1: 0 + 20 pre-runtime, then 20 + 20 runtime = 60 steps.
    # C2..C7: 0 pre-runtime, then 20 + 20 runtime = 40 steps.
    expected_total_steps = [316, 60, 40, 40, 40, 40, 40, 40]

    relevant = [
        e for e in ev
        if e.get("kind") in (
            "B07_ADVAPI_RC4_PRGA_ENTRY",
            "B08_ADVAPI_RC4_PRGA_RETURN",
        )
        and isinstance(e.get("prga_state"), int)
        and 0x24B000 <= e["prga_state"] < 0x24C000
    ]

    # Preserve first-seen context ordering C0..C7.
    ptrs = []
    for e in relevant:
        p = e["prga_state"]
        if p not in ptrs:
            ptrs.append(p)
    if len(ptrs) != 8:
        raise SystemExit("FAIL: expected 8 contexts, got " + repr([hex(x) for x in ptrs]))

    all_ok = True
    for ci, ptr in enumerate(ptrs):
        entries = [
            e for e in relevant
            if e["kind"] == "B07_ADVAPI_RC4_PRGA_ENTRY" and e["prga_state"] == ptr
        ]
        returns = [
            e for e in relevant
            if e["kind"] == "B08_ADVAPI_RC4_PRGA_RETURN" and e["prga_state"] == ptr
        ]
        if not entries or not returns:
            raise SystemExit(f"FAIL context C{ci}: missing entry/return")

        # Inversion input: only the final state after the final use.
        final_state = h258(returns[-1]["state_after_102_hex"])
        recovered_ksa_state = rc4_reverse_steps(final_state, expected_total_steps[ci])

        # Oracle only: state before the first use is exactly the KSA post-state.
        oracle_ksa_state = h258(entries[0]["state_before_102_hex"])
        ok = recovered_ksa_state == oracle_ksa_state
        all_ok &= ok

        print(
            f"C{ci} ptr={ptr:08x} total_steps={expected_total_steps[ci]:3d} "
            f"KSA_STATE_REVERSE={'PASS' if ok else 'FAIL'}"
        )

    print("RC4_FINAL_TO_KSA_STATE=" + ("PASS" if all_ok else "FAIL"))

    verdict = provider_ok and all_ok
    print("INVERSE_EXTENDED_VERDICT=" + ("PASS" if verdict else "FAIL"))
    return 0 if verdict else 1

if __name__ == "__main__":
    raise SystemExit(main())
