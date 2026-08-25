#!/usr/bin/env python3
"""
Inverse baseline for CGR640_FULL_01.

Demonstrates which runtime state can be reconstructed *backwards* without
inverting SHA-1 or RC4 KSA:

1) rsaenh provider XKEY:
   XKEY_after = XKEY_before + out_a + out_b + 2 mod 2^160
   so XKEY_before is recovered exactly from XKEY_after and the 40-byte block.

2) ADVAPI RC4 PRGA state:
   each PRGA step is a bijection on (S,i,j), so 20-byte calls can be reversed
   from the post-state alone.  Two runtime uses per context => reverse 40 steps.

The script compares every recovered state against the forward-capture oracle.
Raw evidence is never modified.
"""

from __future__ import annotations
import argparse
import hashlib
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
    if not isinstance(v, str):
        raise ValueError("missing 20-byte hex field")
    return bytes.fromhex(v[:40])

def h258(v):
    if not isinstance(v, str):
        raise ValueError("missing 258-byte hex field")
    b = bytes.fromhex(v)
    if len(b) != 258:
        raise ValueError(f"expected 258 bytes, got {len(b)}")
    return b

def provider_prev_state(state_after: bytes, out40: bytes) -> bytes:
    if len(state_after) != 20 or len(out40) != 40:
        raise ValueError("bad provider lengths")
    mod = 1 << 160
    after = int.from_bytes(state_after, "big")
    a = int.from_bytes(out40[:20], "big")
    b = int.from_bytes(out40[20:], "big")
    before = (after - a - b - 2) % mod
    return before.to_bytes(20, "big")

def rc4_reverse_steps(state258: bytes, steps: int) -> bytes:
    if len(state258) != 258:
        raise ValueError("RC4 state must be 258 bytes")
    s = list(state258[:256])
    i = state258[256]
    j = state258[257]
    for _ in range(steps):
        # Forward step ended with swap S[i],S[j].
        s[i], s[j] = s[j], s[i]
        # After undoing the swap, s[i] is the pre-swap S[i].
        j = (j - s[i]) & 0xFF
        i = (i - 1) & 0xFF
    return bytes(s) + bytes((i, j))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "events",
        nargs="?",
        type=Path,
        default=Path("/home/hal/xp-cgr-lab/evidence/cgr640-full-01/events.jsonl"),
    )
    args = ap.parse_args()

    raw = [
        json.loads(line)
        for line in args.events.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ev = canonicalize(raw)

    # ---- Provider backward reconstruction ----
    b12 = [
        e for e in ev
        if e.get("kind") == "B12_PROVIDER_FIPS_ENTRY"
        and 260 <= e.get("seq", -1) <= 410
    ]
    b13 = [
        e for e in ev
        if e.get("kind") == "B13_PROVIDER_FIPS_RETURN"
        and 260 <= e.get("seq", -1) <= 410
    ]
    b14 = [
        e for e in ev
        if e.get("kind") == "B14_PROVIDER_RUNTIME_RETURN"
        and e.get("cgr_len") == 0x280
    ]
    if len(b12) != 16 or len(b13) != 16 or len(b14) != 1:
        raise SystemExit(
            f"FAIL provider shape B12={len(b12)} B13={len(b13)} B14={len(b14)}"
        )

    state = h20(b14[0]["global_31958_hex"])
    provider_ok = True
    recovered = [None] * 16

    for i in range(15, -1, -1):
        out40 = bytes.fromhex(b13[i]["out40_after_hex"])
        if len(out40) != 40:
            raise SystemExit(f"FAIL block {i}: out40 len={len(out40)}")
        state = provider_prev_state(state, out40)
        recovered[i] = state
        observed = h20(b12[i]["state_before_20_hex"])
        same = state == observed
        provider_ok &= same
        print(
            f"PROVIDER I{i:02d} reverse={'PASS' if same else 'FAIL'} "
            f"state={state.hex()}"
        )

    print("PROVIDER_BACKWARD_CHAIN=" + ("PASS" if provider_ok else "FAIL"))
    print("PROVIDER_PRE_RUNTIME_XKEY=" + recovered[0].hex())

    # ---- RC4 backward reconstruction ----
    runtime_b07 = [
        e for e in ev
        if e.get("kind") == "B07_ADVAPI_RC4_PRGA_ENTRY"
        and 260 <= e.get("seq", -1) <= 410
        and e.get("prga_len") == 20
    ]
    runtime_b08 = [
        e for e in ev
        if e.get("kind") == "B08_ADVAPI_RC4_PRGA_RETURN"
        and 260 <= e.get("seq", -1) <= 410
    ]
    if len(runtime_b07) != 16 or len(runtime_b08) != 16:
        raise SystemExit(
            f"FAIL runtime RC4 shape B07={len(runtime_b07)} B08={len(runtime_b08)}"
        )

    # Group the two runtime uses of each context pointer.
    uses = {}
    for a, b in zip(runtime_b07, runtime_b08):
        ptr = a["prga_state"]
        uses.setdefault(ptr, []).append((a, b))

    if len(uses) != 8 or any(len(v) != 2 for v in uses.values()):
        raise SystemExit(
            "FAIL expected 8 RC4 contexts used twice: "
            + repr({hex(k): len(v) for k, v in uses.items()})
        )

    rc4_ok = True
    for ptr, pair in sorted(uses.items()):
        first_a, first_b = pair[0]
        second_a, second_b = pair[1]

        # Start only from the final post-state after the second runtime use.
        final_state = h258(second_b["state_after_102_hex"])

        # Reverse the second 20-byte use and compare with its captured pre-state.
        recovered_second_pre = rc4_reverse_steps(final_state, 20)
        observed_second_pre = h258(second_a["state_before_102_hex"])
        ok2 = recovered_second_pre == observed_second_pre

        # Reverse another 20 steps to recover the pre-runtime state.
        recovered_pre_runtime = rc4_reverse_steps(recovered_second_pre, 20)
        observed_pre_runtime = h258(first_a["state_before_102_hex"])
        ok1 = recovered_pre_runtime == observed_pre_runtime

        rc4_ok &= ok1 and ok2
        print(
            f"RC4 ptr={ptr:08x} "
            f"second_pre={'PASS' if ok2 else 'FAIL'} "
            f"pre_runtime={'PASS' if ok1 else 'FAIL'} "
            f"pre_sha256={hashlib.sha256(recovered_pre_runtime).hexdigest()}"
        )

    print("RC4_BACKWARD_CHAIN=" + ("PASS" if rc4_ok else "FAIL"))

    verdict = provider_ok and rc4_ok
    print("INVERSE_BASELINE_VERDICT=" + ("PASS" if verdict else "FAIL"))
    return 0 if verdict else 1

if __name__ == "__main__":
    raise SystemExit(main())
