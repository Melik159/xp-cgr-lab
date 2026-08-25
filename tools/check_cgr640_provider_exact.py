#!/usr/bin/env python3
"""
Close the provider half of CGR640_FULL_01 from the GDB JSONL.

Uses the already published check_strict_e2e.py primitives for ADVAPI RC4 and
rsaenh FIPS/provider replay. Raw events.jsonl is never modified.
"""

from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

DROP = {"seq", "host_time_ns", "accepted_block_index"}

DEFAULT_STRICT = Path(
    "/home/hal/Téléchargements/xp-cgr-replay-release/"
    "deterministic-replay/tools/check_strict_e2e.py"
)

TARGET_KINDS = [
    "B10_PROVIDER_BEFORE_SYSTEMFUNCTION036",
    "B05_SYSTEMFUNCTION036_ENTRY",
    "B07_ADVAPI_RC4_PRGA_ENTRY",
    "B08_ADVAPI_RC4_PRGA_RETURN",
    "B06_SYSTEMFUNCTION036_RETURN",
    "B11_PROVIDER_AFTER_SYSTEMFUNCTION036",
    "B12_PROVIDER_FIPS_ENTRY",
    "B13_PROVIDER_FIPS_RETURN",
]

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

def first20(h):
    if not isinstance(h, str):
        return None
    return bytes.fromhex(h[:40])

def allbytes(h):
    if not isinstance(h, str):
        return None
    return bytes.fromhex(h)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "events", nargs="?", type=Path,
        default=Path("/home/hal/xp-cgr-lab/evidence/cgr640-full-01/events.jsonl")
    )
    ap.add_argument("--strict", type=Path, default=DEFAULT_STRICT)
    args = ap.parse_args()

    if not args.strict.is_file():
        raise SystemExit(f"FAIL: strict checker not found: {args.strict}")
    strict = load_strict(args.strict)

    raw = [
        json.loads(x)
        for x in args.events.read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]
    ev = canonicalize(raw)

    # Locate the one measured 640-byte D640 invocation.
    starts = [
        e for e in ev
        if e.get("kind") == "B10_PROVIDER_BEFORE_SYSTEMFUNCTION036"
        and e.get("cgr_len") == 0x280
        and e.get("cgr_remaining") == 0x280
    ]
    if len(starts) != 1:
        raise SystemExit(f"FAIL: expected one 640-byte start, got {len(starts)}")
    start = starts[0]
    cid = start.get("d640_call_id")

    ends = [
        e for e in ev
        if e.get("kind") == "B14_PROVIDER_RUNTIME_RETURN"
        and e.get("d640_call_id") == cid
        and e.get("cgr_len") == 0x280
        and e.get("seq", -1) >= start["seq"]
    ]
    if len(ends) != 1:
        raise SystemExit(f"FAIL: expected one 640-byte return, got {len(ends)}")
    end = ends[0]

    region = [e for e in ev if start["seq"] <= e["seq"] <= end["seq"]]
    t = [e for e in region if e["kind"] in TARGET_KINDS]

    expected = TARGET_KINDS * 16
    got = [e["kind"] for e in t]
    if got != expected:
        raise SystemExit("FAIL: canonical provider event ordering is not 16 exact cycles")

    blocks = []
    prior_provider_state_after = None
    all_ok = True
    reports = []

    for i in range(16):
        b10, b05, b07, b08, b06, b11, b12, b13 = t[i*8:(i+1)*8]
        c = {}

        rem_expected = 640 - 40*i
        c["remaining"] = b10.get("cgr_remaining") == rem_expected
        c["s036_len"] = b05.get("sysfunc_len") == 20 and b06.get("sysfunc_len") == 20
        c["rc4_len"] = b07.get("prga_len") == 20 and b08.get("prga_len") == 20
        c["fips_len"] = b12.get("provider_len") == 20 and b13.get("provider_len") == 20

        # S036 input is the current 20-byte D640 local.
        d640_local_before = first20(b10.get("provider_aux_before_20_hex"))
        s036_before = first20(b05.get("sys_before_20_hex"))
        c["d640_to_s036"] = d640_local_before == s036_before

        # Exact ADVAPI RC4 replay.
        rc4_state_before = allbytes(b07.get("state_before_102_hex"))
        rc4_in = first20(b07.get("out_before_20_hex"))
        if rc4_state_before is None or rc4_in is None:
            rc4_out = rc4_state_after = None
        else:
            rc4_out, rc4_state_after = strict.rc4_replay(
                rc4_state_before, rc4_in, 20
            )
        c["rc4_state_replay"] = (
            rc4_state_after == allbytes(b08.get("state_after_102_hex"))
        )
        c["rc4_output_replay"] = (
            rc4_out == first20(b08.get("out_after_20_hex"))
        )
        c["s036_equals_rc4"] = (
            first20(b06.get("sys_after_20_hex")) == rc4_out
        )
        c["provider_raw_equals_s036"] = (
            first20(b11.get("provider_sysfunc_raw20_hex")) == rc4_out
        )

        # Exact D640 XOR.
        caller20 = first20(b10.get("caller_current_20_hex"))
        aux_observed = first20(b12.get("aux_final_20_hex"))
        aux_calc = (
            bytes(a ^ b for a, b in zip(rc4_out, caller20))
            if rc4_out is not None and caller20 is not None
            else None
        )
        c["d640_xor"] = aux_calc == aux_observed

        # Exact rsaenh FIPS/provider replay.
        state_before = first20(b12.get("state_before_20_hex"))
        if state_before is None or aux_observed is None:
            out40_calc = state_after_calc = None
        else:
            out40_calc, state_after_calc = strict.provider_block(
                state_before, aux_observed
            )

        out40_observed = allbytes(b13.get("out40_after_hex"))
        state_after_observed = first20(b13.get("state_after_20_hex"))
        c["provider_out40_replay"] = out40_calc == out40_observed
        c["provider_state_replay"] = state_after_calc == state_after_observed
        c["provider_state_continuity"] = (
            prior_provider_state_after is None
            or state_before == prior_provider_state_after
        )
        prior_provider_state_after = state_after_observed

        failed = [k for k, v in c.items() if not v]
        ok = not failed
        all_ok &= ok
        if out40_observed is not None:
            blocks.append(out40_observed)

        reports.append({
            "iteration": i,
            "remaining": b10.get("cgr_remaining"),
            "seq_span": [b10["seq"], b13["seq"]],
            "checks": c,
            "failed": failed,
            "verdict": "PASS" if ok else "FAIL",
        })

        print(
            f"I{i:02d} rem={b10.get('cgr_remaining'):3d} "
            f"RC4={'PASS' if c['rc4_state_replay'] and c['rc4_output_replay'] else 'FAIL'} "
            f"XOR={'PASS' if c['d640_xor'] else 'FAIL'} "
            f"FIPS={'PASS' if c['provider_out40_replay'] and c['provider_state_replay'] else 'FAIL'} "
            f"STATE={'PASS' if c['provider_state_continuity'] else 'FAIL'} "
            f"overall={'PASS' if ok else 'FAIL'}"
        )
        if failed:
            print("  FAILED=" + ",".join(failed))

    final640_calc = b"".join(blocks)
    final640_observed = allbytes(end.get("output_hex"))
    final_state = first20(end.get("global_31958_hex"))

    final_checks = {
        "sixteen_blocks": len(blocks) == 16 and len(final640_calc) == 640,
        "concat_out40_equals_b14_640": final640_calc == final640_observed,
        "final_global_31958_equals_provider_state": final_state == prior_provider_state_after,
    }

    caller_after = args.events.parent / "caller-after.bin"
    if caller_after.is_file():
        final_checks["caller_after_bin_equals_b14"] = (
            caller_after.read_bytes() == final640_observed
        )
    else:
        final_checks["caller_after_bin_equals_b14"] = False

    all_ok &= all(final_checks.values())

    print("\n=== FINAL 640 ===")
    for k, v in final_checks.items():
        print(k + "=" + ("PASS" if v else "FAIL"))
    if final640_observed is not None:
        print("CGR640_SHA256=" + hashlib.sha256(final640_observed).hexdigest())

    report = args.events.parent / "provider640-exact-replay-report.json"
    report.write_text(
        json.dumps({
            "events": str(args.events),
            "events_sha256": hashlib.sha256(args.events.read_bytes()).hexdigest(),
            "strict_checker": str(args.strict),
            "strict_checker_sha256": hashlib.sha256(args.strict.read_bytes()).hexdigest(),
            "target_call_id": cid,
            "target_seq_range": [start["seq"], end["seq"]],
            "iterations": reports,
            "final_checks": final_checks,
            "verdict": "PASS" if all_ok else "FAIL",
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("PROVIDER640_EXACT_REPLAY=" + ("PASS" if all_ok else "FAIL"))
    print("REPORT=" + str(report))
    print("REPORT_SHA256=" + hashlib.sha256(report.read_bytes()).hexdigest())
    return 0 if all_ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
