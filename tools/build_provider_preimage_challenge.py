#!/usr/bin/env python3
"""
Build a solver-neutral provider preimage benchmark from CGR640_FULL_01.

The challenge itself is derived only from:
  - the final rsaenh XKEY after the 640-byte call;
  - the returned 640 bytes.

For each of 16 independent 40-byte provider blocks it reconstructs XKEY_before
algebraically, then defines a 160-bit preimage problem:

    out_a = G(xval)
    out_b = G(xval + out_a + 1 mod 2^160)

where G(x) is the published SHA-1 compression on x || 44 zero bytes with the
standard SHA-1 IV, and:

    aux = xval - XKEY_before mod 2^160.

Captured intermediate AUX values are used only for an oracle self-check and are
NOT serialized into the challenge JSON.
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

def add160(*parts):
    return (sum(int.from_bytes(x, "big") for x in parts) % (1 << 160)).to_bytes(20, "big")

def sub160(a, b):
    return ((int.from_bytes(a, "big") - int.from_bytes(b, "big")) % (1 << 160)).to_bytes(20, "big")

def prev_xkey(state_after, out40):
    a, b = out40[:20], out40[20:]
    value = (
        int.from_bytes(state_after, "big")
        - int.from_bytes(a, "big")
        - int.from_bytes(b, "big")
        - 2
    ) % (1 << 160)
    return value.to_bytes(20, "big")

def G(strict, xval):
    return strict.sha1_compress_one(xval + b"\x00" * 44)

def verify_xval(strict, xkey_before, out40, xval):
    out_a = out40[:20]
    out_b = out40[20:]
    calc_a = G(strict, xval)
    state_a = add160(xkey_before, out_a, (1).to_bytes(20, "big"))
    # Equivalent relation: xval_b = xval + out_a + 1.
    xval_b = add160(xval, out_a, (1).to_bytes(20, "big"))
    calc_b = G(strict, xval_b)
    return {
        "out_a": calc_a == out_a,
        "out_b": calc_b == out_b,
        "state_relation": state_a == add160(xkey_before, out_a, (1).to_bytes(20, "big")),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "events", nargs="?", type=Path,
        default=Path("/home/hal/xp-cgr-lab/evidence/cgr640-full-01/events.jsonl")
    )
    ap.add_argument("--strict", type=Path, default=DEFAULT_STRICT)
    ap.add_argument(
        "--output",
        type=Path,
        default=Path("/home/hal/xp-cgr-lab/evidence/inverse-benchmark-v1/provider-preimage-challenge.json"),
    )
    ap.add_argument("--verify-index", type=int)
    ap.add_argument("--xval", help="candidate 20-byte XVAL as 40 hex chars")
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

    b14 = [
        e for e in ev
        if e.get("kind") == "B14_PROVIDER_RUNTIME_RETURN"
        and e.get("cgr_len") == 0x280
    ]
    if len(b14) != 1:
        raise SystemExit(f"FAIL: expected one target B14, got {len(b14)}")

    output640 = bytes.fromhex(b14[0]["output_hex"])
    final_xkey = bytes.fromhex(b14[0]["global_31958_hex"][:40])
    if len(output640) != 640 or len(final_xkey) != 20:
        raise SystemExit("FAIL: malformed final evidence")

    states_before = [None] * 16
    state = final_xkey
    for i in range(15, -1, -1):
        out40 = output640[i*40:(i+1)*40]
        state = prev_xkey(state, out40)
        states_before[i] = state

    challenge = {
        "schema": "cgr640-provider-preimage-v1",
        "source_events_sha256": hashlib.sha256(args.events.read_bytes()).hexdigest(),
        "strict_model_sha256": hashlib.sha256(args.strict.read_bytes()).hexdigest(),
        "derivation_inputs": {
            "final_xkey_hex": final_xkey.hex(),
            "output640_sha256": hashlib.sha256(output640).hexdigest(),
        },
        "unknown": "xval_160bit",
        "relation": {
            "G": "SHA1 compression, standard IV, single 64-byte block xval||44*00; no SHA1 message padding",
            "out_a": "G(xval)",
            "out_b": "G((xval + out_a + 1) mod 2^160)",
            "aux": "(xval - xkey_before) mod 2^160",
        },
        "instances": [],
    }

    for i in range(16):
        out40 = output640[i*40:(i+1)*40]
        challenge["instances"].append({
            "index": i,
            "xkey_before_hex": states_before[i].hex(),
            "out_a_hex": out40[:20].hex(),
            "out_b_hex": out40[20:].hex(),
            "out40_sha256": hashlib.sha256(out40).hexdigest(),
        })

    # Oracle self-check against captured intermediate AUX, but do not write it.
    b12 = [
        e for e in ev
        if e.get("kind") == "B12_PROVIDER_FIPS_ENTRY"
        and 260 <= e.get("seq", -1) <= 410
    ]
    if len(b12) != 16:
        raise SystemExit(f"FAIL: oracle B12 count={len(b12)}")

    oracle_ok = True
    for i in range(16):
        aux = bytes.fromhex(b12[i]["aux_final_20_hex"][:40])
        xval = add160(states_before[i], aux)
        checks = verify_xval(
            strict,
            states_before[i],
            output640[i*40:(i+1)*40],
            xval,
        )
        ok = all(checks.values())
        oracle_ok &= ok
        print(f"I{i:02d} ORACLE_XVAL_CHECK={'PASS' if ok else 'FAIL'}")

    if not oracle_ok:
        raise SystemExit("FAIL: oracle does not satisfy generated challenge")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(challenge, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("INSTANCE_COUNT=16")
    print("ORACLE_SELF_CHECK=PASS")
    print("CHALLENGE=" + str(args.output))
    print("CHALLENGE_SHA256=" + hashlib.sha256(args.output.read_bytes()).hexdigest())

    if args.verify_index is not None or args.xval is not None:
        if args.verify_index is None or args.xval is None:
            raise SystemExit("FAIL: --verify-index and --xval must be supplied together")
        if not (0 <= args.verify_index < 16):
            raise SystemExit("FAIL: verify index out of range")
        cand = bytes.fromhex(args.xval)
        if len(cand) != 20:
            raise SystemExit("FAIL: xval candidate must be exactly 20 bytes")
        inst = challenge["instances"][args.verify_index]
        out40 = bytes.fromhex(inst["out_a_hex"] + inst["out_b_hex"])
        checks = verify_xval(strict, bytes.fromhex(inst["xkey_before_hex"]), out40, cand)
        print("CANDIDATE_CHECKS=" + repr(checks))
        print("CANDIDATE_VERDICT=" + ("PASS" if all(checks.values()) else "FAIL"))
        return 0 if all(checks.values()) else 1

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
