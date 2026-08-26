#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess
from pathlib import Path

ROOT = Path("/home/hal/xp-cgr-lab")
CHALLENGE = ROOT / "evidence/inverse-benchmark-v2/reduced-challenges.json"
BIN = ROOT / "tools/solve_inverse_cpu_native"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id", nargs="?", default="B00-K24")
    ap.add_argument("--max-candidates", type=int, default=0)
    args = ap.parse_args()

    data = json.loads(CHALLENGE.read_text(encoding="utf-8"))
    matches = [x for x in data["instances"] if x["id"] == args.instance_id]
    if len(matches) != 1:
        raise SystemExit(f"FAIL instance {args.instance_id}")
    inst = matches[0]

    positions = ",".join(str(x) for x in inst["unknown_positions"])
    cmd = [
        str(BIN),
        str(inst["k"]),
        inst["known_value_hex"],
        inst["out_a_hex"],
        inst["out_b_hex"],
        positions,
        str(args.max_candidates),
    ]
    cp = subprocess.run(cmd, text=True, capture_output=True)
    print(f"INSTANCE={args.instance_id}")
    print(cp.stdout, end="")
    if cp.stderr:
        print(cp.stderr, end="")
    return cp.returncode

if __name__ == "__main__":
    raise SystemExit(main())
