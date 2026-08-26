#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

DEFAULT_ROOT = Path("/home/hal/xp-cgr-lab")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id")
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--solver", type=Path, default=None)
    ap.add_argument("--max-candidates", type=int, default=0)
    args = ap.parse_args()

    root = args.root
    challenge = root / "evidence/inverse-benchmark-v2/phase-h-ksa-reduced-challenges.json"
    solver = args.solver or (root / "tools/solve_phase_h_ksa_native")

    data = json.loads(challenge.read_text(encoding="utf-8"))
    matches = [x for x in data["instances"] if x["id"] == args.instance_id]
    if len(matches) != 1:
        raise SystemExit(f"FAIL expected one instance {args.instance_id}, got {len(matches)}")
    inst = matches[0]

    positions = ",".join(str(x) for x in inst["unknown_positions"])
    cmd = [
        str(solver),
        str(inst["k"]),
        inst["known_value_hex"],
        inst["target_post_ksa_hex"],
        positions,
        str(args.max_candidates),
    ]

    r = subprocess.run(cmd, text=True, capture_output=True)
    print(r.stdout, end="")
    if r.stderr:
        print(r.stderr, end="")

    solution = None
    for line in r.stdout.splitlines():
        if line.startswith("SOLUTION_NEW_STATE="):
            solution = line.split("=", 1)[1]

    if solution is not None:
        vr = subprocess.run([
            "python3",
            str(root / "tools/verify_phase_h_ksa_reduced_candidate.py"),
            args.instance_id,
            solution,
        ], text=True, capture_output=True)
        print(vr.stdout, end="")
        if vr.stderr:
            print(vr.stderr, end="")
        print("INDEPENDENT_VERIFIER_EXIT_CODE=" + str(vr.returncode))
        if vr.returncode != 0:
            return 4

    print("SOLVER_EXIT_CODE=" + str(r.returncode))
    return r.returncode

if __name__ == "__main__":
    raise SystemExit(main())
