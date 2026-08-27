#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

EXPECTED_HEAD="17ed6b1d9db49eae4418e252f1cb66621f3d1647"
EXPECTED_SOLVER="0a01e23a2223073913afa28bdbe157374a114bdf8c9f15384e06985194e3a0ea"
EXPECTED_RUNNER="b6ff140ded11bef82605fd46412b0047274c3efdf1d62bceb5133b2c7fb2f812"
EXPECTED_VERIFIER="c59e87e857c00d2ee936907b0a539cfa055025731e11b207b8f038d2717d67a1"

head="$(git rev-parse HEAD)"
[[ "$head" == "$EXPECTED_HEAD" ]] || { echo "FAIL HEAD=$head"; exit 1; }

check_sha() {
  local path="$1" expected="$2"
  local actual
  actual="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || {
    echo "FAIL SHA256 $path expected=$expected actual=$actual"
    exit 1
  }
}

check_sha tools/solve_phase_h_mixer_native.c "$EXPECTED_SOLVER"
check_sha tools/run_phase_h_mixer_native.py "$EXPECTED_RUNNER"
check_sha tools/verify_phase_h_mixer_reduced_candidate.py "$EXPECTED_VERIFIER"

git diff --quiet HEAD -- \
  tools/solve_phase_h_mixer_native.c \
  tools/run_phase_h_mixer_native.py \
  tools/verify_phase_h_mixer_reduced_candidate.py \
  evidence/inverse-benchmark-v2/phase-h-mixer-reduced \
  || { echo "FAIL tracked campaign inputs differ from HEAD"; exit 1; }

cc -O3 -std=c11 -Wall -Wextra \
  tools/solve_phase_h_mixer_native.c \
  -o tools/solve_phase_h_mixer_native

OUT="evidence/inverse-benchmark-v2/phase-h-mixer-cpu-runs"
mkdir -p "$OUT"

count=0
for profile in OLD WS SPLIT; do
  for k in 08 12 16 20 24; do
    id="H-MIXER-00-${profile}-K${k}"
    challenge="evidence/inverse-benchmark-v2/phase-h-mixer-reduced/${id}.json"
    result="${OUT}/${id}.json"
    log="/tmp/${id}.cpu.log"

    python3 tools/run_phase_h_mixer_native.py \
      "$challenge" \
      --json-out "$result" >"$log" 2>&1

    python3 - "$result" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p, encoding="utf-8"))
if d.get("status") != "FOUND" or d.get("candidate_verified") is not True:
    raise SystemExit(f"FAIL {d.get('instance_id')}: status={d.get('status')} verifier={d.get('candidate_verified')}")
print(
    f"{d['instance_id']} STATUS=FOUND COUNTER={d['counter']} "
    f"TESTED={d['tested_candidates']} SECONDS={d['wall_seconds']:.6f} "
    f"RATE={d['throughput_candidates_per_second']:.3f} VERIFIER=PASS"
)
PY
    count=$((count+1))
  done
done

echo "INSTANCE_COUNT=$count"
echo "FOUND_VERIFIED=${count}/${count}"
echo "PHASE_H_MIXER_CPU_MATRIX_K24=PASS"
