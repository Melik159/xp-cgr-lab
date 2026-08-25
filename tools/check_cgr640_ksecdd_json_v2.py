#!/usr/bin/env python3
"""
Validate the eight KSecDD events of CGR640_FULL_01 directly from the GDB JSONL.

The cryptographic primitives/replay functions are imported from the already
published xp-cgr-replay checker so this script does not fork the model.
Raw events.jsonl is never modified.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import hashlib
from pathlib import Path

DROP = {"seq", "host_time_ns", "accepted_block_index"}

DEFAULT_UPSTREAM = Path(
    "/home/hal/Téléchargements/xp-cgr-replay-release/"
    "deterministic-replay/tools/check_kernel_fullchain.py"
)

KIND = {
    "B01": "B01_KSEC_NEWGEN_ENTRY",
    "B02": "B02_KSEC_AFTER_GATHER",
    "B03": "B03_KSEC_PRE_RETURN",
    "B04": "B04_ADVAPI_IOCTL_RETURN",
    "K00": "K00_COLLECTOR_ALLOCATED",
    "K01": "K01_PROCESS_ID_APPENDED",
    "K02": "K02_THREAD_ID_APPENDED",
    "K03": "K03_TICK_COUNT_APPENDED",
    "K04": "K04_CPU_COUNTERS_RETURN",
    "K05": "K05_SYSINFO_05_RAW",
    "K06": "K06_SYSINFO_03_RETURN",
    "K07": "K07_SYSINFO_07_RETURN",
    "K08": "K08_SYSINFO_02_RETURN",
    "K09": "K09_SYSINFO_21_RETURN",
    "K10": "K10_SYSINFO_2D_RETURN",
    "K11": "K11_SYSINFO_08_RAW",
    "K12": "K12_SYSINFO_17_RAW",
    "K13": "K13_PRE_MIX",
    "K14": "K14_POST_MIX",
    "K15": "K15_OLD_STATE_RC4_RETURN",
    "K16": "K16_FINAL_RC4_KSA",
    "K17": "K17_FINAL_RC4_OUTPUT",
}

SOURCE_KEYS = {
    "pid": "K01",
    "tid": "K02",
    "tick": "K03",
    "cpu": "K04",
    "sys05": "K05",
    "sys03": "K06",
    "sys07": "K07",
    "sys02": "K08",
    "sys21": "K09",
    "sys2d": "K10",
    "sys08": "K11",
    "sys17": "K12",
}


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
    spec = importlib.util.spec_from_file_location("xp_cgr_kernel_upstream", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def bhex(e: dict, key: str, exact: int | None = None) -> bytes:
    v = e.get(key)
    if not isinstance(v, str):
        raise ValueError(f"seq={e.get('seq')} missing {key}")
    b = bytes.fromhex(v)
    if exact is not None and len(b) != exact:
        raise ValueError(
            f"seq={e.get('seq')} {key}: got {len(b)} bytes, expected {exact}"
        )
    return b


def align8(v: int) -> int:
    return (v + 7) & ~7


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "events",
        nargs="?",
        type=Path,
        default=Path("/home/hal/xp-cgr-lab/evidence/cgr640-full-01/events.jsonl"),
    )
    ap.add_argument("--upstream", type=Path, default=DEFAULT_UPSTREAM)
    args = ap.parse_args()

    if not args.upstream.is_file():
        raise SystemExit(f"FAIL: upstream checker not found: {args.upstream}")

    upstream = load_upstream(args.upstream)
    strict = upstream.STRICT

    raw = [
        json.loads(x)
        for x in args.events.read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]
    ev = canonicalize(raw)

    arrays = {}
    for label, kind in KIND.items():
        arrays[label] = [
            e for e in ev if e.get("kind") == kind and e.get("seq", 10**9) < 260
        ]

    bad_counts = {k: len(v) for k, v in arrays.items() if len(v) != 8}
    if bad_counts:
        raise SystemExit("FAIL: canonical event counts != 8: " + repr(bad_counts))

    all_ok = True
    summaries = []

    for i in range(8):
        e = {k: arrays[k][i] for k in arrays}
        checks: dict[str, bool] = {}

        base = e["K00"].get("collector_base")
        used = e["K13"].get("used")
        outlen = e["K17"].get("output_len")
        if not isinstance(base, int) or not isinstance(used, int) or not isinstance(outlen, int):
            raise SystemExit(f"FAIL event {i}: missing base/used/output_len")

        checks["used_range"] = 0 < used <= 0xE00 and used % 4 == 0
        checks["output_len_256"] = outlen == 0x100

        workspace = bhex(e["K13"], "workspace_pre_mix_e00_hex", 0xE00)
        old_state = bhex(e["K13"], "global_state_before_50_hex", 0x50)
        new_state = bhex(e["K14"], "state_after_mix_50_hex", 0x50)

        # Collector layout, identical logic to the published checker.
        source_offsets = {}
        reported = {}
        statuses = {}
        for name, klab in SOURCE_KEYS.items():
            se = e[klab]
            src = se.get("source_start")
            length = se.get("reported_len")
            status = se.get("status")
            if isinstance(src, int):
                source_offsets[name] = src - base
            if isinstance(length, int):
                reported[name] = length
            if isinstance(status, int):
                statuses[name] = status

        # K04's generic GDB handler mis-labelled [ebp-0x1d0] as the CPU
        # returned length. Static code shows the real length is returned
        # through [ebp-0x1d8]. The callee can return 0, 8, 16 or 24 bytes.
        # In this run the collector advances from +0x28 to +0x38, i.e.
        # align8(length+8) == 0x10; among those possible return values,
        # the unique solution is length == 8.
        reported["cpu"] = 8

        expected = {"pid": 0x08, "tid": 0x10, "tick": 0x18, "cpu": 0x28}
        if "cpu" in reported:
            expected["sys05"] = expected["cpu"] + align8(reported["cpu"] + 8)
        if "sys05" in expected:
            expected["sys03"] = expected["sys05"] + 0x18
        for previous, following in (
            ("sys03", "sys07"),
            ("sys07", "sys02"),
            ("sys02", "sys21"),
            ("sys21", "sys2d"),
            ("sys2d", "sys08"),
        ):
            if previous in expected and previous in reported:
                expected[following] = expected[previous] + align8(reported[previous] + 8)
        if "sys08" in expected:
            expected["sys17"] = expected["sys08"] + 0x18

        checks["collector_layout"] = all(
            source_offsets.get(name) == off for name, off in expected.items()
        )
        checks["used_matches_final_reservation"] = (
            "sys17" in source_offsets and used == source_offsets["sys17"] + 0x18
        )

        # Direct bytes for fixed small sources.
        checks["pid_bytes"] = (
            "pid" in source_offsets
            and bhex(e["K01"], "source_hex")[:8]
            == workspace[source_offsets["pid"]:source_offsets["pid"] + 8]
        )
        checks["tid_bytes"] = (
            "tid" in source_offsets
            and bhex(e["K02"], "source_hex")[:8]
            == workspace[source_offsets["tid"]:source_offsets["tid"] + 8]
        )
        checks["tick_bytes"] = (
            "tick" in source_offsets
            and bhex(e["K03"], "source_hex")[:16]
            == workspace[source_offsets["tick"]:source_offsets["tick"] + 16]
        )

        cpu_len = reported["cpu"]
        checks["cpu_return_length_derived_8"] = (
            source_offsets.get("cpu") == 0x28
            and source_offsets.get("sys05") == 0x38
            and align8(cpu_len + 8) == 0x10
        )
        checks["cpu_bytes"] = (
            "cpu" in source_offsets
            and bhex(e["K04"], "source_hex")[:cpu_len]
            == workspace[source_offsets["cpu"]:source_offsets["cpu"] + cpu_len]
        )

        # The GDB capture retained a full collector-workspace image at these
        # three raw-query return points. Reproduce the published SHA-1 checks.
        for source_name, klab in (
            ("sys05", "K05"),
            ("sys08", "K11"),
            ("sys17", "K12"),
        ):
            off = source_offsets.get(source_name)
            length = reported.get(source_name)
            raw_ws = bhex(e[klab], "workspace_e00_hex", 0xE00)
            valid = (
                isinstance(off, int)
                and isinstance(length, int)
                and off >= 0
                and off + length <= len(raw_ws)
                and off + 20 <= len(workspace)
            )
            digest = hashlib.sha1(raw_ws[off:off + length]).digest() if valid else b""
            checks[source_name + "_sha1"] = (
                valid and digest == workspace[off:off + 20]
            )

        # Exact published mixer replay.
        replayed_state = upstream.replay_mixer(workspace, used, old_state)
        checks["mixer_state_replay"] = replayed_state == new_state
        checks["global_state_commit"] = (
            bhex(e["K16"], "global_state_50_hex", 0x50) == new_state
        )

        # Exact published RC4 side-effect and final-output replays.
        initial_old_ctx = strict.rc4_ksa(old_state)
        old_ciphertext, old_ctx_after = strict.rc4_replay(
            initial_old_ctx, new_state, len(new_state)
        )
        checks["old_state_rc4_side_effect"] = (
            old_ciphertext == bhex(e["K15"], "old_state_after_50_hex", 0x50)
        )
        checks["old_state_rc4_context"] = (
            old_ctx_after
            == bhex(e["K15"], "rc4_context_after_old_state_102_hex", 0x102)
        )

        final_ctx = strict.rc4_ksa(new_state)
        checks["final_rc4_ksa"] = (
            final_ctx == bhex(e["K16"], "rc4_context_102_hex", 0x102)
        )

        entry = bhex(e["B01"], "out_before_hex", 0x100)
        final_output, _ = strict.rc4_replay(final_ctx, entry, outlen)
        observed_final = bhex(e["K17"], "output_100_hex", 0x100)
        checks["final_rc4_output"] = final_output == observed_final

        after = bhex(e["B02"], "out_hex", 0x100)
        pre_return = bhex(e["B03"], "out_hex", 0x100)
        ioctl = bhex(e["B04"], "ioctl_out_100_hex", 0x100)
        checks["kernel_to_ioctl_byte_equality"] = (
            observed_final == after == pre_return == ioctl
        )

        failed = [k for k, v in checks.items() if not v]
        ok = not failed
        all_ok &= ok
        summaries.append(
            {
                "event": i,
                "seq": [e["B01"]["seq"], e["B04"]["seq"]],
                "used": used,
                "checks": checks,
                "failed": failed,
                "verdict": "PASS" if ok else "FAIL",
            }
        )
        print(
            f"E{i} seq={e['B01']['seq']}..{e['B04']['seq']} "
            f"used=0x{used:x} "
            f"mixer={'PASS' if checks['mixer_state_replay'] else 'FAIL'} "
            f"oldRC4={'PASS' if checks['old_state_rc4_context'] and checks['old_state_rc4_side_effect'] else 'FAIL'} "
            f"finalRC4={'PASS' if checks['final_rc4_ksa'] and checks['final_rc4_output'] else 'FAIL'} "
            f"handoff={'PASS' if checks['kernel_to_ioctl_byte_equality'] else 'FAIL'} "
            f"overall={'PASS' if ok else 'FAIL'}"
        )
        if failed:
            print("  FAILED=" + ",".join(failed))

    report = args.events.parent / "ksecdd-json-replay-report.json"
    report.write_text(
        json.dumps(
            {
                "events": str(args.events),
                "upstream_checker": str(args.upstream),
                "upstream_checker_sha256": hashlib.sha256(
                    args.upstream.read_bytes()
                ).hexdigest(),
                "events_sha256": hashlib.sha256(args.events.read_bytes()).hexdigest(),
                "events_checked": 8,
                "event_reports": summaries,
                "verdict": "PASS" if all_ok else "FAIL",
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    print("KSECDD_EVENTS=8")
    print("KSECDD_INTERNAL_REPLAY=" + ("PASS" if all_ok else "FAIL"))
    print("REPORT=" + str(report))
    print("REPORT_SHA256=" + hashlib.sha256(report.read_bytes()).hexdigest())
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
