#!/usr/bin/env python3
"""Validate two XP J2 result runs and produce comparison/module evidence."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


EXPECTED_LENGTHS = [32, 64] * 5
APIS = {
    "cgr": {
        "api": "CryptGenRandom",
        "namespace": "CGR",
        "trace": "cgr-trace.jsonl",
        "probe": "probe-cgr.jsonl",
        "control": "control-cgr.jsonl",
        "trace_metrics": "trace-cgr-metrics.json",
        "control_metrics": "control-cgr-metrics.json",
        "status": "cgr-hook-status.jsonl",
        "trace_exit": "trace-cgr.exit.txt",
        "control_exit": "control-cgr.exit.txt",
        "trace_stderr": "probe-cgr.stderr.txt",
        "control_stderr": "control-cgr.stderr.txt",
    },
    "rtl": {
        "api": "SystemFunction036",
        "namespace": "RTL",
        "trace": "rtl-trace.jsonl",
        "probe": "probe-rtl.jsonl",
        "control": "control-rtl.jsonl",
        "trace_metrics": "trace-rtl-metrics.json",
        "control_metrics": "control-rtl-metrics.json",
        "status": "rtl-hook-status.jsonl",
        "trace_exit": "trace-rtl.exit.txt",
        "control_exit": "control-rtl.exit.txt",
        "trace_stderr": "probe-rtl.stderr.txt",
        "control_stderr": "control-rtl.stderr.txt",
    },
}


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def read_exit(path: Path) -> int:
    return int(path.read_text(encoding="ascii").strip())


def address_consistent(event: dict) -> bool:
    absolute = int(event["return_address"], 16)
    base = int(event["caller_module_base"], 16)
    offset = int(event["caller_offset"], 16)
    return base != 0 and absolute == base + offset


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path, help="directory containing RUN1/RUN2")
    parser.add_argument("evidence", type=Path, help="J2 evidence output directory")
    args = parser.parse_args()

    comparisons: list[dict] = []
    control_trace: list[dict] = []
    modules: dict[tuple, dict] = {}
    run_api_pass: dict[tuple[str, str], bool] = {}
    caller_signatures: dict[str, list[list[tuple]]] = {key: [] for key in APIS}

    for run_name in ("RUN1", "RUN2"):
        run_dir = args.results / run_name
        for key, spec in APIS.items():
            probe = read_jsonl(run_dir / spec["probe"])
            trace = read_jsonl(run_dir / spec["trace"])
            control = read_jsonl(run_dir / spec["control"])
            trace_metrics = read_json(run_dir / spec["trace_metrics"])
            control_metrics = read_json(run_dir / spec["control_metrics"])
            status = read_jsonl(run_dir / spec["status"])

            local_pass = (
                len(probe) == len(trace) == len(control) == 10
                and [event["requested_length"] for event in probe] == EXPECTED_LENGTHS
                and [event["requested_length"] for event in trace] == EXPECTED_LENGTHS
                and [event["requested_length"] for event in control] == EXPECTED_LENGTHS
                and read_exit(run_dir / spec["trace_exit"]) == 0
                and read_exit(run_dir / spec["control_exit"]) == 0
                and (run_dir / spec["trace_stderr"]).stat().st_size == 0
                and (run_dir / spec["control_stderr"]).stat().st_size == 0
                and trace_metrics["child_exit_code"] == 0
                and trace_metrics["injection_success"] is True
                and control_metrics["child_exit_code"] == 0
                and status
                and all(item["cryptgenrandom_iat_hook"] for item in status)
                and all(item["getprocaddress_iat_hook"] for item in status)
            )

            signatures: list[tuple] = []
            for index, (probe_event, trace_event) in enumerate(zip(probe, trace), 1):
                length_match = probe_event["requested_length"] == trace_event["requested_length"]
                bytes_match = probe_event["bytes_hex"] == trace_event["returned_bytes_hex"]
                pid_match = probe_event["pid"] == trace_event["pid"]
                tid_match = probe_event["tid"] == trace_event["tid"]
                success_match = probe_event["success"] == trace_event["success"]
                error_match = probe_event["win32_error"] == trace_event["win32_error"]
                namespace_match = trace_event["namespace"] == spec["namespace"]
                api_match = (
                    probe_event["api"] == spec["api"]
                    and trace_event["api"] == spec["api"]
                )
                caller_module_expected = trace_event["caller_module"].lower() == "cgr_probe.exe"
                address_match = address_consistent(trace_event)
                event_pass = all(
                    (
                        length_match,
                        bytes_match,
                        pid_match,
                        tid_match,
                        success_match,
                        error_match,
                        namespace_match,
                        api_match,
                        caller_module_expected,
                        address_match,
                    )
                )
                local_pass = local_pass and event_pass
                comparisons.append(
                    {
                        "run": run_name,
                        "api": spec["api"],
                        "pair_index": index,
                        "probe_event": probe_event["event_id"],
                        "trace_event": trace_event["event_id"],
                        "length_match": length_match,
                        "bytes_match": bytes_match,
                        "pid_match": pid_match,
                        "tid_match": tid_match,
                        "success_match": success_match,
                        "error_match": error_match,
                        "caller_module_expected": caller_module_expected,
                        "return_address_in_module": address_match,
                        "pass": event_pass,
                    }
                )
                signature = (
                    trace_event["caller_module"].lower(),
                    trace_event["caller_module_base"].lower(),
                    trace_event["caller_offset"].lower(),
                    trace_event["return_address"].lower(),
                    trace_event["requested_length"],
                )
                signatures.append(signature)
                module_key = (
                    trace_event["process_name"].lower(),
                    trace_event["caller_module"].lower(),
                    trace_event["caller_module_base"].lower(),
                    trace_event["return_address"].lower(),
                    trace_event["caller_offset"].lower(),
                    spec["api"],
                )
                module_item = modules.setdefault(
                    module_key,
                    {
                        "process_name": trace_event["process_name"],
                        "api": spec["api"],
                        "module": trace_event["caller_module"],
                        "base": trace_event["caller_module_base"],
                        "absolute_address": trace_event["return_address"],
                        "rva": trace_event["caller_offset"],
                        "symbol": None,
                        "symbol_status": "not_resolved_offline",
                        "runs": [],
                        "event_count": 0,
                    },
                )
                if run_name not in module_item["runs"]:
                    module_item["runs"].append(run_name)
                module_item["event_count"] += 1

            caller_signatures[key].append(signatures)
            control_lengths = [event["requested_length"] for event in control]
            trace_lengths = [event["requested_length"] for event in probe]
            control_status = [event["success"] for event in control]
            trace_status = [event["success"] for event in probe]
            execution_delta = trace_metrics["execution_us"] - control_metrics["execution_us"]
            execution_ratio = (
                trace_metrics["execution_us"] / control_metrics["execution_us"]
                if control_metrics["execution_us"]
                else None
            )
            control_pass = (
                len(control) == len(probe) == 10
                and control_lengths == trace_lengths == EXPECTED_LENGTHS
                and control_status == trace_status
            )
            local_pass = local_pass and control_pass
            control_trace.append(
                {
                    "run": run_name,
                    "api": spec["api"],
                    "control_event_count": len(control),
                    "trace_event_count": len(probe),
                    "count_match": len(control) == len(probe),
                    "lengths_match": control_lengths == trace_lengths,
                    "status_match": control_status == trace_status,
                    "order_match": control_lengths == trace_lengths,
                    "control_execution_us": control_metrics["execution_us"],
                    "trace_execution_us": trace_metrics["execution_us"],
                    "execution_delta_us": execution_delta,
                    "trace_over_control_ratio": execution_ratio,
                    "pass": control_pass,
                }
            )
            run_api_pass[(run_name, key)] = local_pass

    signature_matches = {
        key: len(values) == 2 and values[0] == values[1]
        for key, values in caller_signatures.items()
    }
    all_pass = all(run_api_pass.values()) and all(signature_matches.values())
    output = {
        "verdict": "PASS" if all_pass else "FAIL",
        "expected_per_api_per_run": {"32_byte_calls": 5, "64_byte_calls": 5, "total": 10},
        "event_comparisons": comparisons,
        "control_trace_comparison": control_trace,
        "reproducibility": {
            "run_count": 2,
            "all_run_api_validations_pass": all(run_api_pass.values()),
            "caller_signature_matches_between_runs": signature_matches,
            "pass": all(signature_matches.values()) and all(run_api_pass.values()),
        },
        "instrumentation_transparency_claimed": False,
    }

    args.evidence.mkdir(parents=True, exist_ok=True)
    (args.evidence / "comparison.json").write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.evidence / "modules.json").write_text(
        json.dumps({"modules": list(modules.values())}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for source_name, destination_name in (
        ("cgr-trace.jsonl", "cgr-trace.jsonl"),
        ("rtl-trace.jsonl", "rtl-trace.jsonl"),
        ("probe-cgr.jsonl", "probe-cgr.jsonl"),
        ("probe-rtl.jsonl", "probe-rtl.jsonl"),
    ):
        shutil.copyfile(args.results / "RUN1" / source_name, args.evidence / destination_name)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
