#!/usr/bin/env python3

import argparse
import csv
import hashlib
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path


RECORD = struct.Struct("<4s12I")
TRAILER = struct.Struct("<II")

GT_MAGIC = b"TCGT"
GT_VERSION = 1
GT_HEADER_SIZE = 52
GT_TRAILER_MARKER = 0x47544F56

PHASES = {
    0: "NONE",
    1: "HEADER",
    2: "MASTER_RNG",
    3: "SALT_RNG",
    4: "KDF",
    5: "HEADER_ENC",
}

EVENTS = {
    1:  "INIT",

    10: "RANDADD_INT32",
    11: "RANDADD_BUF",

    20: "RANDMIX_PRE",
    21: "RANDMIX_POST",

    30: "RANDGET_BEGIN",
    31: "RANDGET_POOL_PRE",
    32: "RANDGET_RAW",
    33: "RANDGET_POOL_INVERTED",
    34: "RANDGET_OUT",
    35: "RANDGET_POOL_POST",

    40: "CGR_SLOW_OUT",
    41: "CGR_SLOW_POOL_PRE",
    42: "CGR_SLOW_POOL_POST",

    43: "CGR_FAST_OUT",
    44: "CGR_FAST_POOL_PRE",
    45: "CGR_FAST_POOL_POST",

    50: "PASSWORD",
    51: "HEADER_PARAMS",
    52: "MASTER_RNG_OUT",
    53: "MASTER_KEYDATA",
    54: "SALT",
    55: "PBKDF2_DK",
    56: "HEADER_PLAIN",
    57: "HEADER_KEY_PRIMARY",
    58: "HEADER_KEY_SECONDARY",
    59: "HEADER_CIPHER",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace", type=Path)
    ap.add_argument("--header", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    blob = args.trace.read_bytes()

    if len(blob) < TRAILER.size:
        raise SystemExit("Trace too small")

    marker, overflow = TRAILER.unpack_from(blob, len(blob) - TRAILER.size)

    if marker != GT_TRAILER_MARKER:
        raise SystemExit(
            "Bad trailer marker: "
            f"0x{marker:08x}, expected 0x{GT_TRAILER_MARKER:08x}"
        )

    stream_end = len(blob) - TRAILER.size

    args.out.mkdir(parents=True, exist_ok=True)
    payload_dir = args.out / "payloads"
    cgr_dir = args.out / "cgr"
    payload_dir.mkdir(exist_ok=True)
    cgr_dir.mkdir(exist_ok=True)

    records = []
    event_counts = Counter()
    phase_counts = Counter()
    event_lengths = defaultdict(Counter)

    pos = 0
    expected_sequence = 1
    problems = []

    while pos < stream_end:
        if pos + RECORD.size > stream_end:
            problems.append(
                f"Truncated record header at offset {pos}"
            )
            break

        fields = RECORD.unpack_from(blob, pos)

        (
            magic,
            version,
            header_size,
            event,
            phase,
            sequence,
            pid,
            tid,
            qpc_low,
            qpc_high,
            data_len,
            aux0,
            aux1,
        ) = fields

        if magic != GT_MAGIC:
            problems.append(
                f"Bad magic at offset {pos}: {magic!r}"
            )
            break

        if version != GT_VERSION:
            problems.append(
                f"Unexpected version at sequence {sequence}: {version}"
            )

        if header_size != GT_HEADER_SIZE:
            problems.append(
                f"Unexpected headerSize at sequence {sequence}: "
                f"{header_size}"
            )

        if header_size < RECORD.size:
            problems.append(
                f"Invalid headerSize at sequence {sequence}: "
                f"{header_size}"
            )
            break

        payload_start = pos + header_size
        payload_end = payload_start + data_len

        if payload_end > stream_end:
            problems.append(
                f"Payload overruns stream at sequence {sequence}: "
                f"offset={pos}, dataLen={data_len}"
            )
            break

        payload = blob[payload_start:payload_end]

        if sequence != expected_sequence:
            problems.append(
                f"Sequence discontinuity: expected "
                f"{expected_sequence}, got {sequence}"
            )
            expected_sequence = sequence

        expected_sequence += 1

        event_name = EVENTS.get(event, f"UNKNOWN_{event}")
        phase_name = PHASES.get(phase, f"UNKNOWN_{phase}")

        qpc = (qpc_high << 32) | qpc_low

        payload_hash = sha256(payload) if payload else ""

        rec = {
            "offset": pos,
            "event": event,
            "event_name": event_name,
            "phase": phase,
            "phase_name": phase_name,
            "sequence": sequence,
            "pid": pid,
            "tid": tid,
            "qpc": qpc,
            "qpc_low": qpc_low,
            "qpc_high": qpc_high,
            "data_len": data_len,
            "aux0": aux0,
            "aux1": aux1,
            "payload_sha256": payload_hash,
        }

        records.append(rec)
        event_counts[event_name] += 1
        phase_counts[phase_name] += 1
        event_lengths[event_name][data_len] += 1

        if payload:
            payload_path = (
                payload_dir /
                f"{sequence:06d}_{event:02d}_{event_name}.bin"
            )
            payload_path.write_bytes(payload)

            if event == 40:
                (
                    cgr_dir /
                    f"{sequence:06d}_CGR_SLOW_OUT.bin"
                ).write_bytes(payload)

            elif event == 43:
                (
                    cgr_dir /
                    f"{sequence:06d}_CGR_FAST_OUT.bin"
                ).write_bytes(payload)

        pos = payload_end

    if pos != stream_end:
        problems.append(
            f"Record stream ended at {pos}, "
            f"expected {stream_end}"
        )

    #
    # Structural validations specific to the observed instrumentation.
    #
    for rec in records:
        if rec["event"] in (40, 41, 42, 43, 44, 45):
            if rec["data_len"] != 640:
                problems.append(
                    f"{rec['event_name']} sequence "
                    f"{rec['sequence']} has length "
                    f"{rec['data_len']}, expected 640"
                )

    #
    # Header comparisons.
    #
    header_checks = []

    if args.header:
        disk_header = args.header.read_bytes()

        header_checks.append({
            "check": "disk_header_size",
            "actual": len(disk_header),
            "expected": 512,
            "pass": len(disk_header) == 512,
        })

        salts = [
            r for r in records
            if r["event"] == 54
        ]

        for r in salts:
            p = (
                payload_dir /
                f"{r['sequence']:06d}_54_SALT.bin"
            ).read_bytes()

            header_checks.append({
                "check": f"SALT_seq_{r['sequence']}_equals_header_0_63",
                "pass": len(p) == 64 and p == disk_header[:64],
                "payload_len": len(p),
            })

        ciphers = [
            r for r in records
            if r["event"] == 59
        ]

        for r in ciphers:
            p = (
                payload_dir /
                f"{r['sequence']:06d}_59_HEADER_CIPHER.bin"
            ).read_bytes()

            result = {
                "check": f"HEADER_CIPHER_seq_{r['sequence']}",
                "payload_len": len(p),
                "disk_header_len": len(disk_header),
                "exact_512_match": False,
                "encrypted_448_match": False,
            }

            if len(p) == 512:
                result["exact_512_match"] = (p == disk_header)

            if len(p) == 448 and len(disk_header) >= 512:
                result["encrypted_448_match"] = (
                    p == disk_header[64:512]
                )

            header_checks.append(result)

    #
    # CSV
    #
    csv_path = args.out / "records.csv"

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        fields = [
            "sequence",
            "offset",
            "event",
            "event_name",
            "phase",
            "phase_name",
            "pid",
            "tid",
            "qpc",
            "data_len",
            "aux0",
            "aux1",
            "payload_sha256",
        ]

        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()

        for r in records:
            w.writerow({k: r[k] for k in fields})

    #
    # Human-readable timeline
    #
    timeline_path = args.out / "timeline.txt"

    with timeline_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(
                f"{r['sequence']:6d} "
                f"off={r['offset']:7d} "
                f"qpc={r['qpc']:12d} "
                f"phase={r['phase_name']:<10} "
                f"event={r['event_name']:<24} "
                f"len={r['data_len']:5d} "
                f"aux0={r['aux0']:10d} "
                f"aux1={r['aux1']:10d}\n"
            )

    #
    # Summary JSON
    #
    summary = {
        "trace": str(args.trace),
        "trace_size": len(blob),
        "trace_sha256": sha256(blob),

        "record_header_size": RECORD.size,
        "record_stream_size": stream_end,
        "record_count": len(records),

        "first_sequence": (
            records[0]["sequence"] if records else None
        ),
        "last_sequence": (
            records[-1]["sequence"] if records else None
        ),

        "trailer_marker_hex": f"0x{marker:08x}",
        "trailer_raw_hex": blob[-8:].hex(),
        "overflow": overflow,

        "event_counts": dict(sorted(event_counts.items())),
        "phase_counts": dict(sorted(phase_counts.items())),

        "event_payload_lengths": {
            name: {
                str(length): count
                for length, count in sorted(lengths.items())
            }
            for name, lengths in sorted(event_lengths.items())
        },

        "header_checks": header_checks,
        "problems": problems,
    }

    (args.out / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8"
    )

    #
    # Console summary
    #
    print("=== TRACE ===")
    print(f"size             : {len(blob)}")
    print(f"sha256           : {sha256(blob)}")
    print(f"records          : {len(records)}")
    print(f"stream end       : {stream_end}")
    print(f"parsed end       : {pos}")
    print(f"overflow         : {overflow}")
    print(
        f"sequence         : "
        f"{records[0]['sequence'] if records else '-'}"
        f".."
        f"{records[-1]['sequence'] if records else '-'}"
    )

    print()
    print("=== EVENT COUNTS ===")

    for name, count in sorted(event_counts.items()):
        lengths = ", ".join(
            f"{n}B×{c}"
            for n, c in sorted(event_lengths[name].items())
        )
        print(f"{name:<28} {count:5d}   {lengths}")

    print()
    print("=== CGR ===")
    print(
        f"CGR_SLOW_OUT     : "
        f"{event_counts.get('CGR_SLOW_OUT', 0)}"
    )
    print(
        f"CGR_FAST_OUT     : "
        f"{event_counts.get('CGR_FAST_OUT', 0)}"
    )

    if header_checks:
        print()
        print("=== HEADER CHECKS ===")
        for check in header_checks:
            print(json.dumps(check, sort_keys=True))

    print()
    print("=== VALIDATION ===")

    if problems:
        print("FAIL")
        for p in problems:
            print(f"  - {p}")
    else:
        print("PASS: structurally complete trace")

    print()
    print(f"CSV              : {csv_path}")
    print(f"Timeline         : {timeline_path}")
    print(f"Summary          : {args.out / 'summary.json'}")
    print(f"Payloads         : {payload_dir}")
    print(f"CGR dumps        : {cgr_dir}")


if __name__ == "__main__":
    main()
