#!/usr/bin/env python3
import argparse, collections, hashlib, json
from pathlib import Path

DROP_FOR_FINGERPRINT = {"seq", "host_time_ns", "accepted_block_index"}

TARGET_KINDS = {
    "B05_SYSTEMFUNCTION036_ENTRY",
    "B06_SYSTEMFUNCTION036_RETURN",
    "B07_ADVAPI_RC4_PRGA_ENTRY",
    "B08_ADVAPI_RC4_PRGA_RETURN",
    "B10_PROVIDER_BEFORE_SYSTEMFUNCTION036",
    "B11_PROVIDER_AFTER_SYSTEMFUNCTION036",
    "B12_PROVIDER_FIPS_ENTRY",
    "B13_PROVIDER_FIPS_RETURN",
}

EXPECTED_PATTERN = [
    "B10_PROVIDER_BEFORE_SYSTEMFUNCTION036",
    "B05_SYSTEMFUNCTION036_ENTRY",
    "B07_ADVAPI_RC4_PRGA_ENTRY",
    "B08_ADVAPI_RC4_PRGA_RETURN",
    "B06_SYSTEMFUNCTION036_RETURN",
    "B11_PROVIDER_AFTER_SYSTEMFUNCTION036",
    "B12_PROVIDER_FIPS_ENTRY",
    "B13_PROVIDER_FIPS_RETURN",
]

def sha256_file(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()

def fingerprint(e):
    x = {k: v for k, v in e.items() if k not in DROP_FOR_FINGERPRINT}
    return json.dumps(x, sort_keys=True, separators=(",", ":"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events", nargs="?",
                    default="/home/hal/xp-cgr-lab/evidence/cgr640-full-01/events.jsonl")
    args = ap.parse_args()
    src = Path(args.events)
    outdir = src.parent
    norm_path = outdir / "events.target640.normalized.jsonl"
    dup_path = outdir / "events.target640.duplicates.json"
    report_path = outdir / "events.target640.normalization-report.json"

    raw = [json.loads(line) for line in src.read_text(encoding="utf-8").splitlines() if line.strip()]

    starts = [e for e in raw
              if e.get("kind") == "B10_PROVIDER_BEFORE_SYSTEMFUNCTION036"
              and e.get("cgr_len") == 0x280
              and e.get("cgr_remaining") == 0x280]
    if len(starts) != 1:
        raise SystemExit(f"FAIL: expected exactly one target start, got {len(starts)}")
    start = starts[0]
    cid = start.get("d640_call_id")

    ends = [e for e in raw
            if e.get("kind") == "B14_PROVIDER_RUNTIME_RETURN"
            and e.get("d640_call_id") == cid
            and e.get("cgr_len") == 0x280
            and e.get("seq", -1) >= start["seq"]]
    if len(ends) != 1:
        raise SystemExit(f"FAIL: expected exactly one target return, got {len(ends)}")
    end = ends[0]

    region = [e for e in raw if start["seq"] <= e.get("seq", -1) <= end["seq"]]

    normalized = []
    duplicate_groups = []
    i = 0
    while i < len(region):
        e = region[i]
        fp = fingerprint(e)
        group = [e]
        j = i + 1
        while (j < len(region)
               and e.get("kind") in TARGET_KINDS
               and region[j].get("kind") == e.get("kind")
               and fingerprint(region[j]) == fp):
            group.append(region[j])
            j += 1
        normalized.append(e)
        if len(group) > 1:
            duplicate_groups.append({
                "kind": e.get("kind"),
                "canonical_seq": e.get("seq"),
                "raw_seqs": [x.get("seq") for x in group],
                "count": len(group),
                "fingerprint_basis": "all JSON fields except seq and host_time_ns",
            })
        i = j

    target_norm = [e for e in normalized if e.get("kind") in TARGET_KINDS]
    counts = collections.Counter(e["kind"] for e in target_norm)

    expected_counts = {k: 16 for k in TARGET_KINDS}
    if dict(counts) != expected_counts:
        raise SystemExit("FAIL: normalized target counts are not exactly 16 for every traced stage: "
                         + repr(dict(counts)))

    kinds = [e["kind"] for e in target_norm]
    expected = EXPECTED_PATTERN * 16
    if kinds != expected:
        for n, (got, exp) in enumerate(zip(kinds, expected)):
            if got != exp:
                raise SystemExit(f"FAIL: cycle ordering mismatch at normalized target event {n}: "
                                 f"got {got}, expected {exp}")
        raise SystemExit(f"FAIL: cycle ordering length mismatch: got {len(kinds)}, expected {len(expected)}")

    b10 = [e for e in target_norm if e["kind"] == "B10_PROVIDER_BEFORE_SYSTEMFUNCTION036"]
    rem = [e.get("cgr_remaining") for e in b10]
    expected_rem = list(range(640, 0, -40))
    if rem != expected_rem:
        raise SystemExit(f"FAIL: B10 remaining sequence {rem!r} != {expected_rem!r}")

    # Per-cycle structural/linkage checks using only captured fields.
    linkage = []
    for n in range(16):
        c = target_norm[n*8:(n+1)*8]
        b10, b05, b07, b08, b06, b11, b12, b13 = c
        checks = {}

        checks["s036_len_20"] = (b05.get("sysfunc_len") == 20 and b06.get("sysfunc_len") == 20)
        checks["rc4_len_20"] = (b07.get("prga_len") == 20 and b08.get("prga_len") == 20)
        checks["fips_len_20"] = (b12.get("provider_len") == 20 and b13.get("provider_len") == 20)

        checks["s036_ptr_is_d640_local"] = (b05.get("sysfunc_out") == b10.get("provider_aux"))
        checks["b11_local_is_same"] = (b11.get("provider_aux") == b10.get("provider_aux"))
        checks["fips_aux_is_same_local"] = (b12.get("provider_aux_final") == b10.get("provider_aux"))

        # The capture field names say "20" but safe_dump(..., 0x20) retained
        # 32 bytes. Cryptographic comparisons below intentionally use only
        # the first 20 decimal bytes (40 hex chars), which is the S036/FIPS size.
        def first20_hex(v):
            return None if v is None else v[:40]

        pre = first20_hex(b10.get("provider_aux_before_20_hex"))
        s036_before = first20_hex(b05.get("sys_before_20_hex"))
        checks["s036_before_equals_d640_local"] = (s036_before == pre)

        checks["rc4_out_ptr_is_s036_ptr"] = (b07.get("prga_out") == b05.get("sysfunc_out"))
        checks["s036_after_equals_rc4_after"] = (
            first20_hex(b06.get("sys_after_20_hex"))
            == first20_hex(b08.get("out_after_20_hex"))
        )
        checks["b11_raw_equals_s036_after"] = (
            first20_hex(b11.get("provider_sysfunc_raw20_hex"))
            == first20_hex(b06.get("sys_after_20_hex"))
        )

        raw20 = first20_hex(b11.get("provider_sysfunc_raw20_hex"))
        caller = first20_hex(b10.get("caller_current_20_hex"))
        aux = first20_hex(b12.get("aux_final_20_hex"))
        if raw20 is not None and caller is not None and aux is not None:
            rb = bytes.fromhex(raw20)
            cb = bytes.fromhex(caller)
            ab = bytes.fromhex(aux)
            checks["d640_xor_exact"] = (
                len(rb) == len(cb) == len(ab) == 20
                and bytes(a ^ b for a, b in zip(rb, cb)) == ab
            )
        else:
            checks["d640_xor_exact"] = False

        checks["fips_state_ptr_stable"] = (
            b12.get("provider_state") == 0x68031958
            and b13.get("provider_state") == 0x68031958
        )

        bad = [k for k, v in checks.items() if not v]
        linkage.append({
            "iteration": n,
            "remaining": b10.get("cgr_remaining"),
            "raw_seq_span": [c[0].get("seq"), c[-1].get("seq")],
            "checks": checks,
            "verdict": "PASS" if not bad else "FAIL",
            "failed": bad,
        })
        if bad:
            raise SystemExit(f"FAIL: linkage iteration {n}: {bad}")

    norm_path.write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in normalized),
        encoding="utf-8"
    )
    dup_path.write_text(json.dumps(duplicate_groups, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")

    report = {
        "source": str(src),
        "source_sha256": sha256_file(src),
        "target_call_id": cid,
        "target_seq_range": [start["seq"], end["seq"]],
        "raw_region_events": len(region),
        "normalized_region_events": len(normalized),
        "duplicate_groups": duplicate_groups,
        "normalized_target_counts": dict(sorted(counts.items())),
        "remaining_sequence": rem,
        "cycle_pattern": EXPECTED_PATTERN,
        "cycle_count": 16,
        "linkage": linkage,
        "verdict": "PASS",
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")

    print("RAW_SHA256=" + report["source_sha256"])
    print("TARGET_CALL_ID=" + str(cid))
    print("TARGET_SEQ_RANGE=" + f'{start["seq"]}..{end["seq"]}')
    print("DUPLICATE_GROUPS=" + str(len(duplicate_groups)))
    for d in duplicate_groups:
        print("DUP", d["kind"], ",".join(map(str, d["raw_seqs"])))
    print("NORMALIZED_COUNTS=" + repr(dict(sorted(counts.items()))))
    print("CYCLES=16")
    print("LINKAGE=16/16")
    print("NORMALIZATION_VERDICT=PASS")
    print("NORMALIZED_SHA256=" + sha256_file(norm_path))
    print("REPORT_SHA256=" + sha256_file(report_path))

if __name__ == "__main__":
    main()
