#!/usr/bin/env python3
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

DROP = {"seq", "host_time_ns", "accepted_block_index"}

def fingerprint(e):
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
            and fingerprint(events[j]) == fingerprint(e)
        ):
            j += 1
        out.append(e)
        i = j
    return out

def rc4_ksa(key):
    if not key:
        raise ValueError("empty RC4 key")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    # ADVAPI trace representation: S[256] || i || j.
    return bytes(s) + b"\x00\x00"

def short_hash_hex(h):
    return hashlib.sha256(bytes.fromhex(h)).hexdigest()[:12]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "events",
        nargs="?",
        default="/home/hal/xp-cgr-lab/evidence/cgr640-full-01/events.jsonl",
    )
    args = ap.parse_args()

    src = Path(args.events)
    raw = [
        json.loads(line)
        for line in src.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ev = canonicalize(raw)

    b04 = [
        e for e in ev
        if e.get("kind") == "B04_ADVAPI_IOCTL_RETURN" and e.get("seq", 0) < 260
    ]
    if len(b04) != 8:
        raise SystemExit(f"FAIL: expected 8 canonical B04 events, got {len(b04)}")

    # The eight provider contexts are exactly the distinct state pointers used by
    # S036 before the target runtime, excluding unrelated/orphan ADVAPI RC4 calls.
    s036_pre_b07 = []
    for e in ev:
        if e.get("kind") != "B07_ADVAPI_RC4_PRGA_ENTRY" or e.get("seq", 0) >= 260:
            continue
        # The two unrelated pre-capture calls use a different stack context and
        # are not inside a B05..B06 S036 window. Restrict by the captured provider
        # context address range discovered in this run.
        ptr = e.get("prga_state")
        if ptr is not None and 0x24B000 <= ptr < 0x24C000:
            s036_pre_b07.append(e)

    ptrs = []
    for e in s036_pre_b07:
        p = e.get("prga_state")
        if p not in ptrs:
            ptrs.append(p)

    if len(ptrs) != 8:
        raise SystemExit(
            "FAIL: expected 8 distinct provider RC4 context pointers, got "
            + repr([hex(x) for x in ptrs])
        )

    print("=== KSecDD IOCTL -> ADVAPI RC4 KSA ===")
    ksa_ok = True
    first_use = {}
    for e in ev:
        if e.get("kind") == "B07_ADVAPI_RC4_PRGA_ENTRY":
            p = e.get("prga_state")
            if p in ptrs and p not in first_use:
                first_use[p] = e

    for idx, (ke, ptr) in enumerate(zip(b04, ptrs)):
        outhex = ke.get("ioctl_out_100_hex")
        if outhex is None:
            raise SystemExit(f"FAIL: B04 seq {ke['seq']} lacks ioctl_out_100_hex")
        key = bytes.fromhex(outhex)
        if len(key) != 256:
            raise SystemExit(
                f"FAIL: B04 seq {ke['seq']} captured {len(key)} bytes, expected 256"
            )
        expected = rc4_ksa(key)
        fu = first_use[ptr]
        observed = bytes.fromhex(fu.get("state_before_102_hex", ""))
        ok = observed == expected
        ksa_ok &= ok
        print(
            f"C{idx} B04={ke['seq']:3d} ptr={ptr:08x} "
            f"first_B07={fu['seq']:3d} len={fu.get('prga_len'):3d} "
            f"KSA={'PASS' if ok else 'FAIL'} "
            f"ksec={hashlib.sha256(key).hexdigest()[:12]} "
            f"state={hashlib.sha256(observed).hexdigest()[:12]}"
        )

    print("KSEC_TO_RC4_KSA=" + ("PASS" if ksa_ok else "FAIL"))

    # Pair each relevant B07 with the next relevant B08 in chronological order.
    b07 = [
        e for e in ev
        if e.get("kind") == "B07_ADVAPI_RC4_PRGA_ENTRY"
        and e.get("prga_state") in ptrs
    ]
    b08 = [
        e for e in ev
        if e.get("kind") == "B08_ADVAPI_RC4_PRGA_RETURN"
        and e.get("prga_state") in ptrs
    ]
    if len(b07) != 26 or len(b08) != 26:
        raise SystemExit(
            f"FAIL: expected 26 relevant B07/B08 events, got B07={len(b07)} B08={len(b08)}"
        )

    pairs = []
    j = 0
    for a in b07:
        while j < len(b08) and b08[j]["seq"] < a["seq"]:
            j += 1
        if j >= len(b08):
            raise SystemExit(f"FAIL: no B08 after B07 seq {a['seq']}")
        b = b08[j]
        if b.get("prga_state") != a.get("prga_state"):
            raise SystemExit(
                f"FAIL: B07 seq {a['seq']} ptr {a.get('prga_state'):08x} "
                f"paired with B08 seq {b['seq']} ptr {b.get('prga_state'):08x}"
            )
        pairs.append((a, b))
        j += 1

    byptr = defaultdict(list)
    for a, b in pairs:
        byptr[a["prga_state"]].append((a, b))

    print("\n=== Per-context lifetime ===")
    continuity_ok = True
    zero_ok = True
    for idx, ptr in enumerate(ptrs):
        uses = byptr[ptr]
        if len(uses) not in (3, 4):
            raise SystemExit(
                f"FAIL: context {ptr:08x} has {len(uses)} uses, expected 3 or 4"
            )
        labels = []
        previous_after = None
        for n, (a, b) in enumerate(uses):
            before = a.get("state_before_102_hex")
            after = b.get("state_after_102_hex")
            if previous_after is not None:
                same = before == previous_after
                continuity_ok &= same
                labels.append(
                    f"{a['seq']}:{a.get('prga_len')}:{'CONT' if same else 'BREAK'}"
                )
            else:
                labels.append(f"{a['seq']}:{a.get('prga_len')}:FIRST")
            if a.get("prga_len") == 0:
                same0 = before == after
                zero_ok &= same0
                labels[-1] += ":ZERO_SAME" if same0 else ":ZERO_CHANGED"
            previous_after = after
        print(f"C{idx} {ptr:08x} " + " -> ".join(labels))

    print("ZERO_LENGTH_STATE_PRESERVATION=" + ("PASS" if zero_ok else "FAIL"))
    print("ALL_CONTEXT_CONTINUITY=" + ("PASS" if continuity_ok else "FAIL"))

    print("\n=== Runtime schedule ===")
    runtime = [
        e for e in b07
        if 260 <= e.get("seq", 0) <= 410
    ]
    sched = [ptrs.index(e["prga_state"]) for e in runtime]
    print("CONTEXT_INDEXES=" + ",".join(map(str, sched)))
    expected_sched = [2,3,4,5,6,7,0,1] * 2
    schedule_ok = sched == expected_sched
    print("EXPECTED=" + ",".join(map(str, expected_sched)))
    print("ROUND_ROBIN_RUNTIME=" + ("PASS" if schedule_ok else "FAIL"))

    verdict = ksa_ok and zero_ok and continuity_ok and schedule_ok
    print("\nCONTEXT_CHAIN_VERDICT=" + ("PASS" if verdict else "FAIL"))
    if not verdict:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
