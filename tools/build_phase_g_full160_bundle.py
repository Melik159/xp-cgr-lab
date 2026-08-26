#!/usr/bin/env python3
"""
Build the Phase-G FULL-160 oracle-isolated challenge bundle.

The builder itself runs inside the research repository, but the generated
bundle contains only:
  - challenge.json
  - verify_candidate.py
  - README.md
  - MANIFEST_SHA256.txt

It rejects unexpected source hashes and rejects serialization of the already
known B00 XVAL oracle into the generated bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path

EXPECTED_CHALLENGE_SHA256 = (
    "2e0e101f80d28a033f4231a7a083ee506fdf2907ea64a546c79e75c4e0d7751c"
)
EXPECTED_VERIFIER_SHA256 = (
    "9fd0f4a21c2b332fc8d0470dd4090e3333501478d23591e9d2613eb3b7a76aaf"
)

# Oracle value used only as a leakage sentinel by this builder.
# It is never written into the output bundle.
FORBIDDEN_ORACLE_HEX = "adb870799c7d3cc1ac3492d939ad290fda40163b"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--repo",
        type=Path,
        default=Path("/home/hal/xp-cgr-lab"),
    )
    args = ap.parse_args()

    repo = args.repo.resolve()
    challenge = (
        repo
        / "evidence/inverse-benchmark-v1/provider-preimage-challenge.json"
    )
    verifier = repo / "tools/verify_full160_candidate.py"
    out = (
        repo
        / "evidence/inverse-benchmark-v2/phase-g-full160-blind-bundle"
    )

    if not challenge.is_file():
        raise SystemExit(f"FAIL missing challenge: {challenge}")
    if not verifier.is_file():
        raise SystemExit(f"FAIL missing verifier: {verifier}")

    challenge_sha = sha256(challenge)
    verifier_sha = sha256(verifier)

    if challenge_sha != EXPECTED_CHALLENGE_SHA256:
        raise SystemExit(
            "FAIL challenge hash mismatch: "
            f"{challenge_sha} != {EXPECTED_CHALLENGE_SHA256}"
        )
    if verifier_sha != EXPECTED_VERIFIER_SHA256:
        raise SystemExit(
            "FAIL verifier hash mismatch: "
            f"{verifier_sha} != {EXPECTED_VERIFIER_SHA256}"
        )

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    shutil.copy2(challenge, out / "challenge.json")
    shutil.copy2(verifier, out / "verify_candidate.py")

    readme = """# Phase G — FULL-160 Oracle-Isolated Challenge Bundle

This directory is the complete input surface for the Phase-G solver run.

## Public relation

For each instance, recover a 160-bit `xval` satisfying:

    out_a = G(xval)
    out_b = G((xval + out_a + 1) mod 2^160)

where `G` is SHA-1 compression of `xval || 44*00`, using the standard
SHA-1 IV, with no SHA-1 message padding.

## Isolation contract

The solver may read only files in this directory.

The bundle contains no captured AUX value, no CGR640 event log, no reduced
benchmark, and no serialized known XVAL candidate.

`xkey_before_hex`, `out_a_hex`, and `out_b_hex` are public challenge data.

The verifier independently recomputes both compression relations and pins the
challenge file to its frozen SHA-256.

This is oracle-isolated, not operator-blind: the experimenter may know a
reference solution from earlier phases, but that solution is not available to
the solver input surface.
"""
    (out / "README.md").write_text(readme, encoding="utf-8")

    # Leakage check over generated textual bundle before manifest creation.
    for p in sorted(out.iterdir()):
        if not p.is_file():
            raise SystemExit(f"FAIL unexpected non-file entry: {p.name}")
        text = p.read_text(encoding="utf-8", errors="ignore").lower()
        if FORBIDDEN_ORACLE_HEX in text:
            raise SystemExit(f"FAIL oracle leakage detected in {p.name}")

    expected_names = {"challenge.json", "verify_candidate.py", "README.md"}
    actual_names = {p.name for p in out.iterdir()}
    if actual_names != expected_names:
        raise SystemExit(
            f"FAIL unexpected bundle contents before manifest: {sorted(actual_names)}"
        )

    manifest_lines = []
    for name in ("challenge.json", "verify_candidate.py", "README.md"):
        manifest_lines.append(f"{sha256(out / name)}  {name}")
    (out / "MANIFEST_SHA256.txt").write_text(
        "\n".join(manifest_lines) + "\n",
        encoding="utf-8",
    )

    final_names = {p.name for p in out.iterdir()}
    expected_final = expected_names | {"MANIFEST_SHA256.txt"}
    if final_names != expected_final:
        raise SystemExit(f"FAIL unexpected final bundle contents: {sorted(final_names)}")

    # Recheck leakage, including manifest.
    for p in sorted(out.iterdir()):
        text = p.read_text(encoding="utf-8", errors="ignore").lower()
        if FORBIDDEN_ORACLE_HEX in text:
            raise SystemExit(f"FAIL oracle leakage detected in {p.name}")

    print("PHASE_G_SOURCE_CHALLENGE_SHA256=" + challenge_sha)
    print("PHASE_G_SOURCE_VERIFIER_SHA256=" + verifier_sha)
    print("PHASE_G_ORACLE_LEAKAGE_CHECK=PASS")
    print("PHASE_G_BUNDLE_FILE_COUNT=4")
    print("PHASE_G_BUNDLE=" + str(out))
    print("PHASE_G_BUNDLE_BUILD=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
