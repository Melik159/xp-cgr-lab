#!/bin/bash
set -euo pipefail

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
build_script="$project_dir/build-cgr-probe.sh"
build_dir="$project_dir/build"
source_file="$project_dir/src/cgr_probe.c"
iso_file="$project_dir/tools/cgr-probe.iso"
readme_file="$project_dir/packaging/README.txt"
batch_file="$project_dir/packaging/run_probe.bat"
stage_dir="$(mktemp -d)"

cleanup() {
  rm -rf -- "$stage_dir"
}
trap cleanup EXIT

"$build_script"

cp "$build_dir/cgr_probe.exe" "$stage_dir/cgr_probe.exe"
cp "$source_file" "$stage_dir/cgr_probe.c"
cp "$readme_file" "$stage_dir/README.txt"
cp "$batch_file" "$stage_dir/run_probe.bat"
cp "$build_script" "$stage_dir/build-cgr-probe.sh"
cp "$project_dir/make-cgr-probe-iso.sh" "$stage_dir/make-cgr-probe-iso.sh"
cp "$build_dir/pe-info.txt" "$stage_dir/pe-info.txt"
cp "$build_dir/toolchain.txt" "$stage_dir/toolchain.txt"

source_sha256="$(sha256sum "$source_file" | awk '{print $1}')"
exe_sha256="$(sha256sum "$build_dir/cgr_probe.exe" | awk '{print $1}')"
{
  printf '%s\r\n' \
    'project=XP_SP3_CGR_LAB' \
    'milestone=1' \
    'target=Windows XP Professional SP3 x86' \
    'machine=XPCASE-2009' \
    'binary=cgr_probe.exe' \
    'format=PE32 i386 console subsystem 5.01' \
    'crypto_provider=default PROV_RSA_FULL with CRYPT_VERIFYCONTEXT|CRYPT_SILENT' \
    'rtl_symbol=advapi32.dll!SystemFunction036 (resolved dynamically)' \
    'output_format=JSONL' \
    'timestamp=GetSystemTime UTC (millisecond field)' \
    'compiler=i686-w64-mingw32-gcc (GCC 10-win32 20220113; Ubuntu package 10.3.0-14ubuntu1+24.3)' \
    'binutils=GNU Binutils 2.38 (Ubuntu package 2.38-3ubuntu1+9build1)' \
    'iso_tool=xorriso 1.5.4 (Ubuntu package 1.5.4-2)' \
    "source_sha256=$source_sha256" \
    "executable_sha256=$exe_sha256"
} > "$stage_dir/manifest.txt"

(
  cd "$stage_dir"
  sha256sum \
    cgr_probe.c \
    cgr_probe.exe \
    README.txt \
    manifest.txt \
    run_probe.bat \
    build-cgr-probe.sh \
    make-cgr-probe-iso.sh \
    pe-info.txt \
    toolchain.txt > hashes.txt
)

# Fixed ISO and file dates, numeric ownership and stable ordering make repeated
# invocations byte-for-byte reproducible for identical payload files.
TZ=UTC xorriso -as mkisofs \
  -quiet \
  -iso-level 3 \
  -J -joliet-long \
  -R \
  -V CGR_PROBE \
  -uid 0 -gid 0 \
  -dir-mode 0555 -file-mode 0444 \
  --modification-date=2026082300000000 \
  --set_all_file_dates 2026082300000000 \
  -o "$iso_file" \
  "$stage_dir"

sha256sum "$iso_file" > "$build_dir/iso.sha256"
printf 'Created %s\n' "$iso_file"
cat "$build_dir/iso.sha256"
