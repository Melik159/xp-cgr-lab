#!/bin/bash
set -euo pipefail

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
build_dir="$project_dir/build/j2"
iso_file="$project_dir/tools/cgr-trace-j2.iso"
stage_dir="$(mktemp -d)"

cleanup() {
  rm -rf -- "$stage_dir"
}
trap cleanup EXIT

"$project_dir/build-cgr-trace-j2.sh"

cp "$build_dir/cgr_trace.dll" "$stage_dir/cgr_trace.dll"
cp "$build_dir/cgr_trace_runner.exe" "$stage_dir/cgr_trace_runner.exe"
cp "$project_dir/build/cgr_probe.exe" "$stage_dir/cgr_probe.exe"
cp "$project_dir/j2/packaging/README.txt" "$stage_dir/README.txt"
cp "$project_dir/j2/packaging/run-j2.bat" "$stage_dir/run-j2.bat"
cp "$project_dir/j2/src/cgr_trace_dll.c" "$stage_dir/cgr_trace_dll.c"
cp "$project_dir/j2/src/cgr_trace_runner.c" "$stage_dir/cgr_trace_runner.c"
cp "$project_dir/build-cgr-trace-j2.sh" "$stage_dir/build-cgr-trace-j2.sh"
cp "$project_dir/make-cgr-trace-j2-iso.sh" "$stage_dir/make-cgr-trace-j2-iso.sh"
cp "$build_dir/cgr_trace-dll-pe.txt" "$stage_dir/cgr_trace-dll-pe.txt"
cp "$build_dir/cgr_trace-runner-pe.txt" "$stage_dir/cgr_trace-runner-pe.txt"
cp "$build_dir/toolchain.txt" "$stage_dir/toolchain.txt"

j1_probe_hash="$(sha256sum "$project_dir/build/cgr_probe.exe" | awk '{print $1}')"
dll_hash="$(sha256sum "$build_dir/cgr_trace.dll" | awk '{print $1}')"
runner_hash="$(sha256sum "$build_dir/cgr_trace_runner.exe" | awk '{print $1}')"
{
  printf '%s\r\n' \
    'project=XP_SP3_CGR_LAB' \
    'milestone=2' \
    'target=Windows XP Professional SP3 x86' \
    'instrumentation=process-local main-image IAT hooks' \
    'cgr_hook=ADVAPI32.dll!CryptGenRandom IAT' \
    'rtl_hook=KERNEL32.dll!GetProcAddress substitution for SystemFunction036' \
    'compiler=i686-w64-mingw32-gcc GCC 10-win32 20220113' \
    "j1_probe_sha256=$j1_probe_hash" \
    "trace_dll_sha256=$dll_hash" \
    "trace_runner_sha256=$runner_hash"
} > "$stage_dir/manifest.txt"

(
  cd "$stage_dir"
  sha256sum * > hashes.txt
)

TZ=UTC xorriso -as mkisofs \
  -quiet -iso-level 3 -J -joliet-long -R \
  -V CGR_TRACE_J2 \
  -uid 0 -gid 0 -dir-mode 0555 -file-mode 0444 \
  --modification-date=2026082300000000 \
  --set_all_file_dates 2026082300000000 \
  -o "$iso_file" "$stage_dir"

sha256sum "$iso_file" > "$build_dir/iso.sha256"
printf 'Created %s\n' "$iso_file"
cat "$build_dir/iso.sha256"
