#!/bin/bash
set -euo pipefail

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
j2_dir="$project_dir/j2"
build_dir="$project_dir/build/j2"
compiler="${CC:-i686-w64-mingw32-gcc}"
objdump_tool="${OBJDUMP:-i686-w64-mingw32-objdump}"

mkdir -p "$build_dir"

common_flags=(
  -std=gnu99
  -Os
  -Wall -Wextra -Werror
  -DWINVER=0x0501 -D_WIN32_WINNT=0x0501
  -fno-ident
  -fno-omit-frame-pointer
  -static-libgcc
)
linker_flags=(
  -Wl,--no-insert-timestamp
  -Wl,--major-os-version,5,--minor-os-version,1
  -Wl,--major-subsystem-version,5,--minor-subsystem-version,1
  -Wl,--nxcompat,--dynamicbase
  -s
)

"$compiler" "${common_flags[@]}" -shared \
  "${linker_flags[@]}" \
  -o "$build_dir/cgr_trace.dll" \
  "$j2_dir/src/cgr_trace_dll.c"

"$compiler" "${common_flags[@]}" -mconsole \
  "${linker_flags[@]}" \
  -o "$build_dir/cgr_trace_runner.exe" \
  "$j2_dir/src/cgr_trace_runner.c"

sha256sum \
  "$j2_dir/src/cgr_trace_dll.c" \
  "$j2_dir/src/cgr_trace_runner.c" \
  "$build_dir/cgr_trace.dll" \
  "$build_dir/cgr_trace_runner.exe" \
  > "$build_dir/build-hashes.sha256"

{
  "$compiler" --version | sed -n '1,3p'
  "$objdump_tool" --version | sed -n '1,2p'
} > "$build_dir/toolchain.txt"
"$objdump_tool" -f -p "$build_dir/cgr_trace.dll" > "$build_dir/cgr_trace-dll-pe.txt"
"$objdump_tool" -f -p "$build_dir/cgr_trace_runner.exe" > "$build_dir/cgr_trace-runner-pe.txt"

printf 'Built J2 instrumentation in %s\n' "$build_dir"
cat "$build_dir/build-hashes.sha256"
