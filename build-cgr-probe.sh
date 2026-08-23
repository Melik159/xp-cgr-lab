#!/bin/bash
set -euo pipefail

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
build_dir="$project_dir/build"
source_file="$project_dir/src/cgr_probe.c"
output_file="$build_dir/cgr_probe.exe"
compiler="${CC:-i686-w64-mingw32-gcc}"
objdump_tool="${OBJDUMP:-i686-w64-mingw32-objdump}"

mkdir -p "$build_dir"

"$compiler" \
  -std=c89 \
  -Os \
  -Wall -Wextra -Werror -pedantic \
  -DWINVER=0x0501 -D_WIN32_WINNT=0x0501 \
  -fno-ident \
  -static-libgcc \
  -mconsole \
  -Wl,--no-insert-timestamp \
  -Wl,--major-os-version,5,--minor-os-version,1 \
  -Wl,--major-subsystem-version,5,--minor-subsystem-version,1 \
  -Wl,--nxcompat,--dynamicbase \
  -s \
  -o "$output_file" \
  "$source_file" \
  -ladvapi32

sha256sum "$source_file" "$output_file" > "$build_dir/build-hashes.sha256"
{
  "$compiler" --version | sed -n '1,3p'
  "$objdump_tool" --version | sed -n '1,2p'
} > "$build_dir/toolchain.txt"
"$objdump_tool" -f -p "$output_file" > "$build_dir/pe-info.txt"

printf 'Built %s\n' "$output_file"
cat "$build_dir/build-hashes.sha256"
