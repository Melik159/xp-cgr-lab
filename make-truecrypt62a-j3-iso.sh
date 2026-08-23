#!/bin/bash
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")" && pwd)
stage_dir="$repo_dir/build/j3/iso-root"
iso_path="$repo_dir/tools/truecrypt62a-j3.iso"

mkdir -p "$stage_dir"
cp "$repo_dir/build/j2/cgr_trace.dll" "$stage_dir/"
cp "$repo_dir/build/j2/cgr_trace_runner.exe" "$stage_dir/"
cp "$repo_dir/software/truecrypt-archive/repo/TrueCrypt Setup 6.2a.exe" "$stage_dir/"
cp "$repo_dir/j3/packaging/"*.bat "$stage_dir/"
cp "$repo_dir/j3/packaging/README.txt" "$stage_dir/"
printf 'XP_SP3_CGR_LAB_J3\r\n' > "$stage_dir/J3TOOLS.TAG"

(cd "$stage_dir" && sha256sum * > hashes.sha256)
xorriso -as mkisofs -quiet -J -R -V XP_CGR_J3 -o "$iso_path" "$stage_dir"
sha256sum "$iso_path"
