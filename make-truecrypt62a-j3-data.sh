#!/bin/bash
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")" && pwd)
image_path="$repo_dir/build/j3/j3-data.img"

if [[ -e "$image_path" ]]; then
    echo "Refusing to overwrite existing $image_path" >&2
    exit 1
fi
truncate -s 64M "$image_path"
mformat -i "$image_path" -v J3DATA ::
printf 'XP_SP3_CGR_LAB_J3_DATA\r\n' > "$repo_dir/build/j3/J3DATA.TAG"
mcopy -i "$image_path" "$repo_dir/build/j3/J3DATA.TAG" ::J3DATA.TAG
mdir -i "$image_path" ::
sha256sum "$image_path"
