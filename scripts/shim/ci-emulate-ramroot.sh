#!/bin/bash
# Wait for a kernel CI run, download to ignored output, then execute diskless QEMU.
# Launch with scripts/bg.sh. No phone tools or partition operations.
set -euo pipefail
run=${1:?CI run ID required}
root=${2:?RAM-root artifact directory required}
case "$run" in *[!0-9]*|'') echo 'Invalid run ID' >&2; exit 2;; esac
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
gh_tool=${GH_EXECUTABLE:-gh}
dest="$repo/out/preservation-ci-run-$run/experimental-preservation-kernel"
"$gh_tool" run watch "$run" --repo MrShmallow99/iOSPlus10 --exit-status --interval 15
mkdir -p "$dest"
download_dest=$dest
if [[ "$gh_tool" == *.exe ]]; then download_dest=$(wslpath -w "$dest"); fi
"$gh_tool" run download "$run" --repo MrShmallow99/iOSPlus10 \
    --name experimental-preservation-kernel --dir "$download_dest"
python3 scripts/shim/emulate-ramroot.py --kernel-artifact "$dest" \
    --ramroot-artifact "$root" --seconds 60
