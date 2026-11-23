#!/bin/sh
# Build + verify. On the Mac with VitaSDK installed this is the one command
# that produces the update VPK and the artefacts the host tools expect.
set -eu
b=${1:-build}
sh ./build.sh "$b"

if command -v python3 >/dev/null 2>&1; then
    python3 verify_package.py "$b"
else
    echo "python3 required for package verification" >&2; exit 1
fi

ver=$(awk '$1=="#define" && $2=="WB_VERSION"{gsub(/[".]/,"",$3);print $3}' wb_ver.h)
case "$ver" in [0-9][0-9][0-9][0-9]) ;; *) echo "invalid WB_VERSION for VPK" >&2; exit 1;; esac
pkg="$b/workbench_${ver}.vpk"
if command -v shasum >/dev/null 2>&1; then
    sum=$(shasum -a 256 "$pkg") || exit 1
else
    sum=$(sha256sum "$pkg") || exit 1
fi
printf '%s\n' "$sum" > "$pkg.sha256"
printf '%s\n' "$sum"
