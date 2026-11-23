#!/bin/sh
set -eu
[ "$#" -eq 1 ] || exit 64
d=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cp "$d/BASELINE.h" "$1"
cmp "$d/BASELINE.h" "$1"
printf "%s\n" "restored pristine R1 header"
