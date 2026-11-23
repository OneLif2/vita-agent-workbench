#!/bin/sh
# Host Linux fixture; never links production binaries back to the Vita.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/../.." && pwd)
src=${WB_SOURCE_DIR:-"$root/source"}
R=${WB_LIBSSH_REVIEW_ROOT:?Set to matching libssh/mbedTLS native build directory}
out=${1:?Pass a temporary output directory}
mkdir -p "$out"
policy=""
if ! grep -q 'savedata0:' "$src/wb_host_identity.h"; then
  policy="-DWB_LEGACY_BASELINE"
fi
for c in crypto_roundtrip identity_test; do
    gcc -std=c11 -Wall -Wextra -Werror -O2 $policy \
        -I"$here/sim" -I"$src" -I"$R/libssh-0.12.2/include" \
        -I"$R/native-ssh/include" -I"$R/mbedtls-ssh/include" \
        "$here/$c.c" "$src/wb_sha256.c" "$R/native_platform.c" \
        "$R/native-init-explicit/libssh.a" "$R/mbed-native/library/libmbedcrypto.a" \
        -lpthread -o "$out/$c"
    "$out/$c"
done
