#!/bin/sh
# Run from a separate build directory; never updates the shared SDK.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${VITASDK:?Set VITASDK to the existing VitaSDK installation}"
export PATH="$VITASDK/bin:$PATH" TZ=UTC LC_ALL=C
rev=f498a16c7db6d4b2de200b3e0856528dfe0613c3
src_tar=${1:?"Usage: rebuild.sh /absolute/path/micropython-COMMIT.tar.gz"}
case "$src_tar" in /*) ;; *) echo "Provide an absolute archive path" >&2; exit 2;; esac
echo "77b0641c47213f41d14d71085cbca086e4ce87ae809c34ddb823c61ea820eca4  $src_tar" | sha256sum -c -
printf 'MicroPython source revision %s\n' "$rev"
b=$(mktemp -d "${TMPDIR:-/tmp}/wbgame-build.XXXXXXXX"); cd "$b"
echo "Build directory: $b"; mkdir src; tar xzf "$src_tar" --strip-components=1 -C src
for x in game.c wb_game.h mpconfigport.h native.mk embed.mk host.c host_tests.py pin_script.py tictactoe_ai.py; do cp -- "$here/$x" .; done
python3 -B pin_script.py tictactoe_ai.py game_blob.inc
make -f embed.mk MICROPYTHON_TOP=./src -j4
make -f native.mk -j4
cc -Os host.c obj-host/libwbgame.a -lm -o host-test
python3 -B host_tests.py ./host-test
make -f embed.mk MICROPYTHON_TOP=./src CROSS_COMPILE=arm-vita-eabi- BUILD=build-vita PACKAGE_DIR=mp-vita -j4
make -f native.mk CC=arm-vita-eabi-gcc AR=arm-vita-eabi-ar OBJDIR=obj-vita MP=mp-vita -j4
sha256sum obj-vita/libwbgame.a; arm-vita-eabi-size obj-vita/game.o
# Linux build outputs stay in the printed build dir. No console operations here.
