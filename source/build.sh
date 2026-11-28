#!/bin/sh
# Builds Workbench v2.21 (SFO 02.21): the eboot core, the live-swappable payload and the
# update VPK. Requires a VitaSDK with the libssh/mbedtls inputs 01.09 used.
#
#   VITASDK=/path/to/vitasdk \
#   VITA_PLATFORM_OBJECT=/path/to/mbed_platform.o \
#   ./build.sh build
set -eu

v=${VITASDK:?Set VITASDK to the VitaSDK root}
export PATH="$v/bin:$PATH" TZ=UTC
b=${1:-build}
platform_object=${VITA_PLATFORM_OBJECT:?Set VITA_PLATFORM_OBJECT to the Vita Mbed TLS platform object}

libssh_include=${LIBSSH_INCLUDE:-../libssh-0.12.2/include}
libssh_include2=${LIBSSH_INCLUDE2:-../ssh-arm-explicit/include}
libssh_archive=${LIBSSH_ARCHIVE:-../ssh-arm-explicit/src/libssh.a}
mbed_include=${MBED_INCLUDE:-../mbedtls-ssh/include}
mbed_lib=${MBED_LIB:-../mbed-arm/library}
extra_libs=${WB_EXTRA_LIBS:-SceKernelModulemgr_stub}

mkdir -p "$b"
echo "== validate owner App registry (compiled into core; not writable over SSH)"
python3 -B ../tools/gen_app_registry.py "$b/registry-generated/wb_registry_data.inc"

cflags="-std=c11 -DWITH_SERVER -DWB_SHELL2 -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-function -Os -mcpu=cortex-a9 -mtune=cortex-a9"
cflags="$cflags -I. -I$libssh_include -I$libssh_include2 -I$mbed_include"

core_src="vita_ssh_status.c display.c startup.c
wb_err.c wb_str.c wb_sha1.c wb_crc32.c wb_inflate.c wb_zip.c
wb_sfo.c wb_head.c wb_path.c wb_out.c wb_payload.c wb_cmd.c wb_install.c
wb_ssh.c wb_shell.c wb_shell_channel.c wb_tty_file.c wb_shell_vfs.c wb_sftp_ro.c wb_sftp_vita.c wb_sftp_frame.c wb_photo_gate.c wb_vita_photo.c wb_vita_io.c wb_vita_install.c wb_vita_payload.c wb_updater.c wb_timeline.c
../unsupported_vita_calls.c"

stubs="-lSceGxm_stub -lSceDisplay_stub -lSceAppUtil_stub -lSceCommonDialog_stub
-lSceNet_stub -lSceNetCtl_stub -lSceSysmodule_stub -lSceLibKernel_stub
-lSceAppMgr_stub -lSceIofilemgr_stub -lSceRtc_stub -lSceCtrl_stub -lSceTouch_stub -lScePower_stub
-lScePromoterUtil_stub -lScePhotoExport_stub"

for lib in $extra_libs; do stubs="$stubs -l$lib"; done

echo "== updater (INAP00019)"
# A separate title that promotes the staged core. Same role as VitaShell's
# VSUPDATER: the running app can never replace its own eboot.
mkdir -p "$b/updater"
# Do not silently create a new helper identity per core release. Use the exact
# approved 01.74 binary and SFO, refuse source drift pending a new helper epoch.
python3 -B verify_helper_epoch.py "$b/updater"
vita-pack-vpk -s "$b/updater/param.sfo" -b "$b/updater/eboot.bin" "$b/updater/updater_0119.vpk"
( cd "$b" && arm-vita-eabi-ld -r -b binary -o updater_res.o updater/eboot.bin updater/param.sfo )

echo "== core"
# Compile wb_sha256.c at -O3 -funroll-loops for the core while keeping source/wb_sha256.c
# byte-identical to the frozen INAP00019 helper epoch 01.74.
arm-vita-eabi-gcc -std=c11 -Wall -Wextra -Werror -O3 -funroll-loops -mcpu=cortex-a9 -mtune=cortex-a9 -I. -c wb_sha256.c -o "$b/wb_sha256.o"
# shellcheck disable=SC2086
arm-vita-eabi-gcc -I"$b/registry-generated" $cflags \
  -Wl,-q,--defsym=__sce_headroom=0x1000,-Map,"$b/workbench.map" \
  -DWB_STANDING_BOOTSTRAP=0 -DWB_GAME_FEATURE -DWB_SCREEN_MIRROR -DWB_TTY_FILE $core_src "$b/wb_sha256.o" wb_game_vita.c wb_game_io.c wb_screen_mirror.c "$b/updater_res.o" "$libssh_archive" "$platform_object" libwbgame.a -lm -L"$mbed_lib" \
  -lmbedcrypto -lpthread $stubs -o "$b/workbench.elf"

echo "== payload"
# shellcheck disable=SC2086
# A loadable module: no crt0, entry at module_start, and no libc calls that
# would become a PLT slot (vita-elf-create rejects R_ARM_JUMP_SLOT). The
# payload carries its own formatter, see payload/payload_main.c.
arm-vita-eabi-gcc $cflags -nostartfiles -fno-builtin \
  -fno-tree-loop-distribute-patterns \
  -Wl,-q,-e,module_start,-Map,"$b/payload.map" \
  ../payload/payload_main.c -lSceLibKernel_stub -lSceIofilemgr_stub -lScePower_stub \
  -o "$b/workbench_payload.elf"

echo "== self"
# The Jetson SDK linker script reserves unmapped space before the RW load
# segment via __sce_headroom. A fixed padding section *inside* RX only
# consumed space; after HF1 code growth the converter had just 1336 bytes.
python3 check_core_layout.py "$b/workbench.elf"
vita-elf-create "$b/workbench.elf" "$b/workbench.velf"
# No -s: the installer needs the full-permission authid 0x2F00000000000001
# (module load from ux0, ScePromoterUtil, renames under ux0:app). A safe
# eboot (0x2F00000000000002) would restrict exactly those paths.
# Standard SDK segment compression shrinks the bytes hashed by the old core;
# this changes neither the linked program nor its full-permission authid.
vita-make-fself -c "$b/workbench.velf" "$b/eboot.bin"
# Independent raw wrapping of the exact same linked VELF is diagnostic only;
# it is never a VPK member or an installation fallback.
vita-make-fself "$b/workbench.velf" "$b/eboot.uncompressed-proof.bin"
PYTHONPATH=../tools python3 - "$b/eboot.bin" "$b/eboot.uncompressed-proof.bin" <<'PY'
from pathlib import Path
import hashlib,sys
from self_segments import parse_self
packed,plain=(Path(p).read_bytes() for p in sys.argv[1:])
c,u=parse_self(packed),parse_self(plain)
assert c.compressed and not u.compressed and c.logical_bytes==u.logical_bytes
assert c.authid==u.authid==0x2f00000000000001 and len(packed)<len(plain)
print('SELF compression proof: packed=%d raw=%d logical_sha256=%s authid=%#x' %
      (len(packed),len(plain),hashlib.sha256(c.logical_bytes).hexdigest(),c.authid))
PY
# -m and -e are mutually exclusive; the explicit entry list is what makes
# module_start reachable for the loader.
vita-elf-create -m module_start,module_stop,module_exit \
  "$b/workbench_payload.elf" "$b/workbench_payload.velf"
vita-make-fself "$b/workbench_payload.velf" "$b/workbench_payload.suprx"

# Keep the known release module byte-identical; the freshly compiled module
# remains in build/ for inspection. A payload-only ABI update is not required.
approved=../payload/release_0122_p2_1.suprx
python3 - "$approved" <<'PY'
import hashlib,pathlib,sys
b=pathlib.Path(sys.argv[1]).read_bytes()
if hashlib.sha256(b).hexdigest()!="0e3a633929b7069a5a194c86bd92eb770515d1766101f597139af61b0a45a66b": raise SystemExit("unapproved payload image")
PY
echo "== package"
vita-mksfoex -s TITLE_ID=INAP00018 -s APP_VER=02.21 'Vita Agent Workbench' "$b/param.sfo"
vita-pack-vpk -s "$b/param.sfo" -b "$b/eboot.bin" \
  -a "$approved=workbench_payload.suprx" \
  "$b/workbench_0221.vpk"

ls -l "$b/eboot.bin" "$b/workbench_payload.suprx" "$b/workbench_0221.vpk"
echo "== done: $b/workbench_0221.vpk"
