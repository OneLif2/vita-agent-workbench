#!/bin/sh
set -eu
export TZ=UTC VITASDK=${VITASDK:-/home/pi/.ina-vita-build.SiSrFyLM/sdk}
export PATH="$VITASDK/bin:$PATH"
# Always invoke in a fresh frozen sources/ directory. Never overwrite an old out/.
mkdir out
cc -std=c11 -O2 -Wall -Wextra -Werror host.c -o out/policy-host
./out/policy-host
for n in main worker; do
  libs=""
  [ "$n" != main ] || libs="-lSceSysmodule_stub -lSceBgAppUtil_stub_weak -lSceAppMgr_stub"
  case "$n" in main) heap_bytes=1048576;; worker) heap_bytes=524288;; *) exit 2;; esac
  printf 'unsigned int _newlib_heap_size_user = %su;\n' "$heap_bytes" > "out/$n.heap.c"
  arm-vita-eabi-gcc -std=c11 -Os -Wall -Wextra -Werror -I.. -Icommon -Wl,-q,--defsym=__sce_headroom=0x1000,--wrap=sceNetRecv,--wrap=sceNetSend,--wrap=sceNetSocketClose "$n.c" "out/$n.heap.c" storage.c probe_io.c offline.c $libs -lSceRtc_stub -lSceAppUtil_stub -lSceLibKernel_stub -lSceIofilemgr_stub -o "out/$n.elf"
  python3 common/check_core_layout.py "out/$n.elf"
  arm-vita-eabi-nm "out/$n.elf" > "out/$n.syms"
  for symbol in sceAppUtilSaveDataDataSave sceKernelGetSystemTimeWide sceRtcGetCurrentTick sceIoSyncByFd; do grep -w "$symbol" "out/$n.syms"; done
  if grep -E '[[:space:]](sceNet|ssh_|sceAppMgrDestroy|scePromoterUtility|sceShell|tai[A-Z]|sceCtrl|sceDisplay|sceGxm)' "out/$n.syms"; then exit 2; fi
  case $n in
   main)
    grep -w sceBgAppUtilStartBgApp out/main.syms
    grep -w sceAppMgrLaunchAppByUri out/main.syms
    grep -w sceKernelExitProcess out/main.syms
    if grep -E '[[:space:]]sceAppMgr' out/main.syms | grep -v 'sceAppMgrLaunchAppByUri$'; then exit 2; fi
    e=eboot.bin; m=0x2000; a=0;;
   worker)
    if grep -E '[[:space:]](sceBgAppUtil|sceAppMgr)' out/worker.syms; then exit 2; fi
    e=eboot2.bin; m=0x1000; a=3;;
  esac
  vita-elf-create "out/$n.elf" "out/$n.velf"
  vita-make-fself -s -m "$m" -at "$a" "out/$n.velf" "out/$e"
done
vita-mksfoex -s TITLE_ID=WBLC00079 -s APP_VER=01.02 -d ATTRIBUTE=16809984 -s CATEGORY=gdc -s PUBTOOLINFO=has_bg=1 'WB Lifecycle' out/param.sfo
vita-mksfoex -s TITLE_ID=WBLB00079 -s APP_VER=01.02 -d ATTRIBUTE=17305600 -s CATEGORY=gdd -s INSTALL_DIR_ADDCONT=WBLC00079 -s INSTALL_DIR_SAVEDATA=WBLC00079 'WB Lifecycle BG' out/param2.sfo
vita-pack-vpk -s out/param.sfo -b out/eboot.bin -a out/eboot2.bin=eboot2.bin -a out/param2.sfo=sce_sys/param2.sfo out/wake-probe.vpk
python3 ../verify_package.py out/wake-probe.vpk
sha256sum out/wake-probe.vpk
