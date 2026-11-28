# Building and configuration boundaries

This is a source-only export of `psvita-agent-terminal` (reference `02.21`). External toolchains/dependencies and local trust configuration are deliberately not bundled; an unconfigured native build is expected to fail closed rather than silently enrolling a key or disabling checks.

1. Obtain VitaSDK, `libssh 0.12.2`-compatible headers/server archive, matching Mbed TLS (`3.6.x`), and the Vita Mbed TLS platform object.
   - **Performance note (`02.21`):** Build `libssh.a` and `libmbedcrypto.a` with `-O3 -mcpu=cortex-a9 -mtune=cortex-a9 -mfpu=neon -mfloat-abi=hard -DNDEBUG -fno-pic -fno-pie` (with `-DMAX_BUF_SIZE=65536 -DWITH_DEBUG_CALLTRACE=OFF -DWITH_PCAP=OFF` for `libssh`, ensuring `-fPIC` is not emitted so `vita-elf-create` accepts all ARM relocations). Compiling `libssh.a` at default `-O0` significantly caps SFTP throughput.
2. Review `source/wb_standing_provision.h.example`. Generate your own public host, owner, and release-signer provisioning, then create the ignored `source/wb_standing_provision.h`. Never commit any private key. Update local `192.0.2.x` documentation addresses and `HOST_SHA256` slots in your local config.
3. Review `tools/apps.txt` as reference approvals and regenerate the compiled registry with `tools/gen_app_registry.py`.
4. Rebuild the fixed-game library from `runtime/`; see `runtime/README.md`. Place the resulting `libwbgame.a` in `source/`.
5. In `source/`, set `VITASDK`, `VITA_PLATFORM_OBJECT`, `LIBSSH_INCLUDE`, `LIBSSH_INCLUDE2`, `LIBSSH_ARCHIVE`, `MBED_INCLUDE`, and `MBED_LIB`, then run `sh build.sh build`.

## Frozen helper/payload inputs

`source/verify_helper_epoch.py` expects the approved updater epoch `01.74` (`manifest.json`, `eboot.bin`, `param.sfo`) and `source/build.sh` expects the approved `payload/release_0122_p2_1.suprx`. Those binary records are omitted from this source-only repository (sources for both updater and payload are included in `updater/` and `payload/`).
