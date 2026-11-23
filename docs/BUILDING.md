# Building and configuration boundaries

This is a source-only research export. External toolchains/dependencies and local
trust configuration are deliberately not bundled; an unconfigured native build
is expected to stop, not silently enroll a key or disable checks.

1. Obtain VitaSDK, libssh 0.12.2-compatible headers/server archive, matching Mbed TLS
   and the project's Vita Mbed TLS platform object. These dependencies need their
   own upstream build instructions; no SDK installer is run by this repository.
2. Review `source/wb_standing_provision.h.example`. Generate your own public host,
   owner and release-signer provisioning, then create the ignored actual header.
   Never copy another owner's pins or commit any private key. Public host-tool
   slots must also be configured locally; invalid slots intentionally fail checks.
3. Review `tools/apps.txt` as reference approvals, not a bundle of installable apps.
   Build/approve your own artifacts and regenerate the registry with
   `tools/gen_app_registry.py`. No third-party VPK is supplied.
4. Rebuild the fixed-game library from `runtime/`; see its README. Put the resulting
   local `libwbgame.a` in `source/`. The precompiled archive is intentionally omitted.
5. In `source/`, set `VITASDK`, `VITA_PLATFORM_OBJECT`, `LIBSSH_INCLUDE`,
   `LIBSSH_INCLUDE2`, `LIBSSH_ARCHIVE`, `MBED_INCLUDE` and `MBED_LIB`, then review
   `build.sh` before invoking `sh build.sh build`.

The original release coordinator depended on private input manifests and sibling
version trees; it is not included as a reusable public deployment pipeline. Do
not fake successful manifests or skip native title/path/hash/R1 checks to build.
Further public-build portability work is pending; no fresh generic native build
or new-device pairing acceptance is claimed for this export.

## Additional frozen inputs: packaging is intentionally incomplete

The steps above describe prerequisites, not a complete runnable public build.
`source/verify_helper_epoch.py` also requires the approved epoch-0174
`manifest.json`, `eboot.bin` and `param.sfo`; `source/build.sh` requires the exact
approved `payload/release_0122_p2_1.suprx`. These frozen binary/input records are
not included in this source-only publication. Sources for the updater and payload
are present, but a new rebuild does not automatically reproduce an approved hash.
The approved-input guards will stop packaging. Do not bypass them or fabricate
manifests: a reviewed, reproducible public helper/payload release workflow is
pending. Private LAN defaults are replaced with TEST-NET documentation addresses;
they are not reachable device configuration.
