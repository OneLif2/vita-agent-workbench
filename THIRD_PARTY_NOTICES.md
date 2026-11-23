# Third-party notices and licensing scope

The root Apache-2.0 license applies to original Workbench code only. It does not
relicense third-party material or remove existing notices. This source tree is
not represented as Apache-only. Binary redistribution requires a separate review
of all combined components; this publication contains no compiled binaries.

| Component | Scope / source | License treatment |
|---|---|---|
| VitaShell | `source/wb_head_template.inc` explicitly identifies VitaShell `resources/head.bin`; `wb_head.c` follows its package-header scheme. Promoter integration also credits VitaShell. Upstream: https://github.com/TheOfficialFloW/VitaShell | Preserve GPLv3 for the template / upstream-derived material; full upstream GPLv3 text in `LICENSES/GPL-3.0.txt`. Do not interpret the root Apache file as relicensing this material. |
| JetBrains Mono | Derived ASCII bitmap data in `source/wb_font_jetbrains.h` and `source/wb_jetbrains_*.h`, and original font notice | SIL Open Font License 1.1; see `LICENSES/JetBrainsMono-OFL-1.1.txt` and `tools/font_assets/README.md`. The upstream TTF is not bundled. |
| MicroPython | External v1.25.0 source dependency used by `runtime/` | MIT / upstream per-file notices; upstream license retained in `LICENSES/MicroPython-MIT.txt`. No upstream archive or precompiled runtime is bundled. |
| libssh | External cross-compiled dependency, not bundled | Retain upstream license for the exact version used: https://www.libssh.org/license/ |
| Mbed TLS | External cryptography / platform dependency, not bundled | Consult the exact upstream version's license: https://github.com/Mbed-TLS/mbedtls |
| VitaSDK | External toolchain / headers / stubs, not bundled | Upstream per-component licenses: https://github.com/vitasdk |

VitaShell package-installer reference retains the copyright of TheFloW; see
https://github.com/TheOfficialFloW/VitaShell/blob/master/package_installer.c .
No claim is made that functional API knowledge or original Workbench code changes
have all been authored by an upstream project. This is a provenance notice, not
a certification that a future combined binary satisfies every dependency's terms.
