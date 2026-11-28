# PS Vita Agent Terminal (`psvita-agent-terminal`)

*Formerly `vita-agent-workbench`.*

Agent-operated, Linux-style SSH terminal and verified OTA deployment environment for PlayStation Vita.
Reference development release: **`02.21` / `02.21-hyper-sftp`** (source-only research snapshot — **no VPK, precompiled library, private key, or game package is distributed**).

## Highlights

- **Linux-Style Interactive SSH Terminal (`WB_SHELL2`):**
  - Dynamic ANSI-colored prompt (`pi@vita:/ux0$ `) that updates live on `cd` (`cd ux0:/VITA-POC`, `cd /ur0/tai`, `cd /`, `cd -`, `cd ~`).
  - Interactive readline editing (`↑`/`↓` 32-entry history, `←`/`→`/`Home`/`End`, `Ctrl-A`/`E`/`K`/`W`/`L`), bash-style multi-match Tab completion, command chaining (`;`, `&&`), and pipelines (`| grep`, `| head`, `| tail`, `| wc`, `| sort`, `| uniq`).
  - Multi-mount read-only browsing (`/ux0`, `/ur0`, `/uma0`) with a dedicated writable `/inbox` (`ux0:/VITA-POC`), plus built-in `ls`, `ll`, `ls -lh`, `cat`, `head`, `tail`, `grep`, `find`, `hexdump`/`xxd`, `sha256sum`, `cp`, `rm`, `touch`, `du -h`, `df -h`, `free -h`, `uptime`, `uname -a`, `history`, and `clear`.
- **Live GitHub-Dark OLED Terminal Mirror (`960×544`):**
  - `#0d1117` dark terminal window on the Vita OLED with `#161b22` titlebar, `• SSH ONLINE` / `BASH` status badges, full 16-color ANSI SGR rendering, solid green block cursor, and D-pad viewport scroll/pan.
  - Real-time **`0%–100%`** progress bars with `MB/total`, `MB/s`, and `ETA` for `SFTP PUT`, `SFTP GET`, `VERIFY`, `APP COPY`, `VALIDATE`, `EXTRACT`, `APPROVE`, `INSTALL`, `PATCH`, and `COPY`.
  - SSH host-key verification runs strictly on the PC terminal (`tools/wb2.py`), keeping the Vita screen clean.
- **Hyper-SFTP File Transfer Plane (`02.21`):**
  - `2 MiB` `SceNet` network pool + `512 KiB` TCP buffers + `TCP_NODELAY`, `444 MHz` ARM / `222 MHz` Bus boost during active transfers, `250 ms` OLED refresh pacing, pipelined SFTP reply coalescing, `256 KiB` SFTP GET read-ahead cache, and Core-1 overlapped async disk writer + SHA-256 (`8 × 256 KiB` ring buffer).
  - Verified live on PS Vita 2.4 GHz Wi-Fi with `-O3 -mcpu=cortex-a9` `libssh`/`libmbedcrypto`: **`2.15–2.27 MiB/s`** encrypted upload stream (`1.42–1.46 MiB/s` end-to-end including `sceIoSyncByFd` and full-file SD readback SHA-256).
- **Zero-Button Verified Self-Updates (`tools/wb2.py update`):**
  - Owner-key paired SSH + WBQ2 SHA-256 stage verification (`INAP00018`), followed by `update apply` (`INAP00019` atomic promote + automatic `return-intent` relaunch directly back to `SSH LISTENING` with **0 physical Vita button presses**).
- **App Lifecycle & Fast Archive Engine:**
  - `app ls`, `app install-vpk`, atomic `app patch-eboot` (stages `eboot.bin.new` + SHA-256 verify + backup/rollback on `param.sfo` failure), `app approve` / `app prune` (64-row runtime approval table), and a **9-bit Huffman lookup table `-O3`** inflate engine with `128 KiB` Vita I/O buffers + `-O3 -funroll-loops` SHA-256.
  - Hard anti-brick and credential guardrails blocking raw overwrite or uninstall of Workbench's SSH identity (`host.private`, `mac-public-pin.txt`), `ur0:/tai`, `INAP00018`, `INAP00019`, and Sony system titles (`NPXS*`).

## Verified Reference Build vs This Public Export

The privately configured **`02.21` (`02.21-hyper-sftp`)** reference build was compiled on Jetson (ARM32 VitaSDK) and verified live on a physical PS Vita:
- **Host gates:** `12/12` focused pin/security suites + `95/95` host regression suites passed (including `linux_shell2`, `large_zip` 250 differential + 2,000 fuzz streams, `app_approve_native`, `sftp_interop`, `scp_stock`, and `WBQ2`).
- **Live hardware:** Zero-button upgrade `02.20 -> 02.21` (`15.27 s`, `0` physical buttons pressed), live OLED screenshot capture, `6/6` interactive shell/security verification groups, and `8 MiB` / `16 MiB` live SFTP throughput benchmarks. See [docs/VALIDATION.md](docs/VALIDATION.md).

This public export omits personal provisioning, private release ledgers, machine-specific build scripts, and precompiled archives/binaries. Configuration slots (`HOST_SHA256`, `OWNER_SHA256`, `SIGNER_SHA256`, `SEC1_PUBLIC_KEY`, and `192.0.2.x` TEST-NET addresses) are intentionally fail-closed and must be configured locally.

## Running Host-Only Verification Tests (No Vita Needed)

```sh
python -B tests/linux_shell2/run.py
python -B tests/shell_engine/run.py
python -B tests/sftp_ro_engine/run.py
python -B tests/sftp_interop/run.py
python -B tests/scp_stock/run.py
python -B tests/app_running/run.py
python -B tests/app_running_table/run.py
python -B tests/font_atlas/run.py
```

## Building & Security

- Build prerequisites and frozen-input notes: [docs/BUILDING.md](docs/BUILDING.md)
- Handover & architecture notes: [HANDOVER.md](HANDOVER.md)
- Security & trust boundary: [SECURITY.md](SECURITY.md)
- Publication scope: [docs/PUBLICATION_SCOPE.md](docs/PUBLICATION_SCOPE.md)

## License

Original code: **Apache-2.0**. Third-party exceptions include GPLv3 VitaShell template material, JetBrains Mono SIL OFL 1.1 bitmap data, and external MicroPython MIT notices; **this is not an Apache-only tree**. Read [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), [NOTICE](NOTICE), and [LICENSES/](LICENSES/) before reusing or distributing combined binaries.

Not affiliated with or endorsed by Sony, VitaShell, VitaSDK, JetBrains, or MicroPython.
