# Source publication handover — `psvita-agent-terminal` (`02.21-hyper-sftp`)

This repository is a sanitized, source-only publication of **PS Vita Agent Terminal** (formerly *Vita Agent Workbench*) at reference release **`02.21` (`02.21-hyper-sftp`)**. No VPKs, precompiled libraries, private keys, personal host pins, or device logs are included.

## Major milestones since `02.06`
- **`02.15–02.17`:** Fast-paced SFTP (`444/222 MHz` clock boost, Core-1 async ring-buffer writer), Linux-style built-in commands (`ll`, `sha256sum`, `head`, `tail`, `du -h`, `df -h`, `cp`, `touch`, `clear`, `free -h`, `uptime`, `uname -a`), and idle display-off fix.
- **`02.18`:** Workbench 2.0 agent-operated architecture — zero-button WBQ2 self-updates (`tools/wb2.py update`), generic app lifecycle (`app ls`, `app install-vpk`, `app patch-eboot`, `app launch`, `app remove`), integrated `WB_SHELL2` (readline, history, pipelines, multi-mount `/ux0`/`/ur0`/`/uma0`), and removal of on-Vita host-key screens.
- **`02.19–02.20`:** Dynamic colored `pi@vita:/path$ ` prompt, GitHub-Dark 16-color ANSI OLED terminal window, real `0–100%` live OLED progress bars across SFTP and all long app operations, 9-bit Huffman `-O3` inflate + `128 KiB` ZIP buffers, `-O3 -funroll-loops` core SHA-256, `64`-row `apps.local` + `app prune`, atomic `app patch-eboot` with rollback, and `SSH_REQUEST_GLOBAL` keepalive handling.
- **`02.21`:** Hyper-SFTP transfer optimizations (`-O3` Cortex-A9 `libssh`/`libmbedcrypto`, `MAX_BUF_SIZE=65536`, `2 MiB` `SceNet` pool + `512 KiB` TCP buffers, `250 ms` OLED pacing, pipelined SFTP reply coalescing, `256 KiB` GET read-ahead, Core-1 overlapped SHA-256), pushing live encrypted PUT streams to `2.15–2.27 MiB/s`.

## Known follow-up items
- Restore/optimize `SFTP GET` non-blocking socket flush inside `wb_sf_pump`/`sftp_wr` so pipelined downloads match the `2+ MiB/s` upload stream rate.
- Optional fast-close SFTP mode (avoiding redundant full-file SD readback when callers verify SHA-256 separately).
- Reproducible public updater/payload epoch build workflow and generic first-pair setup tooling.
