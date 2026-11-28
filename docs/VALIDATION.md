# Validation scope (`02.21-hyper-sftp`)

## Reference build validation (private hardware & Jetson cross-build)

- **Host verification:** `12/12` focused pin/security suites + `95/95` host regression suites passed against the exact frozen `02.21` source tree, including:
  - `linux_shell2`: dynamic `pi@vita:/path$ ` prompt, `cd`/`~`/`-`/`/`, ANSI SGR 16-color OLED mirror, SFTP `ATTR_SIZE`/`fstat` total progress, `wb_xfer_format_pct`, `app prune`.
  - `large_zip`: 9-bit Huffman lookup table `-O3` inflate verified against 250 differential `zlib` streams, 250 trailing-byte rejections, and 2,000 malformed fuzz streams.
  - `app_approve_native`: 64-row runtime approval capacity, dedup, and `app prune`.
  - `sftp_interop`, `scp_stock`, `sftp_ro_engine`, `sftp_ro_vita`, `sftp_admission`, `WBQ2`.
- **Cross-build verification:** ARM32 SELF (`authid 0x2f00000000000001`), 3-member CRC, compressed/uncompressed ELF segment identity proof, and `INAP00018 02.21` / payload `01.22-p2.1` checks passed. Reference VPK (`974,399 B`, SHA-256 `58bab7035ddb3f9b7330cdc67fb3cf2faa6dc0898cfd4556bce79d240a1be8a0`) is **not distributed**.
- **Live PS Vita hardware verification:**
  - Zero-button WBQ2 self-update `02.20 -> 02.21` completed in `15.27 s` (`0` physical Vita buttons pressed) with pinned host key verified on PC terminal only.
  - Live `8 MiB` `wb2.py` Turbo SFTP PUT reached **`2.155–2.273 MiB/s`** wire stream and **`1.425–1.460 MiB/s`** end-to-end (including `sceIoSyncByFd` + full-file SD readback SHA-256), up **+53%–55%** over `02.20` (`1.464` stream / `0.954` total). Reference local Vita SD `cp` (R+W) measured `3.36 MiB/s` and `sha256sum` measured `5.78 MiB/s`.
  - All anti-brick and credential protections verified live (`host.private`, `mac-public-pin.txt`, `ur0:/tai` write, `INAP00018`/`INAP00019`/`NPXS*` removal all denied).

## Public-export host verification

Selected host-only C/SDK-stub tests are re-run directly on this sanitized public tree (no Vita or network I/O) before publication and recorded in `PUBLIC-HOST-TESTS.json` outside the repository.
