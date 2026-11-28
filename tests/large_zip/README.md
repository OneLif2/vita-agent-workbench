# Workbench 2.09 ZIP32 streaming engine

Host-only regression: `python -B tests/large_zip/run.py`. No network, device control,
installation, promotion or stopped timing workflow is used.

## Implemented contract

- `wb_zip_stream_entry` emits at most 16,384 bytes per callback, with incremental
  CRC-32, an exact expanded-length bound and exact compressed-stream consumption.
- The existing RFC 1951 decoder now uses a fixed 32 KiB history and two fixed
  16 KiB I/O buffers, rather than holding either entire entry. The caller-buffer
  `wb_zip_read` adapter remains available for small metadata. `extract_all` closes
  a created file on payload read, inflate, CRC, sink write and sink close errors.
- Source reader contents must remain immutable throughout validation/extraction.
  Callers must discard partially emitted staged output after any failure.
- No 32 MiB entry or 256 MiB expanded-total application quota remains here.
  Count/size/offset limits are the implemented ZIP32 format: at most 65,534 entries,
  and 0xfffffffe per size/offset field; ZIP64 marker fields, ZIP64 extra fields,
  local ZIP64 size markers and ZIP64 EOCD locators return `WB_E_ZIP64` (-18),
  `zip64-unsupported`. This is not unlimited ZIP support or a storage guarantee.
- Expanded totals use uint64_t. Available storage/filesystem limits and errors
  remain real limits. Duplicate-name validation uses 201 bytes per entry (about
  13.2 MB at the ZIP32 count ceiling); payload memory does not scale with size.
- The existing ASCII relative-path policy, 200-character name contract,
  case-insensitive duplicate checks, local/central metadata agreement and encryption
  rejection remain. Symlinks/devices/sockets are explicitly rejected. Signed and
  signature-free data descriptors must match the central directory.
- Sequential central-directory iteration now caches its offset instead of
  rescanning the whole prefix for every `wb_zip_next` call.
- Fixed three-file S1 core schema/approvals/size limits are unchanged.

## VitaShell comparison and provenance

The official VitaShell `archive.c` uses libarchive with read/seek callbacks
(lines 48-139) and extracts through a fixed `TRANSFER_SIZE` read/write loop
(lines 600-665), with progress/cancel processing per transfer. This supports the
streamed-I/O architecture; it does not imply identical feature or ZIP64 support.

Primary source: https://github.com/TheOfficialFloW/VitaShell/blob/master/archive.c
License: https://github.com/TheOfficialFloW/VitaShell/blob/master/LICENSE (GPLv3).
No VitaShell/libarchive/minizip implementation code was copied. Changes extend
Workbench's existing decoder independently; this comparison is not code import.

## Observed regression results

See `evidence/large-zip.json` for literal commands, stdout, stderr and exit statuses.
The same real 320 MiB expanded archive is rejected by untouched v2.08 with -5 and
streamed by v2.09 successfully. Real 40 MiB incompressible DEFLATE and 40 MiB stored
entries pass. Engine heap peak on these fixtures is 66,560 bytes; data callbacks
are at most 16,384 bytes. A 4,097-entry archive passes. Synthetic >4 GiB expanded
metadata totals pass preflight then deliberately fail create; this is not a claim
of actual >4 GiB extraction. Differential tests cover 250 standard zlib streams,
250 trailing-byte rejects and 2,000 bounded malformed streams. Negatives cover
truncation, malformed DEFLATE, CRC, path traversal, duplicate case aliases,
local/central disagreement, encryption, links/devices, ZIP64, bad descriptors,
read and create/write/close failures. Existing S1 host gate passes separately.

Host checks are not Vita installation or runtime acceptance receipts.
