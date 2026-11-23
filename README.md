# Vita Agent Workbench

Experimental, source-only PS Vita agent workbench. Reference development version:
**02.06 / `02.06-live-safequery`**. This is a research snapshot, **not a turnkey
end-user distribution** and not a Linux port. No VPK or game package is published.

## What it does

- Owner-paired, host-pinned SSH PTY terminal, mirrored to the Vita display.
- Bounded file operations and framed file transfer through that terminal.
- WBQ2 content-bound core updates through a separate updater title, with R1
  owner authorization and one-shot deployment records.
- Approved app installation, runtime owner-signed approval rows, and conservative
  `app running TITLEID` / deduplicated `app running all` queries.
- A fixed, approved tic-tac-toe program on a restricted MicroPython runtime.
  This is not arbitrary Python execution, CPython, or a Linux filesystem.

## Verified reference build vs this public export

The privately configured 02.06 reference build was installed and checked on a
physical Vita: original pin, a new run, same-connection `ver -> status -> ver`,
full installed WBQ2 receipt and an empty queue. Its approved table reported six
unique titles with seven approval rows; WB self-query returned started.

Original configured-source validation: **76 host suites + 12 pin/authorization
suites**, including 78 app-query and 52 table cases, plus Jetson ARM32 SELF/CRC
package validation. See [validation scope](docs/VALIDATION.md).

This export omits personal provisioning, private release ledgers, machine-specific
build orchestration and precompiled dependencies. It is **not** the exact configured
build tree: public configuration slots must be filled locally. Do not claim those
reference tests prove a fresh generic installation or this export's native build.

## Important limitations

- `all` means approved titles, not all installed apps, all processes, or foreground.
  Approval versions do not identify the running process image/version.
- Only NOT_FOUND means not-started; other errors remain unknown. Unverified raw
  AppMgr ABI probes are disabled, not treated as proof of a permission boundary.
- **Closing WB also stops its SSH. There is no verified independent WAKE receiver.**
  `close wb` currently refuses with `wake-not-ready`; `--force` and `wb open` are
  unsupported. Update-triggered self-restart is not independent wake capability.
- First-return nonce audit does not survive the current self-reexec log reset;
  intermediate reexec is an explicit inference, not direct returned-proof telemetry.
- Simultaneous game/WB execution and global foreground identity are not established.
- Historical `wbctl.py` / `check_in_place.py` device exec modes are not the supported
  control route. Use paired interactive PTY+shell, never silently trust a new key.

## Source and building

See [BUILDING.md](docs/BUILDING.md), [HANDOVER.md](HANDOVER.md), and
[SECURITY.md](SECURITY.md). The source requires an external VitaSDK, matching
libssh/Mbed TLS builds, a platform object, a locally built fixed-game library and
**your own** pairing/provisioning. Configuration is intentionally fail-closed.

Selected host-only C/SDK-stub tests (no Vita connection):

```sh
python -B tests/app_running/run.py
python -B tests/app_running_table/run.py
```

## License

Original Workbench code: **Apache-2.0**. Third-party exceptions include GPLv3
VitaShell template material and OFL font data; **this is not an Apache-only tree**.
Read [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), [NOTICE](NOTICE) and
[LICENSES](LICENSES) before reusing or distributing combined binaries.

Not affiliated with or endorsed by Sony, VitaShell, VitaSDK, JetBrains or MicroPython.
