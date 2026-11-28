# Security and trust boundary

- Always verify the pinned SSH host key fingerprint on the PC side before authenticating (`tools/wb2.py` / `tools/pinned_check.py`). Never use `AutoAddPolicy` or disable host-key pinning on production devices.
- No private SSH keys, host pins, DPAPI blobs, runtime consent files, or device logs belong in this repository. `source/wb_standing_provision.h` is gitignored.
- Exported configuration slots (`HOST_SHA256`, `OWNER_SHA256`, `SIGNER_SHA256`, `SEC1_PUBLIC_KEY`, `192.0.2.x`) intentionally fail closed until configured locally.
- Workbench protects its own SSH credentials (`ux0:data/INAP00018/host.private`, `mac-public-pin.txt`), `ur0:/tai`, `INAP00018`/`INAP00019` app directories, and Sony system titles (`NPXS*`) from raw overwrite or uninstall.
- Please report suspected security issues privately to the repository owner before publishing credentials or sensitive device logs.
