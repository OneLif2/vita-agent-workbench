# Security and trust boundary

- Pair and verify the host fingerprint through an owner-controlled channel before
  authenticating. Do not use AutoAddPolicy or disable StrictHostKeyChecking.
- No private SSH keys, DPAPI blobs, runtime consent files or signed update tokens
  belong in this repository. The actual provisioning header is ignored.
- Exported configuration slots intentionally do not authorize a device. Do not
  replace unknown values with all-zero keys or remove validation checks.
- Use the paired interactive PTY+shell for device control. Legacy exec-mode tools
  retained as source dependencies are not a supported administration route.
- Approved app metadata is not running-image identity. NOT_FOUND is not proof of
  uninstall; approved-table counts are not a global process/foreground inventory.
- There is no verified background wake service. Never force-close WB based on a
  public diagnostic file; its own SSH cannot reopen it after it exits.
- Please report suspected security issues privately to the repository owner before
  publishing credentials or sensitive device logs in an issue.
