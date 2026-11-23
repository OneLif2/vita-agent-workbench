# Native Workbench wake-probe regression

Run on the host:

```powershell
python -B D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\wake_probe\run.py
python -B D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\wake_probe\record.py
```

97 named checkpoints compile the actual `wb_wake_probe_vita.h`, `wb_shell.c`,
`wb_cmd.c`, output and SHA-256 implementation against deterministic SDK stubs.
The only bridge-source substitution redirects the generated package-approval
include to four tiny deterministic file members. Their real SHA-256 hashes are
checked by production logic. **This does not approve or install the real VPK**;
production package metadata must be independently audited.

Coverage includes each paired-PTY prerequisite, raw-exec rejection, command and
descriptor bounds, active R1/queue/seal, actual network admission, every installed
member's digest, second/final rechecks, RNG/clock/RTC/overflow, exact private/public
records, publication collisions, read/write/sync/rename failures, duplicate jobs,
late admission changes, mismatched/invalid/expired diagnostic status, and the
actual unchanged `close wb` rejection after `DIAGNOSTIC_COMPLETE`.

The fixture has no socket or process-exit implementation. Its sole app-launch
stub asserts the fixed title and `0x20000` flags, then records a call. Passing
proves host control-flow checks, **not Vita background scheduling, unattended
return, receiver authentication or remote wake**. Public results always remain
`public-untrusted`, `readiness=not-provided`, `close_wb=disabled`.

## Four transaction roles

- `D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\wake_probe\transaction\MODIFIED_FILE.c`
- `D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\wake_probe\transaction\DIFF_FILE.patch`
- `D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\wake_probe\transaction\VERIFICATION.txt`
- `D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\wake_probe\transaction\ROLLBACK.sh`

The verification role is parseable JSON containing literal command stdout,
stderr and exit status, source hashes, fixture limitations, and corrected tool
errors. With the same input `wake probe job1`:

- BASELINE: `ERR invalid or disallowed Workbench command/options`
- MODIFIED: `OK wake-probe DISPATCHED_UNVERIFIED ... no close authority`
- ROLLBACK: the identical BASELINE output and original hash.

The later `ps` / `app running` feature supplements these same roles with 60
additional native checkpoints and its own literal `ps` three-state outputs.
Earlier role bytes and reports are retained under the transaction's `history`
directory before publishing the latest shell copy.

All three exit 0 with empty stderr in this host shell harness; semantic rejection
is carried in the command output, not misrepresented as a successful probe.
`git -c core.autocrlf=false apply` reconstructs the exact modified bytes. The
portable rollback is executed on a separate changed copy; both original source
and the production candidate remain unchanged. Role files are reopened before
reporting. Each snapshot retains its observed raw line endings; the history
contains the earlier LF candidate, and the latest role follows the current
production source bytes exactly. The recorder does not normalize source bytes.
