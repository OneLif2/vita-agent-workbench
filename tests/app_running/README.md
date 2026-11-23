# Safe AppMgr query candidate — v2.06 (host only)

Production copy:
`D:\OneDrive\_python_test\PS-Vita-REA\v2.06\source\wb_app_running_vita.h`

Run the actual helper/shell/parser SDK fixture suite:

```powershell
python -B D:\OneDrive\_python_test\PS-Vita-REA\v2.06\tests\app_running\run.py
python -B D:\OneDrive\_python_test\PS-Vita-REA\v2.06\tests\app_running\record_transaction.py
```

78 checkpoints preserve the prior snapshot guards and add invalid-PID/unknown
classification, injected exact-title validation and zero calls to unverified raw
status/PID-list/AppInfo probes. The fixture declares the real public AppInfo
wrapper with two arguments; it does not invent a three-argument public API.
The three unsupported probes are explicitly `not-probed reason=abi-unverified`.
SDK-declared ForShell capacity probes and GetIdByName self identity remain.

Shared `wb_running_admission(cmd)` enforces paired owner PTY, connection, command
kind/argc and descriptor flags before native calls. Shared
`wb_running_query_state(rc,pid)` returns started only for rc0/positive PID,
not-started only for NOT_FOUND, otherwise unknown. The separately owned approved
registry table route uses these same helpers. No foreground claim is added.

## Four roles and preserved history

All four paths were reopened after real host compilation, reconstruction and
rollback:

- `D:\OneDrive\_python_test\PS-Vita-REA\v2.06\tests\app_running\transaction\MODIFIED_FILE.h`
- `D:\OneDrive\_python_test\PS-Vita-REA\v2.06\tests\app_running\transaction\DIFF_FILE.patch`
- `D:\OneDrive\_python_test\PS-Vita-REA\v2.06\tests\app_running\transaction\VERIFICATION.txt`
- `D:\OneDrive\_python_test\PS-Vita-REA\v2.06\tests\app_running\transaction\ROLLBACK.sh`

Rollback restores pristine binary bytes from sibling `BASELINE_FILE.h`; keep it
beside the script. It does not need the v2.05 source directory. An initial embedded
CRLF heredoc was found to lose CR bytes in Git Bash, so that test failure and the
corrected sibling-byte restoration are retained under `transaction/HISTORY/`.
The first fixture/header compile warnings and their non-suppression corrections
are retained there too; copied old tests/reports are `HISTORICAL-*` files.

Same-input observed behavior:

| Fixture input | BASELINE v2.05 | MODIFIED candidate | ROLLBACK |
|---|---|---|---|
| positive | started, exit0 | identical | identical to baseline |
| NOT_FOUND | not-started, exit1 | identical | identical |
| arbitrary-5 | unknown, exit1 | identical | identical |
| rc0/pid0 or negative | incorrectly not-started, exit1 | unknown / INVALID_RESULT, exit1 | original behavior |
| first list denied | six legacy unsafe-stub calls, exit1 | explicitly skipped, zero unsafe calls, exit1 | original six-stub behavior |

All three roles used the same native fixture input and empty stderr. The restored
SHA equals the original `014bec03029064b92f1086d00d324200bfc35e6b42f17d957907b47bbc7f9712`.
The candidate source remains modified after this disposable rollback test.

Legacy signature fixtures exist only to compare the immutable old header; they
are not claims that those raw firmware ABIs were valid. These are HOST results,
not installation, live game/foreground acceptance or permission changes. No Vita,
Jetson or release build is invoked by these scripts.
