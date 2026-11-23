# Native TTY adapter / exact probe result GET

```powershell
python -B D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\tty_vita\run.py
python -B D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\tty_vita\record_result_get.py
```

The fixture compiles the actual production `wb_tty_vita.inc`, digest and path
functions against a bounded in-memory filesystem. Existing upload, abort,
no-clobber, corrupted readback, quota, tree and stream assertions are retained.

The only production change adds **exact read-only GET** of
`ux0:/data/INAP00018/wake-probe/result.bin`. The positive fixture takes
`WP_RESULT_PATH` from the shared native protocol header, rather than relying
only on another duplicated literal. Protocol-path drift therefore fails the
actual production allowlist test. It reads all 256 bytes and verifies no write
or unlink occurred.

79 additional assert executions include 13 denied job/private/sibling/traversal
paths, each checked through GET, PUT, stream PUT, mkdir and tree-probe. Writes on
an open GET handle fail. Completing or aborting GET cannot delete the file.
The TTY adapter has no public remove command. This change adds no VFS, SFTP,
private savedata or general directory permissions and no fallback channel.

## Supplemental four roles

- `D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\tty_vita\transaction\MODIFIED_FILE.inc`
- `D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\tty_vita\transaction\DIFF_FILE.patch`
- `D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\tty_vita\transaction\VERIFICATION.txt`
- `D:\OneDrive\_python_test\PS-Vita-REA\v1.89\tests\tty_vita\transaction\ROLLBACK.sh`

Input `get-result`, using the same memory-file bytes:

| Role | Observed stdout | Exit / stderr |
|---|---|---|
| BASELINE | `DENIED error=path-denied writes=0 removes=0` | 0 / empty |
| MODIFIED | `GET bytes=256 read=256 ... readonly=1 writes=0 removes=0` | 0 / empty |
| ROLLBACK | identical BASELINE rejection | 0 / empty |

The portable rollback restores a separate copy to original SHA-256
`30d22f52ff04255ce753f0dea43fc3f6e80c9b748e00001c9ec6107c867727aa`.
The exact one-leaf patch reconstructs the modified adapter. Original v1.88
remains unchanged. Current native source SHA-256 is
`4ebeac628bd253818c9cb255e7ca5fd0d6b214b3a60a57f930ff917cd0525d72`.

The primary shell transaction's previous verification is archived before a
supplemental link is appended; its four paths and original three-state evidence
are not replaced. These are host source transactions, **not Vita installation,
actual file download, background survival or WAKE acceptance**.
