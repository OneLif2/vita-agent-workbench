# Signed main handoff transaction coverage

Offline only; no Vita connection, signing key, upload, stage or installation.

`run.py` extracts the exact APPLY_RETURN / APPLY_CORE / PROMOTE / S1_CHECK
switch case from `source/vita_ssh_status.c`. It executes that unedited case
against the real R1 savedata/dispatch and signed-focus code, with the existing
deterministic SDK/storage/signature test model. This is stronger than adjacent
`r1_apply(false); r1_apply(true)` calls, but is not the entire running Vita main
loop, real cryptographic verification, or physical-device acceptance.

The fixture injects coherent two seconds into the actual sync, arm, helper,
fence, WBQ_TEST stat and private R1 read call sites. It checks one durable dispatch
and one launch in each positive case; 143 total cases cover overlay, counters, RTC/monotonic changes, callback,
power generation/latch, input errors/veto, queue/pin/run changes, access checks,
I/O failures and the unchanged attended/physical routes.

The signed operation now has:

1. A strict outer snapshot before the first precheck.
2. Existing bounded snapshots for both full-tree hashes.
3. A bounded intermediate snapshot immediately after precheck, before every
   main queue/stat operation and around real savedata/helper/fence work.
4. A final outer snapshot before launch, including the durable dispatch write.

The full operation is capped at ten seconds, not three independent ten-second
allowances. Ten seconds succeeds in the model; eleven seconds refuses, revokes
the dispatched request when storage permits, and never launches the updater.
Late power/clock changes during dispatch saving also prevent launch. A failed
revocation is reported separately; it never converts failure into launch.

No `foreground(true)`, global baseline reset, new identity, release key, title,
receipt, expiry, nonce or promotion path is introduced. The ordinary baseline
is advanced only by the existing endpoint validator after both snapshots pass.
Each signed r1_apply also captures its strict endpoint before the private R1
savedata read, not after potentially blocking file I/O. The same nonce, owner,
host, receipt and expiry checks still follow that read; the snapshot grants no
authority by itself. Manual tickets keep their original read/validation path.

`transaction/VERIFICATION.txt` records full commands and literal output. Same
`intergate-2s` input:

```text
BASELINE: status=1 launches=0 private_phase=1 intent=0 stage_checks=1
MODIFIED: status=0 launches=1 private_phase=2 intent=1 stage_checks=2
ROLLBACK: status=1 launches=0 private_phase=1 intent=0 stage_checks=1
REAPPLIED: status=0 launches=1 private_phase=2 intent=1 stage_checks=2
```

All four processes exit zero with empty stderr; assertions check the observed
state. Rollback is executed only on a separate copy; its SHA equals the pristine
parent. Parent files remain unchanged and the candidate remains modified.

The root-review correction was executed, not just audited: the initial fix still
failed `teststat-2s`, and an old R1 header still failed `private-read-2s`. Both now
pass with launch1/phase2/intent1 and revert to the failure on rollback. The
header's supplemental four roles are in `header-transaction/`. Pre-review main
roles are preserved in `transaction-before-stat-review/`; a line-ending-only
intermediate record is preserved in `transaction-stat-review-before-eol/`.
Final main line endings match the CRLF parent, and the final patch is minimal.

Current installation/bootstrap restrictions are owned by the project handover.
These test results do not install the fix into the older on-device core.
