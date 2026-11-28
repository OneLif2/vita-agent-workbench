# Explicit local standing-update enrollment — host regression

```powershell
python -B D:\OneDrive\_python_test\PS-Vita-REA\v2.08\tests\standing_enroll\run.py
```

`--source HEADER_PATH` selects a copy of the production standing header;
`--core CORE_PATH` selects its main source. Actual early/post-enrollment reopen
blocks are compiled against capture-only marker/LoadExec stubs. Seven cases
verify that a 02.08 marker cannot bypass enrollment, refused consent cannot
reexec, successful consent removes the marker before reexec, and other core
versions retain their previous early-reopen behavior. The
runner extracts its real record schema, native SaveData/exact-readback code,
active-record validation, unchanged historical bootstrap and new local-only
enrollment implementation. It does not reimplement the enrollment algorithm.
The actual R1 format, ticket validation, pin normalization and receipt parsing
helpers are used; crypto signature verification is outside this local flow.

The fixture substitutes controller, display, time, native power tick,
installed-receipt and application-private savedata boundaries. Return tickets
are genuine-format synthetic tickets; the fixture seeds the completed-return
state rather than claiming to have performed an install or `r1_boot` on a Vita.

Coverage: 63 cases / 338 assertions, including:

- Absent, invalid and revoked records require fresh neutral then CROSS; an
  already-active record remains unchanged without prompt or write.
- Exact 02.06→02.08 return, completed-ticket identity, different current run,
  host/owner provisioning, no attached SSH session, TTL and installed receipt.
- Missing/failed input, held CROSS, 60-second timeout, START/SELECT cancellation,
  display/focus/power errors, monotonic/RTC reversal and ticket expiry.
- Final rechecks after installed-content reads: changed receipt/host, a slow
  read exceeding the deadline, final missing input or local cancellation.
- Both power-inhibition ticks while waiting; no remote input is synthesized.
- The actual existing bounded focus-settle implementation (not a settle stub):
  zero-bit and benign `0x1080` registration reach the physical prompt, transient
  overlay settles, and real power/supply mismatch, low/suspend, persistent overlay,
  callback/app/RTC errors refuse before showing a prompt or writing savedata.
- Power generation is anchored through the prompt, final installed-content read
  and native save; a changed generation refuses or durably revokes the attempt.
- Native save errors, false success, corrupted/missing readback, audit failure
  before physical save or after save, RAM disable and best-effort revocation.
- A previously revoked/disabled profile can be restored only by the separate
  explicit physical enrollment gesture, without creating an R1 update grant.

No device, network, real button press, real display or native savedata is used.
Passing this host suite is not physical approval, enrollment-on-device proof,
automatic-update enablement proof or permission to bypass R1/focus safeguards.
