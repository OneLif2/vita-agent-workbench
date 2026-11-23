# 5090 crash-index tests (offline)

From the project root, run `python -B v1.80/tests/crash_cli/run.py`.
The suite refuses real sockets. Generated PTY transcripts and fixture rows are **not**
evidence that this build is installed or that a particular application crashed.

After WB 01.80 or later is verified on-device, from the release folder:

```cmd
bin\wb.cmd diag crashes
bin\wb.cmd diag crashes --limit 5
bin\wb.cmd --json diag crashes --since 2026-11-22T23:09:00 --until 2026-11-22T23:20:00
```

In an existing interactive Vita SSH shell use `diag crashes` or `diag crashes --limit 5`.
The time window and JSON formatting are 5090-only. The 5090 opens one original-pinned
Workbench PTY, checks the version and run, issues the fixed command, verifies the
exit receipt, then closes that connection. No alternative endpoint is attempted.

Rows contain filename, Vita-reported local modification time (or `unknown`) and
byte count. The newest rows are first. The default is 10, or 32 with a time window.
Window bounds are both inclusive and use the Vita clock, without timezone conversion.
A match is a **time candidate**, not a title or cause. If any rows were truncated or
their timestamp is unknown, absence of visible candidates is `INCONCLUSIVE`, not
`NO_MATCH`. An empty successful index is distinct from a failed read or an older WB.
No dump is opened, downloaded, written, or deleted.
