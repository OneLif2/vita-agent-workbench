# Startup power UX host regression
Run from the project root:

- Candidate only: `python -B v1.67/tests/startup_power_ux/run.py`
- Same inputs against both releases with literal commands/output: `python -B v1.67/tests/startup_power_ux/run.py --baseline v1.66/source --evidence v1.67/evidence/HOST-POWER-UI.json`
- A single archived-source probe: `python -B v1.67/tests/startup_power_ux/run.py --source PATH_TO_SOURCE_DIR --probe-low`

The C compiler builds the source under test's unmodified startup power loop, WBPD1 writer, startup main fragment through its actual wb_ssh_open() call, and inactive_screen() frame call. The fixture substitutes the SDK/controller/clock, display and bind interfaces; the display stub records the exact label and hint that reach the frame, not a screenshot. No battery values are changed on a device; no SSH listener, network or actual updater runs. Run 5DE8ABEBD83AAD5E is the source of the fixed low-power sample. Starting after callback registration tests the demonstrated branch, not a full Vita boot.

Cases cover low on AC as reported, low on battery, failed diagnostic write, invalid power API result, simultaneous suspend/low, stable non-low startup, settled automatic resume, no manual UI during auto-ack (including unavailable manual input/renderer), independent downstream R1 veto/input/focus and pairing checks, fresh manual approval only after release, manual cancel/input/renderer failure, and clock/focus/callback/repeat/flags/supply errors. A failure to write a diagnostic is not authority to proceed.
