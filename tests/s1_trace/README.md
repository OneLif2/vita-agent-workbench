# WBQ2 sealing / native errors: controlled host fault model

Run from the project root:

    python -B v1.34/tests/s1_trace/run.py --source-dir v1.33/source --out v1.34/evidence/s1-seal-baseline.json
    python -B v1.34/tests/s1_trace/run.py --out v1.34/evidence/s1-seal-candidate.json
    python -B v1.34/tests/s1_trace/run.py --calibrate --out v1.34/evidence/s1-calibration-host.json

The fixture compiles the actual old seal function or the new shared production seal helper, plus the original WBQ2 final verification gate. Vita native I/O is replaced with an isolated host-directory adapter. The consumer is a counter, not a promoter. It never connects to a Vita. One real SFO is extracted from the pinned archived 01.33 VPK, paired with inert file content; this is not a staged production update.

Cases cover a valid seal and final handoff; missing, extra and changed members; a legacy WBQ1 receipt, a mismatched private seal and content changed after sealing. Each selected directory, read, receipt-open/write/sync/close and receipt-readback failure is injected separately. Positive short writes must complete; zero-progress writes must stop. Combined write and close failures must preserve the first raw error. Successful closure does not prove durable content: after writing, the candidate also reads and checks the complete receipt. A readback error/corruption must yield no usable pair and no handoff.

The two SYSTEM-mode tests model an I/O implementation rejecting creation of the private receipt/directory when the SYSTEM bits are absent. In this model 0600/0700 fails and 0606/0707 works. These POSITIVE/NEGATIVE HOST observations do **not** assert the real Vita returned EINVAL. To isolate a real failure, rely on the device-generated native phase/op/path/rc for the same authenticated update, or a controlled paired legacy/corrected device probe. Valid negative tests are PASS; a mismatched package intentionally denied does not mean S1 failed.
