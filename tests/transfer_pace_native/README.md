# Native transfer pace / status regression

Compiles the actual transfer functions extracted from source/vita_ssh_status.c.
Deterministic SDK/time/channel doubles cover 30 ms bounded bursts, partial ACK
writes, zero progress, completion without dispatching the next command, shell and
service failures, display error, idle routing, critical local-status preservation,
PUT/GET progress and throttled presentation. Source-order assertions preserve
outer START/SELECT/power/guard/updater processing; due restart is not delayed.

Run: `python -B tests/transfer_pace_native/run.py` from the v2.11 root.
No network, real device, throughput measurement or live power assertion.
