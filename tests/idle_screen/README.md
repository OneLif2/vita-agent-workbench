# Host-only idle-screen regression

Run:

```powershell
python D:\OneDrive\_python_test\PS-Vita-REA\v2.07\tests\idle_screen\run.py
```

The runner compiles the production `wb_idle_screen.h` policy and extracts the
actual idle adapter from `source/vita_ssh_status.c`. Native controller, touch,
display-power and suspend-timer functions are replaced by capture-only SDK
stubs. The policy and adapter are not independently reimplemented by the test.

Coverage includes the 900000 ms boundary, one-shot display-off, local wake/reset,
controller/touch activity, missing input, remote output not being local activity,
clock reversal, disabled/strict mode, failed-call backoff, and separate
auto-suspend/OLED timer behavior.

These tests demonstrate host-side branch behavior only. They do not connect to
a Vita, change a device screen, prove a native lock screen appeared, measure
hardware power consumption, or prove that a real SSH session remains connected.
Actual paired-PTY transport timeout coverage is separate from the idle policy.

The same-input transaction probe accepts an original, modified, or restored
source copy and reports the actual source mechanism at 900000 ms:

```powershell
python D:\OneDrive\_python_test\PS-Vita-REA\v2.07\tests\idle_screen\behavior.py --source SOURCE_COPY --include D:\OneDrive\_python_test\PS-Vita-REA\v2.07\source --transport TRANSPORT_SOURCE --at-ms 900000
```

`behavior.py` extracts the legacy listener's real OLED tick/auto-suspend block
when testing an old source, and the actual idle adapter for a changed source.
It also compiles the supplied production transport deadline checks. Its
`off-request-accepted` output means the SDK stub accepted that call; it is not a
physical lock-screen observation. The full runner additionally checks that only
an already-authenticated, admitted, live owner PTY bypasses the 30-minute idle
deadline, while authentication/KEX, non-PTY, closing, EOF and disconnected
sessions retain their existing timeout behavior.

`tests/remote_start/native.c.in` keeps a deliberately minimal idle adapter stub
so its existing paired recovery/veto/guard checks remain scoped to admission.
It is not the native power-adapter test.
