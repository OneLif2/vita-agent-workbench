# Owner-authorized remote startup / listener recovery

Host-only tests; no network/device control. The fixture extracts the real startup
from load_config through wb_ssh_open, the real local-input/runtime guard block,
and the real gate_ok admission function. It uses the actual exact-pair comparison
and recovery helper with deterministic SDK/identity/storage stubs. It is not an
entire Vita process, real SSH handshake, GXM, promoter or loader acceptance.

43 cases cover paired foreground/overlay, RTC/AppMgr/callback observations,
registration zero/0x80/0x1080/unknown bits with AC0, unavailable local input,
return-intent/arm/R1-return routes, strict-mode startup override, unavailable
input to observed SELECT, held keys and real release, SELECT to opt-out chord,
failed opt-out persistence closing this listener, network failure and admission.
Unknown local input is never fabricated as a neutral release or as approval.
Actual START/SELECT vetoes still win. Unknown/mismatched/missing identity,
quick opt-out/corrupt preference, import/prepare/watch/network/bind errors and
startup audit-log failure do not produce a listener. The installed receipt audit
logs an exact owned-title/current-version receipt or an error and leaves recovery
SSH available; it never writes or grants an update authorization.

The full startup must retain key enrollment/identity checks outside the extracted
branch, and the build suite tests those separately. Signed-R1 foreground and
content/nonce checks remain unchanged. Recovery mode only changes listener
availability; an independently recorded recovery apply-core is not R1-return.

Transaction role files preserve the original main bytes. Same overlay-battery
input: BASELINE blocked/waits1/enroll-1/binds0; MODIFIED listener/waits0/enroll0/
binds1; ROLLBACK blocked; REAPPLIED listener. All process exits0/stderr empty.
ROLLBACK.sh accepts a target copy and restores sibling BASELINE.c; the helper is a
new dependency, recorded by hash and unused by the original main.
