# Native App spool mode regression

This compiles unmodified production `wb_app_spool_vita.h`, the protected block-SHA
spool and `wb_vita_io.c` against deterministic SDK syscalls. Unlike the older
host `tmpfile()` adapter, it rejects write modes missing SYSTEM RW (`0006`).

`run.py --adapter path/to/pristine/header --probe` compares the same 65,573-byte
input before/after/rollback. Ordinary execution covers 18 lifecycle/fault cases,
short native writes and reads, sync/close/reopen ordering, allocated-memory and
handle accounting, collisions and foreign-directory preservation. Cleanup errors
must remain errors; leftover owned scratch on a simulated remove/rmdir failure is
reported rather than called fully cleaned.

The close-error fixture retires its FD before reporting error. It does not prove
real Vita descriptor state after a failed close. `wb_vita_reader_close()` has a
pre-existing void interface, so native read-close failure propagation is not claimed.
No host fixture is physical Vita installation acceptance.

Primary semantics: [VitaSDK iofilemgr.h](https://github.com/vitasdk/vita-headers/blob/master/include/psp2common/kernel/iofilemgr.h)
defines `SCE_S_IWSYS=000002`, `SCE_S_IRSYS=000004`, and documents that unsafe
homebrew must supply SYSTEM RW. Group bits in `0666` are ignored; its effective
user/system permissions include the same required low bits as `0606`.
