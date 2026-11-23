# Validation scope

The privately provisioned 02.06 reference build passed 76 host suites, 12 focused
pin/authorization suites, 78 app-query cases and 52 approved-table cases. A fresh
Jetson native build passed three-member CRC, ARM32 SELF, authid
`0x2f00000000000001`, version/payload checks and compressed/uncompressed ELF segment
identity. Reference VPK: 898,205 bytes, SHA-256
`cc0dced42c64a900d9d5859f06147c71ca625f22e74c4ae2b8c3d6032d5eb0a7`.
**That binary is not distributed.**

Physical reference acceptance observed a new02.06 process with the original host
pin, exact installed WBQ2 content receipt, empty queue and one-PTY identity triplet.
The six-unique-title/seven-approval table, WB self positive query, malformed-input
rejection and explicit ABI-probe skips were observed. No new real unknown-error
injection was made on-device: that classification was tested in host SDK fixtures.

Host-copy transaction behavior: false absence -> unknown -> rollback restored the
original output/hash; duplicated title queries2 -> unique1 -> rollback2. Unsafe
probe mocks6 -> zero -> rollback6. Rollback tests were on disposable host copies,
not a firmware downgrade. Private run logs, keys, signed authorization tokens and
machine identifiers are intentionally not published. No physical zero-input or
strict first-return nonce proof is claimed across self-reexec.

The public export changes/omits personal configuration and binary fixtures. It has
not been claimed to pass the full private release pipeline. Any selected public
export test results are recorded separately, without implying generic native or
physical-device acceptance.

## Public-export host check, 2026-11-24

The exported source was separately compiled with host SDK stubs using the two
commands in README: app_running passed 78 checkpoints and app_running_table
passed 52 cases, both exit 0. These tests perform no Vita or network I/O. This is
not a public native-build, generic-pairing or physical-device acceptance result.

The public-export `tests/font_atlas/run.py` check also passed (exit 0), including
compiled OFL license byte identity. The omitted TTF was not regenerated.
