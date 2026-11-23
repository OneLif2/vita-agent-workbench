# Known-good Updater test material

The three members of `helper-samples.zip` are the unmodified Updater payloads extracted from the archived core VPKs, not generated fixtures. Both core VPKs contain an inner SCE SELF, followed by the exact binary SFO. No launch, package installation, or device access occurs in the host test. The C code under test reads these buffers using host stub I/O.

| VPK | Embedded SELF (161438 bytes) SHA-256 |
| --- | --- |
| 01.73 | 53bc94ee1418a73339965da45a110562caa34bd63778c7f81f21e63f2e1189a8 |
| 01.74 | 3db1718a22be8c4a2916e41e2dae1d1930fd881c958b7163862f76b6093deb3b |

Both releases embed the same 912-byte SFO: `1dba3e69e2647c12bf6a094c291dc210cdc651b7bbad11c3d6cdef63b3a4fe1b`. The runner verifies every sample digest before compiling, and compares with the corresponding full VPK when available. Three successive handoffs in a fixture are not three real upgrades. Actual app registration, layout/folder membership and optical display must be checked on hardware.
