# Source publication handover — reference02.06

Development paused at the owner's request after installing and checking the
privately configured02.06 reference build. This repository is a source/document
publication only; no VPK, credentials, personal provisioning or private logs.

Current implementation priorities delivered: typed owner-PTY admission, conservative
app-state tri-state, deduplicated approved-title queries with provenance, and
quarantine of unverified raw AppMgr ABI calls. See docs/VALIDATION.md for exact
reference-vs-export verification boundaries.

Still pending: independent paired background WAKE receiver; safe real close/open;
persistent first-return nonce audit across LoadExec; simultaneous game/query
acceptance; generic first-pair/public build portability; fuller runtime app approval
acceptance. Do not turn a rejected close command into a force-kill, and do not
silently weaken pin/hash/title/path/R1 checks to make setup easier.

The prior configured02.05 source archive was hash-consistent but lacked a required
root C input and host fixture; this export includes unsupported_vita_calls.c and
explicitly documents omitted fixtures/dependencies rather than claiming turnkey
buildability. Third-party licensing exceptions are documented separately.
