#ifndef WB_WAKE_PROBE_APPROVED_H
#define WB_WAKE_PROBE_APPROVED_H
/* Exact offline-verified finite diagnostic artifact. NOT a receiver or close grant. */
#include <stdint.h>
#define WB_PROBE_TITLE "WBLC00079"
#define WB_PROBE_VERSION "01.02"
#define WB_PROBE_VPK_SHA256 "026389c85760b79921a0b587eefed0daaedf22e108a4b915c2375c26a1534621"
static const struct { const char *path; uint64_t bytes; const char *sha256; } wb_probe_members[4] = {
    {"eboot.bin", UINT64_C(76634), "89771122df75891afebee63173820a330bcddde5dc3785f788be69a383161146"},
    {"eboot2.bin", UINT64_C(75914), "1941c4255ce6caf2d3c3826a0faaf32072fa119a9341567d8627ee5e73800b9e"},
    {"sce_sys/param.sfo", UINT64_C(952), "499dbfb491b18121b49a0b742657dd4d59ca922dc21089682e4d3496bff75be3"},
    {"sce_sys/param2.sfo", UINT64_C(1008), "cb0a2e2eed6ab4894c0038dd2cf82d5858b66e0ca0ef3abe3690f75da974c478"},
};
#endif
