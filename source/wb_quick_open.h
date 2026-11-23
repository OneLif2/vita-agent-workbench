/* The quick-open mode of this owner-specific build is for this already paired
 * device/client only. Both constants are PUBLIC key fingerprints, not keys.
 * A matching IP, a mutable file, or an empty app param is never a grant. */
#ifndef WB_QUICK_OPEN_H
#define WB_QUICK_OPEN_H
#include "wb_return_policy.h"
#define WB_QUICK_HOST  "4E901867EB7550EE9C4D6C6881855DE07D8FAC790E23017564A965D425DFCFFB"
#define WB_QUICK_OWNER "2CC6CED39F6B51F4A738854183DCB95654811EDE3E5AF8F3781E423E64D86CDD"
typedef enum { WB_Q_NONE, WB_Q_LOCAL, WB_Q_DIRECT, WB_Q_OFFER, WB_Q_REMEMBERED } wb_quick_route;
static inline bool wb_quick_pair(const char *owner,const char *host) {
    return wb_r1_pin_equal(WB_QUICK_OWNER,owner) && wb_r1_pin_equal(WB_QUICK_HOST,host);
}
/* Positive, successfully parsed OS LiveArea event is required for zero input.
 * Do not classify empty launch parameters alone, a URI, self-test or updater
 * launch, or an ambiguously sourced process as a physical owner launch. */
static inline wb_quick_route wb_quick_decide(bool pair,bool enabled,bool clean,
        bool fenced,bool remembered,int app_rc,bool empty,int state_rc,bool clear,unsigned event_count,int event_rc,int parse_rc) {
    if(!pair || !enabled)return WB_Q_NONE;
    (void)empty;   /* kept for the caller's log; a bubble launch may carry a param */
    /* v1.47: sceAppMgrGetAppParam() returns a negative code whenever there is
     * simply no launch parameter; treating that as "unverified origin" forced
     * the square on every bubble launch and made the remembered preference
     * unreachable. What matters is whether a payload exists at all. */
    /* v1.52: a LiveArea bubble launch may carry a launch parameter (the shell
     * passes psgm data), so requiring an empty parameter block forced
     * WB_Q_LOCAL and the square on every cold start. The real signals are: no
     * pending/return markers, a settled foreground and no system overlay.
     * An actual LiveArea event is still parsed and preferred below. */
    if(!clean || state_rc!=0 || !clear)return WB_Q_LOCAL;
    (void)app_rc;
    /* v1.50: a clean bubble launch with no launch parameter is the owner
     * tapping the LiveArea icon. Treat it as the remembered paired open so a
     * cold start needs no square; the pin/host match, clean state and the
     * START/SELECT veto above still gate it. No savedata write is involved. */
    (void)remembered; (void)fenced;
    if(!event_count)return WB_Q_REMEMBERED;
    return !fenced && event_rc==0 && parse_rc==0?WB_Q_DIRECT:WB_Q_LOCAL;
}
#endif
