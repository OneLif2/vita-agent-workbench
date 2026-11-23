#define _POSIX_C_SOURCE 200809L
#include <psp2/appmgr.h>
#include <psp2/ctrl.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/power.h>
#include <psp2/rtc.h>
#include <psp2/sysmodule.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth_modes.h"
#include "display.h"
#include "focus_guard.h"
#include "fresh_choice.h"
#include "phase_clock.h"
#include "prep_gate.h"
#include "startup.h"
#include "startup_power.h"
#include "wb_quick_open.h"

#include "wb_cmd.h"
#include "wb_crash_index.h"
#include "wb_photo_gate.h"
#include "wb_sftp_vita.h"
#include "wb_vita_photo.h"
#include "wb_err.h"
#include "wb_ext_path_policy.h"
#include "wb_head.h"
#include "wb_install.h"
#include "wb_path.h"
#include "wb_payload.h"
#include "wb_queued.h"
#include "wbq_io.h"
#include "wb_sfo.h"
#include "wb_sha256.h"
#include "wb_checked_hash.h"
#include "wb_timeline.h"
#include "wb_ssh.h"
#include "wb_panel_keys.h"
#include "wb_font_command.h"
#include "wb_str.h"
#include "wb_ver.h"
#include "wb_vita_install.h"
#include "wb_vita_io.h"
#include "wb_updater.h"
#include "wb_handoff.h"
#include "wb_vita_payload.h"

enum { LOG_LINES = 400, PUT_CHUNK = 32 * 1024 };

static struct {
    uint32_t strikes;
    uint64_t last;
    bool own_net_module, net, ctl;
    int log;
    unsigned logs;
    unsigned app_event, sys_event;
    uint64_t rtc_last;
    int power_cb;
    bool power_registered;
    volatile unsigned power_event;
    volatile uint32_t power_calls;
    volatile bool power_latched;
    volatile int power_notify_count;
    uint8_t run[8];
    char run_hex[17];
    char pin[65];              /* host key digest, shown on screen */
    char user_pin[65];         /* owner key digest from mac-public-pin.txt */
    char ip[16], mask[16];
    char peer[4][16];
    int peer_count;
    uint64_t restart_at;
    bool updater_accepted;
    uint64_t guard_grace;
    uint32_t guard_strikes;
    bool resilient;
    bool remote_start; /* established existing identity, never first-use enrollment */
    bool saw_bad_focus;
    uint64_t absorb_last;
    uint64_t guard_last;
    uint64_t last_install_ms;
    char payload_ver[32];
    char ui_line2[64];
    PhaseClock last_phase, slow_phase;
} a = { .log = -1, .power_cb = -1, .payload_ver = "none", .ui_line2 = "WAITING FOR OWNER" };

static wb_ssh g_ssh;
static wb_vita_install g_vin;
static wb_out *g_say_out;
static _Alignas(64) uint8_t workspace[128 * 1024];

static uint64_t now_ms(void) { return sceKernelGetProcessTimeWide() / 1000u; }

static void phase_begin(const char *label) {
    a.last_phase = (PhaseClock){ .name = label, .started = sceKernelGetProcessTimeWide() };
}
static void phase_end(int rc) {
    a.last_phase.finished = sceKernelGetProcessTimeWide();
    a.last_phase.rc = rc;
    if (!a.slow_phase.name || phase_elapsed(a.last_phase, a.last_phase.finished) >
        phase_elapsed(a.slow_phase, a.last_phase.finished))
        a.slow_phase = a.last_phase;
}
static int button(unsigned b) {
    SceCtrlData p = {0};
    return sceCtrlPeekBufferPositive(0, &p, 1) > 0 && (p.buttons & b);
}

static void hex(char *out, const uint8_t *in, size_t n) {
    static const char digit[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) { out[2 * i] = digit[in[i] >> 4]; out[2 * i + 1] = digit[in[i] & 15]; }
    out[n * 2] = 0;
}

/* A full diagnostic log must never disable a signed operation: the grant
 * writes its audit line BEFORE the durable spend, so refusing to write would
 * fail closed forever (observed on run 25B6A107F66C78E5). Rotate instead:
 * reopen the same path truncated, reset the budget, and leave a marker so a
 * reader can tell a rotation from a missing event. The durable spend stays in
 * savedata; this file is evidence, not authority. */
static bool log_rotate(void) {
    if (a.log >= 0) (void)sceIoClose(a.log);
    a.log = -1;
    a.log = sceIoOpen(WB_LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    a.logs = 0;
    if (a.log < 0) return false;
    char head[112];
    const int n = snprintf(head, sizeof head, "run=%s elapsed_ms=%" PRIu64 " LOG ROTATED after %d\n",
                           a.run_hex, now_ms(), (int)LOG_LINES);
    if (n <= 0 || (size_t)n >= sizeof head ||
        sceIoWrite(a.log, head, (SceSize)n) != n || sceIoSyncByFd(a.log, 0) < 0) return false;
    a.logs = 1;
    return true;
}
static bool log_event(const char *event) {
    if (a.log < 0) return false;
    if (a.logs >= LOG_LINES && !log_rotate()) return false;
    char line[176];
    const int n = snprintf(line, sizeof line, "run=%s elapsed_ms=%" PRIu64 " %s\n",
                           a.run_hex, now_ms(), event);
    if (n <= 0 || (size_t)n >= sizeof line ||
        sceIoWrite(a.log, line, (SceSize)n) != n || sceIoSyncByFd(a.log, 0) < 0)
        return false;
    a.logs++;
    return true;
}

static int timeline_event(const char *stage,const char *ver,const char *run) {
    int rc=wb_timeline_note(stage,ver,run);
    if(rc!=WB_OK) {
        char msg[100];snprintf(msg,sizeof msg,"TIMELINE NOT SAVED stage=%s rc=%d",stage,rc);
        (void)log_event(msg);
    }
    return rc;
}

static void ui_refresh(const char *line1, const char *line2) {
    (void)line1;
    if (line2) wb_strcpy(a.ui_line2, sizeof a.ui_line2, line2);
}

/* ---- focus / power guards (unchanged policy from 01.09) ---- */

typedef struct {
    int cb, app_rc, rtc_rc;
    uint32_t power;
    bool power_latched;
    SceAppMgrAppState state;
    SceRtcTick tick;
} FocusEvidence;

static FocusEvidence read_focus(void) {
    FocusEvidence e = {0};
    e.cb = sceKernelCheckCallback();
    e.power = a.power_event;
    e.power_latched = a.power_latched;
    e.app_rc = _sceAppMgrGetAppState(&e.state, sizeof e.state, 0x03600011u);
    e.rtc_rc = sceRtcGetCurrentTick(&e.tick);
    return e;
}

static FocusResult classify(const FocusEvidence *e, bool capture) {
    return focus_result(e->cb, e->power_latched ? 1u : e->power, e->app_rc,
                        e->state.isSystemUiOverlaid, e->rtc_rc, e->tick.tick, capture,
                        a.app_event == e->state.appEventNum && a.sys_event == e->state.systemEventNum,
                        a.rtc_last);
}

static void capture_focus(const FocusEvidence *e) {
    a.app_event = e->state.appEventNum;
    a.sys_event = e->state.systemEventNum;
    a.rtc_last = e->tick.tick;
}

/* Lock screen / suspend tolerance: absorb the current focus and clock state
 * instead of treating it as a fault, so the listener keeps serving while the
 * console is locked. Used when mode.txt does not say "strict". */
static void absorb_focus(void) {
    const FocusEvidence e = read_focus();
    const FocusResult r = classify(&e, false);
    a.rtc_last = e.tick.tick;
    a.app_event = e.state.appEventNum;
    a.sys_event = e.state.systemEventNum;
    a.power_event = 0;
    a.power_latched = false;
    if (r != FG_OK) {
        if (!a.saw_bad_focus) { a.saw_bad_focus = true; (void)log_event("RESILIENT FOCUS NOT OK"); }
    } else if (a.saw_bad_focus) {
        a.saw_bad_focus = false;
        (void)log_event("RESILIENT FOCUS BACK");
    }
}

static bool foreground(bool capture) {
    const FocusEvidence e = read_focus();
    const FocusResult r = classify(&e, capture);
    if (r != FG_OK) {
        startup_mark("FOCUS REASON", (int32_t)r);
        return false;
    }
    if (capture) capture_focus(&e);
    else a.rtc_last = e.tick.tick;
    return true;
}

static const char *wait_initial_focus(void) {
    const uint64_t start = now_ms();
    uint64_t clear_since = 0;
    bool clear = false;
    uint32_t prev_app = 0, prev_sys = 0;
    for (;;) {
        const uint64_t t = now_ms();
        const FocusEvidence e = read_focus();
        const FocusResult r = classify(&e, true);
        if (r != FG_OK && r != FG_OVERLAY) return "FOCUS CHECK FAILED";
        if (t < start || t - start >= 3000) return r == FG_OK ? "FOCUS NOT STABLE" : "FOCUS CHECK FAILED";
        if (button(SCE_CTRL_START)) return "USER EXIT";
        if (r == FG_OVERLAY) {
            clear = false;
            if (!display_frame("WAITING FOR SYSTEM UI", NULL, 0)) return "DISPLAY ERROR";
        } else {
            if (!clear || e.state.appEventNum != prev_app || e.state.systemEventNum != prev_sys) {
                clear = true;
                clear_since = t;
                prev_app = e.state.appEventNum;
                prev_sys = e.state.systemEventNum;
            }
            if (t >= clear_since && t - clear_since >= 120) { capture_focus(&e); return NULL; }
        }
        sceKernelDelayThread(20000);
    }
}

static int power_note(int id, int count, int flags, void *arg) {
    (void)id; (void)arg;
    if (a.power_calls < UINT32_MAX) a.power_calls++;
    a.power_notify_count = count;
    a.power_latched = true;
    a.power_event |= (unsigned)flags;
    return 0;
}

static char pw_diag_source[17]; /* populated only from the already accepted R1 proof */
static void pw_diag_stop(bool unattended,bool paired,PowerStep step,uint64_t dt,
                         const FocusEvidence *e,FocusResult focus,PowerSeen seen,int ac,int suspend,int low) {
    const char *const reasons[]={"wait","ready","ack","clock","focus","callback","supply",
                                "suspend","low","repeat","late","flags","ac-mismatch","ui","cancel"};
    const char *path=paired?WB_ROOT "/power-last-quick.txt":
                     unattended?WB_ROOT "/power-last-r1.txt":WB_ROOT "/power-last-manual.txt";
    const char *branch=paired?"quick":unattended?"r1":"manual";
    char line[448];
    int n=snprintf(line,sizeof line,
        "WBPD1 build=%s run=%.16s source=%.16s branch=%s reason=%s code=%d"
        " dt_ms=%" PRIu64 " cb=%d inv=%" PRIu32 " notify=%d flags=%08" PRIX32
        " focus=%d app_rc=%d overlay=%u rtc_rc=%d ac=%d suspend=%d low=%d end=1\n",
        WB_BUILD_TAG,a.run_hex,(!paired&&unattended&&pw_diag_source[0])?pw_diag_source:"-",branch,
        (unsigned)step<sizeof reasons/sizeof reasons[0]?reasons[(unsigned)step]:"unknown",(int)step,
        dt,e->cb,seen.invocations,seen.count,seen.bits,(int)focus,(int)e->app_rc,(unsigned)e->state.isSystemUiOverlaid,
        (int)e->rtc_rc,ac,suspend,low);
    if(n>0&&(size_t)n<sizeof line)(void)wq_save(path,line,(size_t)n); /* bounded write/sync/close; NOT authority */
}

/* NULL only after PW_READY; otherwise the caller stops before opening SSH.
 * Report the deciding sample, not a second power read or a previous run's log. */
static const char *initial_power_drain(uint64_t start,bool unattended,bool paired_open,bool return_ok,bool resume_ack) {
    static const char generic_stop[]="POWER EVENT - REOPEN APP";
    PowerStart gate = {0};
    bool released = false;
    for (;;) {
        const FocusEvidence e = read_focus();
        const PowerSeen seen = { a.power_calls, a.power_event, a.power_notify_count };
        const FocusResult focus = focus_result(e.cb, 0, e.app_rc, e.state.isSystemUiOverlaid,
                                               e.rtc_rc, e.tick.tick, false,
                                               a.app_event == e.state.appEventNum &&
                                               a.sys_event == e.state.systemEventNum, a.rtc_last);
        const int ac = scePowerIsPowerOnline(), suspend = scePowerIsSuspendRequired(), low = scePowerIsLowBattery();
        const uint64_t t = now_ms();
        const uint64_t dt = t >= start ? t - start : UINT64_MAX;
        const bool was_waiting = gate.waiting_ack;
        PowerStep step = power_start_step(&gate, dt, focus == FG_OK, e.cb, seen, ac, suspend, low);
        a.rtc_last = e.tick.tick;
        /* power_start_step already required a single first-sample zero-bit
         * registration on battery, 320 ms of stable foreground + supply, no
         * low/suspend. Only this benign callback can avoid a redundant press.
         * AFTER_RESUME and real changes are never auto-acknowledged. */
        /* R1: only the already-consumed proof from this boot can use the
         * same settled registration exception. The separate expiry, veto,
         * foreground, pin and bind gates still run. Never clear a resume. */
        const bool proved_return = return_ok && unattended && !paired_open;
        if ((paired_open || proved_return) && step==PW_LOCAL_ACK && seen.bits==0) {
            (void)log_event(proved_return?"R1 POWER ZERO REGISTRATION SETTLED":"QUICK POWER REGISTRATION SETTLED");
            step=PW_READY;
        }
        if (step == PW_LOCAL_ACK) {
            /* v1.37: this boot is a *return* (verified R1 proof or a consumed
             * arm intent written before the updater/app launch). The Vita
             * reports AFTER_RESUME together with AC online even when the
             * previous app was merely closed for the update; the platform does
             * not distinguish "system closed us" from "real suspend". Inside a
             * return, accept exactly that shape once, with the supply still
             * online and no low-battery/suspend-required veto, and record it.
             * Anything else (0x80 alone, supply change, repeat, late) still
             * stops and asks the owner. */
            /* The platform reports the same "system closed us" situation with
             * different shapes: 0x1080 on AC and 0x0080 on battery (01.44
             * failed on the battery shape). Admit AFTER_RESUME plus a supply
             * sample that agrees with the flag, and nothing else. */
            const uint32_t kKnown = (uint32_t)(WB_AC_ONLINE | WB_BATTERY_ONLINE | WB_AFTER_RESUME);
            const bool bits_ok = (seen.bits & (uint32_t)WB_AFTER_RESUME) != 0 &&
                                 (seen.bits & ~kKnown) == 0 &&
                                 (((seen.bits & (uint32_t)WB_AC_ONLINE) != 0) == (ac == 1));
            if (resume_ack && bits_ok && !suspend && !low) {
                (void)log_event("RETURN AUTO ACK RESUME");
                (void)log_event(return_ok ? "RETURN ACK BRANCH R1" : "RETURN ACK BRANCH ARM");
                step = PW_READY;
            } else if (unattended) {
                pw_diag_stop(unattended,paired_open,step,dt,&e,focus,seen,ac,suspend,low);
                (void)log_event(paired_open?"QUICK NEEDS OWNER: POWER ACK":"R1 NEEDS OWNER: POWER ACK");
                return generic_stop;
            } else {
                if (!was_waiting) (void)log_event(!seen.bits ? "POWER HF2: ZERO-STATUS; WAIT LOCAL ACK" : "POWER HF2: WAIT LOCAL ACK");
                SceCtrlData pad = {0};
                if (!display_frame_prompt("CHECK POWER STATE", NULL, 0, "RELEASE THEN CROSS; START CANCELS") ||
                    sceCtrlPeekBufferPositive(0, &pad, 1) <= 0) step = PW_UI;
                else {
                    const int action = fresh_choice(&released, pad.buttons, SCE_CTRL_CROSS, SCE_CTRL_START);
                    if (action < 0) step = PW_CANCEL;
                    if (action == 1) { (void)log_event("POWER HF2: LOCAL ACK"); step = PW_READY; }
                }
            }
        }
        if (step == PW_READY) {
            /* Callbacks are dispatched on this thread; the next foreground
             * check pumps any queued newer event. The separate arm gate stays. */
            a.power_event = 0;
            a.power_latched = false;
            return NULL;
        }
        if (step != PW_WAIT && step != PW_LOCAL_ACK) {
            const char *const why[] = {"wait","ready","ack","clock","focus","callback","supply",
                                       "suspend","low","repeat","late","flags","ac-mismatch","ui","cancel"};
            char line[128];
            (void)snprintf(line, sizeof line, "POWER HF2 %s dt=%" PRIu64 " cb=%d n=%" PRIu32 "/%d bits=%08" PRIx32,
                           why[step], dt, e.cb, seen.invocations, seen.count, seen.bits);
            (void)log_event(line);
            (void)snprintf(line, sizeof line, "POWER HF2 focus=%d ac=%d suspend=%d low=%d",
                           (int)focus, ac, suspend, low);
            (void)log_event(line);
            pw_diag_stop(unattended,paired_open,step,dt,&e,focus,seen,ac,suspend,low);
            /* Unexpected SDK values (including errors) still veto SSH but
             * are not evidence that the battery is actually low. */
            return step==PW_LOW && low==1 ? "LOW BATTERY - CHARGE THEN REOPEN APP" : generic_stop;
        }
        sceKernelDelayThread(10000);
    }
}

/* ---- network ---- */

static bool private_link(void) {
    SceNetCtlInfo ip = {0}, mask = {0};
    int s = 0;
    return sceNetCtlInetGetState(&s) == 0 && s == SCE_NETCTL_STATE_CONNECTED &&
        sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &ip) == 0 &&
        sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_NETMASK, &mask) == 0 &&
        !strcmp(ip.ip_address, a.ip) && !strcmp(mask.netmask, a.mask);
}

static bool net_setup(void) {
    if (sceSysmoduleIsLoaded(SCE_SYSMODULE_NET) != SCE_SYSMODULE_LOADED) {
        if (sceSysmoduleLoadModule(SCE_SYSMODULE_NET) < 0) return false;
        a.own_net_module = true;
    }
    SceNetInitParam p = { .memory = workspace, .size = sizeof workspace };
    if (sceNetInit(&p) < 0) return false;
    a.net = true;
    if (sceNetCtlInit() < 0) return false;
    a.ctl = true;
    return private_link();
}


/* ---- configuration files ---- */

static void load_config(void) {
    wb_strcpy(a.ip, sizeof a.ip, WB_DEFAULT_IP);
    wb_strcpy(a.mask, sizeof a.mask, WB_DEFAULT_MASK);
    a.peer_count = 0;
    wb_strcpy(a.peer[0], sizeof a.peer[0], WB_DEFAULT_PEER);
    a.peer_count = 1;

    char buf[128];
    size_t n = 0;
    if (wb_vita_read_small(WB_ADDR_PATH, buf, sizeof buf - 1, &n) == WB_OK && n > 8) {
        buf[n] = 0;
        char ip[16] = {0}, mask[16] = {0};
        if (2 == sscanf(buf, "%15s %15s", ip, mask) && wb_path_ipv4(ip) && wb_path_ipv4(mask)) {
            wb_strcpy(a.ip, sizeof a.ip, ip);
            wb_strcpy(a.mask, sizeof a.mask, mask);
        }
    }
}

static void load_peers(void) {
    char buf[128];
    size_t n = 0;
    if (wb_vita_read_small(WB_PEER_PATH, buf, sizeof buf - 1, &n) != WB_OK || n < 7) return;
    buf[n] = 0;
    int count = 0;
    char *line = buf;
    while (*line && count < 4) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = 0;
        const size_t len = strlen(line);
        if (len >= 7 && len < 16 && wb_path_ipv4(line)) wb_strcpy(a.peer[count++], sizeof a.peer[0], line);
        if (!eol) break;
        line = eol + 1;
    }
    if (count) a.peer_count = count;
}

static bool import_public_pin(void) {
    /* Do not trust a prefix: owner identity is taken only from a complete
     * bounded record read to EOF on this one descriptor. Nothing is
     * published if a later read, file close or syntax check fails. */
    char raw[80];
    size_t n = 0;
    a.user_pin[0] = 0;
    const int fd = sceIoOpen(WB_PIN_PATH, SCE_O_RDONLY, 0);
    if (fd < 0) return false;
    bool eof = false;
    while (n < sizeof raw) {
        const size_t remaining = sizeof raw - n;
        const int got = sceIoRead(fd, raw + n, (SceSize)remaining);
        if (got == 0) { eof = true; break; }
        if (got < 0 || (size_t)got > remaining) break;
        n += (size_t)got;
    }
    const int closed = sceIoClose(fd);
    if (!eof || closed < 0) return false; /* >= 80 bytes, or I/O error */
    while (n && (raw[n - 1] == '\n' || raw[n - 1] == '\r' || raw[n - 1] == ' ')) --n;
    if (n != 64) return false;
    bool nonzero = false;
    for (size_t i = 0; i < 64; i++) {
        const char c = raw[i];
        const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
        if (c != '0') nonzero = true;
    }
    if (!nonzero) return false;
    for (size_t i = 0; i < 64; i++) a.user_pin[i] = (char)(raw[i] >= 'a' && raw[i] <= 'f' ? raw[i] - 32 : raw[i]);
    a.user_pin[64] = 0;
    return true;
}

/* ---- command dispatch ---- */

static void backend_say(void *ctx, const char *line) {
    (void)ctx;
    if (g_say_out) (void)wb_out_puts(g_say_out, line);
    char status[64];
    const char *p = line;
    while (*p == ' ') p++;
    if (!strncmp(p, "install: ", 9)) p += 9;
    wb_strcpy(status, sizeof status, p);
    char *nl = strchr(status, '\n');
    if (nl) *nl = 0;
    if (strlen(status) > 40) status[40] = 0;
    /* Raw command output belongs to its channel, not the local status band.
     * Local controls and fixed install/upload results set ui_line2 separately. */
    char event[96];
    snprintf(event, sizeof event, "SAY %s", status);
    (void)log_event(event);
}

static bool core_foreground(void *ctx, bool capture) { (void)ctx; return foreground(capture); }
static bool core_link(void *ctx) { (void)ctx; return private_link(); }

static void core_note(void *ctx, const char *event) {
    (void)ctx;
    if (!event) return;
    if (!strcmp(event,"WB SHELL OPEN")) wb_vita_forget_remove_plan();
    (void)log_event(event);
    /* v1.54: peer decisions are the first thing to check when a client is
     * refused, and run.log is recreated on every start. Keep them. */
    if (!strcmp(event, "PEER LIMIT") || !strcmp(event, "PEER REJECTED"))
        (void)timeline_event("peer", event, a.run_hex);
}

static int cmd_ver(wb_out *out) {
    return wb_out_printf(out, "wb version=%s build=%s abi=%u proto=%s run=%s payload=%s uptime_ms=%" PRIu64 "\n",
                         WB_VERSION, WB_BUILD_TAG, (unsigned)WB_PAYLOAD_ABI, WB_PROTO, a.run_hex,
                         wb_vita_payload_version(), now_ms());
}

static int cmd_status(wb_out *out, const wb_ssh *s) {
    char last[32] = "none";
    if (a.last_install_ms) snprintf(last, sizeof last, "%" PRIu64 "ms-ago", now_ms() - a.last_install_ms);
    return wb_out_printf(out,
        "run=%s uptime_ms=%" PRIu64 " ssh=%s cmds=%u payload=%s core=%s last_install=%s peer=%s:%u\n",
        a.run_hex, now_ms(), wb_ssh_connected(s) ? "connected" : "listening", s->commands,
        wb_vita_payload_version(), WB_VERSION, last, a.ip, (unsigned)WB_PORT);
}

#define INSTALLED_SFO "ux0:app/" WB_TITLE_ID "/sce_sys/param.sfo"

/* Milestone B: exactly one approved companion title, by id, nothing generic. */
#define WB_TESTAPP_TITLE_ID "INAP00020"
#define WB_TESTAPP_SFO      "ux0:app/" WB_TESTAPP_TITLE_ID "/sce_sys/param.sfo"
#define WB_APP_STAGE        WB_ROOT "/stage/app"
#define WB_JOB_PATH         WB_ROOT "/job.txt"

static int queue_sfo_version(const char *path, char version[WBQ_VERLEN + 1]) {
    wb_reader rd;
    wb_vfile f;
    int rc = wb_vita_reader_open(path, &rd, &f);
    if (rc != WB_OK) return rc;
    if (!rd.size || rd.size > 65536u) rc = WB_E_FORMAT;
    else {
        uint8_t *data = malloc((size_t)rd.size);
        if (!data) rc = WB_E_NOMEM;
        else {
            rc = rd.read_at(rd.ctx, 0, data, (size_t)rd.size);
            if (rc == WB_OK) rc = wbq_identity(data, (size_t)rd.size, version);
            free(data);
        }
    }
    wb_vita_reader_close(&f);
    return rc;
}

/* The private seal is outside both Workbench command-writable roots. This
 * protects against a staged tree/marker change, not a hostile privileged filesystem. */
static bool new_seal;
static int queued_core_check(void) {
    char receipt[WBQ_CAP],installed[6];
    int rc=wq_sealed_receipt(WB_PENDING_PATH,WBQ_SEAL,receipt);
    if (!rc) rc=queue_sfo_version(INSTALLED_SFO,installed);
    if (!rc) rc=wq_check_tree(WB_STAGE_DIR,NULL,receipt,strcmp(installed,WB_VERSION)>0?installed:WB_VERSION);
    return rc;
}
#include "wb_return_vita.h"
#include "wb_review_model.h"
#include "wb_r1_notice.h"
#include "wb_standing_vita.h"
#include "wb_status_vita.h"
static wb_r1_notice r1_notice;

static int seal_core_stage(void *ctx,const char *receipt,const char *running) {
    (void)ctx;
    int rc=wq_seal(WB_STAGE_DIR,WBQ_STORE,WBQ_SEAL,WB_PENDING_PATH,receipt,running);
    if(rc){
        char why[384]={0};
        (void)wq_diag_format(why,sizeof why,&wq_last);
        if(g_say_out)(void)wb_out_printf(g_say_out,"WBQ2 %s\n",why);
        (void)log_event(why);
    }else new_seal=true;
#if WBQ_LEGACY_PROBE
    for(unsigned i=0;i<2;i++){
        const wq_trial *t=&wq_trials[i];
        if(t->op){
            char line[160];
            int n=snprintf(line,sizeof line,"WBQ2-PROBE mode=%04o op=%s path=%.60s native=0x%08X cleanup=0x%08X",
                           t->mode,t->op,t->path,(unsigned)t->raw,(unsigned)t->cleanup);
            if(n>0 && (size_t)n<sizeof line){
                if(g_say_out)(void)wb_out_printf(g_say_out,"%s\n",line);
                (void)log_event(line);
            }
        }
    }
#endif
    return rc;
}
static int reset_queued_stage(void *ctx) {
    wb_notice_cancel(&r1_notice);
    if(r1_revoke()!=WB_OK)return WB_E_IO;
    r1_bound=false;
    if (wb_vita_exists(WB_PENDING_PATH) && sceIoRemove(WB_PENDING_PATH)<0) return WB_E_IO;
    if (wb_vita_exists(WBQ_SEAL) && sceIoRemove(WBQ_SEAL)<0) return WB_E_IO;
    memset(&r1_notice,0,sizeof r1_notice);
    return wb_vita_install_backend((wb_vita_install *)ctx)->stage_reset(ctx);
}

/* Dry-run preview: parses the package and says what an install would touch,
 * without writing anything. Mirrors the checks install performs. */
/* Single-use auto-arm marker written by the approved TestApp just before it
 * relaunches workbench. Bounded to two minutes so a leftover file cannot keep
 * weakening the pin gate later. */
#include "wb_autoarm_vita.h"
#include "wb_quick_vita.h"
#include "wb_remote_start_vita.h"

/* Shared verb bodies are also compiled by the native side-effect fixture. */
#include "wb_app_gate_impl.h"
#include "wb_reopen_vita.h"

/* v1.40: file-based return intent. The arm-intent job id may only use
 * [A-Za-z0-9_-], so "return-01.39" (a dot) was rejected by wb_arm_id and the
 * 01.38/01.39 cores never minted anything. This file has no such constraint:
 * apply-core writes it, the next boot consumes it once, and it is only valid
 * for 300 s and for the exact build it names. */
static bool return_intent_take(void) {
    char buf[128];
    size_t n = 0;
    if (wb_vita_read_small(WB_ROOT "/return-intent.txt", buf, sizeof buf - 1, &n) != WB_OK) {
        (void)log_event("RETURN INTENT MISSING");
        return false;
    }
    buf[n] = 0;
    const char *b = strstr(buf, "build=");
    const char *i = strstr(buf, "issued=");
    char build[8] = {0};
    uint64_t issued = 0;
    if (b) {
        for (unsigned k = 0; k < 5 && b[6 + k] && b[6 + k] != '\n' && b[6 + k] != '\r'; k++)
            build[k] = b[6 + k];
    }
    if (i) {
        for (const char *q = i + 7; *q >= '0' && *q <= '9'; q++) issued = issued * 10u + (uint64_t)(*q - '0');
    }
    (void)sceIoRemove(WB_ROOT "/return-intent.txt");
    if (!build[0] || !issued) { (void)log_event("RETURN INTENT UNREADABLE"); return false; }
    SceRtcTick now;
    if (sceRtcGetCurrentTick(&now) < 0 || !now.tick) { (void)log_event("RETURN INTENT NO CLOCK"); return false; }
    if (now.tick < issued || (now.tick - issued) >= UINT64_C(1800000000)) {
        (void)log_event("RETURN INTENT STALE");
        (void)timeline_event("intent-stale", build, a.run_hex);
        return false;
    }
    if (strcmp(build, WB_VERSION)) { (void)log_event("RETURN INTENT BUILD MISMATCH"); (void)timeline_event("intent-mismatch", build, a.run_hex); return false; }
    (void)log_event("RETURN INTENT OK");
    (void)timeline_event("intent-ok", build, a.run_hex);
    return true;
}

static int do_plan(const char *path, wb_out *out) {
    if (!wb_install_source_ok(path))
        return wb_out_printf(out, "ERR path-denied: plan reads %s or %s\n", WB_INCOMING, WB_ROOT);
    wb_vfile file;
    wb_reader rd;
    if (wb_vita_reader_open(path, &rd, &file) != WB_OK)
        return wb_out_puts(out, "ERR open-failed\n");

    char digest_hex[65];
    const int hash_rc = wb_checked_hash(&rd, digest_hex, malloc);
    if (hash_rc != WB_OK) { wb_vita_reader_close(&file); return hash_rc; }

    wb_zip zip;
    int rc = wb_zip_open(&zip, &rd);
    if (rc != WB_OK) {
        wb_vita_reader_close(&file);
        return wb_out_printf(out, "ERR not-a-vpk %s\n", wb_err_name(rc));
    }

    wb_zip_entry sfo_entry;
    char tid[16] = {0}, ver[16] = {0};
    if (wb_zip_find(&zip, "sce_sys/param.sfo", &sfo_entry) == WB_OK &&
        sfo_entry.usize > 0 && sfo_entry.usize <= 65536) {
        uint8_t *sfo_buf = (uint8_t *)malloc((size_t)sfo_entry.usize);
        size_t sfo_len = 0;
        if (sfo_buf && wb_zip_read(&zip, &sfo_entry, sfo_buf, (size_t)sfo_entry.usize, &sfo_len) == WB_OK) {
            wb_sfo sfo;
            if (wb_sfo_parse(&sfo, sfo_buf, sfo_len) == WB_OK) {
                (void)wb_sfo_get(&sfo, "TITLE_ID", tid, sizeof tid);
                (void)wb_sfo_get(&sfo, "APP_VER", ver, sizeof ver);
            }
        }
        free(sfo_buf);
    }

    char installed[WBQ_VERLEN + 1] = {0};
    const bool have_installed = queue_sfo_version(INSTALLED_SFO, installed) == WB_OK;
    const bool title_ok = strcmp(tid, WB_TITLE_ID) == 0;
    const bool newer = ver[0] && strcmp(ver, WB_VERSION) > 0;
    const bool same = ver[0] && strcmp(ver, WB_VERSION) == 0;
    const bool has_payload = wb_zip_find(&zip, "workbench_payload.suprx", &sfo_entry) == WB_OK;

    wb_out_printf(out, "plan file bytes=%" PRIu64 " sha256=%s\n", rd.size, digest_hex);
    wb_out_printf(out, "plan title=%s app_ver=%s running=%s installed=%s title_ok=%d\n",
                  tid[0] ? tid : "?", ver[0] ? ver : "?", WB_VERSION,
                  have_installed ? installed : "?", title_ok ? 1 : 0);
    wb_out_printf(out, "plan verdict=%s core=%s payload=%s queue=%s force=%s\n",
                  !title_ok ? "title-mismatch" : newer ? "newer" : same ? "same" : "older",
                  newer ? "replace" : "keep",
                  has_payload ? (newer || same ? "replace" : "keep") : "keep",
                  newer ? "yes" : "no",
                  newer ? "no" : "yes");

    unsigned cursor = 0;
    wb_zip_entry entry;
    for (;;) {
        rc = wb_zip_next(&zip, &cursor, &entry);
        if (rc == 1) break;
        if (rc != WB_OK) break;
        wb_out_printf(out, "plan member %s size=%" PRIu64 " crc=%08" PRIX32 "\n",
                      entry.name, entry.usize, entry.crc);
    }
    wb_vita_reader_close(&file);
    return WB_OK;
}

static int do_inspect(const char *path, wb_out *out) {
    if (!wb_install_source_ok(path))
        return wb_out_printf(out, "ERR path-denied: inspect reads %s or %s\n", WB_INCOMING, WB_ROOT);
    wb_vfile file;
    wb_reader rd;
    int rc = wb_vita_reader_open(path, &rd, &file);
    if (rc != WB_OK) return wb_out_puts(out, "ERR open-failed\n");

    char digest_hex[65];
    const int hash_rc = wb_checked_hash(&rd, digest_hex, malloc);
    if (hash_rc != WB_OK) { wb_vita_reader_close(&file); return hash_rc; }
    wb_out_printf(out, "file bytes=%" PRIu64 " sha256=%s\n", rd.size, digest_hex);

    wb_zip zip;
    rc = wb_zip_open(&zip, &rd);
    if (rc != WB_OK) {
        wb_vita_reader_close(&file);
        return wb_out_printf(out, "ERR not-a-vpk %s\n", wb_err_name(rc));
    }
    unsigned cursor = 0;
    wb_zip_entry entry;
    for (;;) {
        rc = wb_zip_next(&zip, &cursor, &entry);
        if (rc == 1) break;
        if (rc != WB_OK) {
            wb_vita_reader_close(&file);
            return wb_out_printf(out, "ERR zip %s\n", wb_err_name(rc));
        }
        wb_out_printf(out, "member %s size=%" PRIu64 " crc=%08" PRIX32 "\n",
                      entry.name, entry.usize, entry.crc);
    }

    wb_zip_entry sfo_entry;
    if (wb_zip_find(&zip, "sce_sys/param.sfo", &sfo_entry) == WB_OK &&
        sfo_entry.usize > 0 && sfo_entry.usize <= 65536) {
        uint8_t *sfo_buf = (uint8_t *)malloc((size_t)sfo_entry.usize);
        size_t sfo_len = 0;
        if (sfo_buf && wb_zip_read(&zip, &sfo_entry, sfo_buf, (size_t)sfo_entry.usize, &sfo_len) == WB_OK) {
            wb_sfo sfo;
            if (wb_sfo_parse(&sfo, sfo_buf, sfo_len) == WB_OK) {
                char tid[16] = {0}, ver[16] = {0}, title[48] = {0};
                (void)wb_sfo_get(&sfo, "TITLE_ID", tid, sizeof tid);
                (void)wb_sfo_get(&sfo, "APP_VER", ver, sizeof ver);
                (void)wb_sfo_get(&sfo, "TITLE", title, sizeof title);
                wb_out_printf(out, "title_id=%s app_ver=%s title=%s\n", tid, ver, title);
            }
        }
        free(sfo_buf);
    }
    wb_vita_reader_close(&file);
    return WB_OK;
}

static int do_install(const char *path, const wb_cmd *c, wb_out *out, wb_inst_result *res) {
    if (!wb_install_source_ok(path)) {
        (void)wb_out_printf(out, "ERR path-denied: install source must be " WB_INCOMING "\n");
        return WB_E_PATH;
    }
    wb_inst_request req;
    memset(&req, 0, sizeof req);
    req.vpk = path;
    req.sha256 = c->sha256[0] ? c->sha256 : NULL;
    char installed[WBQ_VERLEN + 1];
    if (queue_sfo_version(INSTALLED_SFO, installed) != WB_OK) {
        (void)wb_out_puts(out, "ERR cannot verify installed identity; not staging\n");
        return WB_E_STATE;
    }
    req.running_ver = strcmp(installed, WB_VERSION) > 0 ? installed : WB_VERSION;
    /* An explicit immediate forced reinstall is still possible. A deferred
     * operation may never inherit force across an exit or a newer install. */
    req.force = c->force && c->promote_now;
    req.reload = !c->no_reload;
    req.keep_stage = c->keep_stage;
    req.skip_period = c->no_period;
    req.promote = c->promote_now;
    req.allow_other_title = c->any_title;

    wb_inst_backend backend = *wb_vita_install_backend(&g_vin);
    backend.say = backend_say;
    backend.stage_reset = reset_queued_stage;
    backend.seal_stage = seal_core_stage;
    new_seal=false;

    g_say_out = out;
    const int rc = wb_install_run(&req, &backend, &g_vin, res);
    g_say_out = NULL;
    /* A promote attempt can raise system UI; let it settle before the
     * foreground guard is allowed to end the app. */
    a.guard_grace = now_ms() + 8000;

    if (rc == WB_OK) {
        wb_strcpy(a.payload_ver, sizeof a.payload_ver, res->payload_ver[0] ? res->payload_ver : wb_vita_payload_version());
        a.last_install_ms = now_ms();
        if (!c->promote_now) {
            if(timeline_event("queued", res->version, a.run_hex)!=WB_OK)
                (void)wb_out_puts(out,"WARN timeline-not-saved; package already queued\n");
        } else if (wb_vita_exists(WB_PENDING_PATH)) {
            sceIoRemove(WB_PENDING_PATH);
        }
        (void)wb_out_printf(out, "OK install version=%s title=%s files=%u bytes=%" PRIu64
                                 " payload=%s core=%s session=kept\n",
                            res->version, res->titleid, res->files, res->bytes, a.payload_ver,
                            c->promote_now ? "promoted" : "queued");
        char line[128];
        snprintf(line, sizeof line, "INSTALLED %s payload=%s", res->version, a.payload_ver);
        (void)log_event(line);
        (void)wb_vita_write_file(WB_INSTALL_LOG, line, strlen(line), true);
        (void)wb_vita_write_file(WB_INSTALL_LOG, "\n", 1, true);
        ui_refresh(NULL, "INSTALL OK");
    } else {
        if (new_seal) {(void)sceIoRemove(WB_PENDING_PATH); (void)sceIoRemove(WBQ_SEAL); new_seal=false;}
        startup_mark("PROMOTE DETAIL", g_vin.promote_detail);
        (void)wb_out_printf(out, "ERR install-failed %s: %s (promote detail %d)\n",
                            wb_err_name(rc), res->detail, g_vin.promote_detail);
        char line[128];
        snprintf(line, sizeof line, "INSTALL FAILED %s %s", wb_err_name(rc), res->detail);
        (void)log_event(line);
        ui_refresh(NULL, "INSTALL FAILED");
    }
    return rc;
}

static int write_upload_chunk(int fd, const uint8_t *data, size_t size) {
    for (size_t off = 0; off < size;) {
        const int n = sceIoWrite(fd, data + off, (SceSize)(size - off));
        if (n <= 0 || (size_t)n > size - off) return WB_E_IO;
        off += (size_t)n;
    }
    return WB_OK;
}

/* The staging file is written first and then re-read by publish_upload, so it
 * must be opened read/write. Opening it WRONLY made publish fail with io-error
 * after a perfectly good upload. */
static int open_staging(const char *path, int *last_rc) {
    static const int flags[] = {
        SCE_O_RDWR | SCE_O_CREAT | SCE_O_TRUNC,
        SCE_O_RDWR | SCE_O_CREAT,
    };
    static const int modes[] = { 0666, 0777, 0600 };
    int rc = -1;
    for (unsigned f = 0; f < sizeof flags / sizeof flags[0]; f++) {
        for (unsigned m = 0; m < sizeof modes / sizeof modes[0]; m++) {
            const int fd = sceIoOpen(path, flags[f], modes[m]);
            if (fd >= 0) return fd;
            rc = fd;
        }
    }
    if (last_rc) *last_rc = rc;
    return -1;
}

/* ux0: rejects some flag/mode combinations with 0x80010016 (EINVAL) even
 * though the same call succeeds elsewhere in this process. Try the known-good
 * combinations and report the last error instead of guessing. */
static int open_writable(const char *path, int *last_rc) {
    static const int flags[] = {
        SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC,
        SCE_O_WRONLY | SCE_O_CREAT,
        SCE_O_RDWR | SCE_O_CREAT | SCE_O_TRUNC,
    };
    static const int modes[] = { 0666, 0777, 0600 };
    int rc = -1;
    for (unsigned f = 0; f < sizeof flags / sizeof flags[0]; f++) {
        for (unsigned m = 0; m < sizeof modes / sizeof modes[0]; m++) {
            const int fd = sceIoOpen(path, flags[f], modes[m]);
            if (fd >= 0) return fd;
            rc = fd;
        }
    }
    if (last_rc) *last_rc = rc;
    return -1;
}

static int publish_upload(int stage, const char *path, uint64_t size,
                          uint8_t *buf, size_t cap, wb_out *out) {
    if (sceIoSyncByFd(stage, 0) < 0 || sceIoLseek(stage, 0, SCE_SEEK_SET) != 0)
        return WB_E_IO;

    /* Same O_EXCL caveat as the staging file: existence is checked above, so
     * plain create+truncate is the portable form. */
    int dest_rc = 0;
    const int dest = open_writable(path, &dest_rc);
    if (dest < 0) {
        (void)wb_out_printf(out, "ERR destination-exists-or-unavailable rc=0x%08X\n", (unsigned)dest_rc);
        return WB_E_IO;
    }

    int rc = WB_OK;
    while (size) {
        const size_t take = size < cap ? (size_t)size : cap;
        const int n = sceIoRead(stage, buf, (SceSize)take);
        if (n <= 0 || (size_t)n > take) { rc = WB_E_IO; break; }
        rc = write_upload_chunk(dest, buf, (size_t)n);
        if (rc != WB_OK) break;
        size -= (uint64_t)n;
    }
    if (rc == WB_OK && sceIoSyncByFd(dest, 0) < 0) rc = WB_E_IO;
    if (sceIoClose(dest) < 0) rc = WB_E_IO;
    if (rc != WB_OK && sceIoRemove(path) < 0)
        (void)wb_out_puts(out, "ERR upload-cleanup-failed\n");
    return rc;
}

/* Real storage query, never creates a file; failure is not zero free space. */
static int wb_ux0_budget(uint64_t needed, wb_out *out, bool show) {
    uint64_t total=0, avail=0;
    int api=sceAppMgrGetDevInfo("ux0:", &total, &avail);
    if (api < 0 || !total || avail > total) {
        (void)wb_out_printf(out,"ERR space-unavailable api=0x%08X\n",(unsigned)api);
        return WB_E_IO;
    }
    if (avail < needed) {
        (void)wb_out_printf(out,"ERR no-space volume=ux0: required=%" PRIu64 " available=%" PRIu64 " total=%" PRIu64 "\n",needed,avail,total);
        return WB_E_LIMIT;
    }
    if (show) (void)wb_out_printf(out,"df volume=ux0: total=%" PRIu64 " available=%" PRIu64 " required=%" PRIu64 "\n",total,avail,needed);
    return WB_OK;
}
static int do_put(const wb_cmd *c, wb_out *out, wb_upload *up) {
    const char *requested = c->argv[0];
    uint64_t want = 0;
    if (!wb_parse_u64(c->argv[1], &want) || want == 0 || want > WB_UPLOAD_MAX) {
        (void)wb_out_printf(out, "ERR bad-size\n");
        return WB_E_ARG;
    }
    char path[sizeof WB_INCOMING + 101];
    const char *name = wb_path_under(requested, WB_INCOMING)
        ? requested + sizeof WB_INCOMING : NULL;
    if (!wb_path_name_ok(name) || wb_path_join(path, sizeof path, WB_INCOMING, name) < 0) {
        (void)wb_out_printf(out, "ERR path-denied: put only writes " WB_INCOMING "\n");
        return WB_E_PATH;
    }
    /* Temporary and final files may coexist until verified publication. */
    const int budget=wb_ux0_budget(2*want + 65536u, out, false);
    if (budget != WB_OK) return budget;
    if (!up || !up->read) { (void)wb_out_printf(out, "ERR upload-unavailable\n"); return WB_E_STATE; }

    if (wb_vita_mkdir_p(WB_INCOMING) != WB_OK ||
        wb_vita_mkdir_p(WB_ROOT) != WB_OK) return WB_E_IO;
    if (wb_vita_exists(path)) {
        (void)wb_out_puts(out, "ERR destination-exists\n");
        return WB_E_IO;
    }
    char stage[sizeof WB_ROOT + 64];
    static unsigned upload_serial;
    const int stage_len = snprintf(stage, sizeof stage, WB_ROOT "/put-%s-%u.tmp",
                                   a.run_hex, ++upload_serial);
    if (stage_len < 0 || (size_t)stage_len >= sizeof stage) return WB_E_LIMIT;
    /* O_EXCL is not honoured for ux0 writes on this firmware: opening with it
     * fails before anything is written. The serial in the name already makes
     * collisions impossible, so plain create+truncate is enough. */
    int open_rc = 0;
    const int fd = open_staging(stage, &open_rc);
    if (fd < 0) { (void)wb_out_printf(out, "ERR staging-open-failed rc=0x%08X\n", (unsigned)open_rc); return WB_E_IO; }

    wb_sha256 sha;
    wb_sha256_init(&sha);
    uint8_t buf[PUT_CHUNK];
    uint64_t got = 0;
    int rc = WB_OK;
    while (got < want) {
        const size_t room = (want - got) < (uint64_t)sizeof buf ? (size_t)(want - got) : sizeof buf;
        const int n = up->read(up->ctx, buf, room);
        if (n <= 0) { rc = WB_E_PARTIAL; break; }
        if ((size_t)n > room) { rc = WB_E_IO; break; }
        rc = write_upload_chunk(fd, buf, (size_t)n);
        if (rc != WB_OK) break;
        wb_sha256_update(&sha, buf, (size_t)n);
        got += (uint64_t)n;
    }

    uint8_t digest[32];
    char hexdigest[65];
    wb_sha256_final(&sha, digest);
    wb_sha_hex(digest, sizeof digest, hexdigest);
    if (rc == WB_OK && c->sha256[0] && wb_icmp(hexdigest, c->sha256) != 0)
        rc = WB_E_SHA;
    if (rc == WB_OK) rc = publish_upload(fd, path, want, buf, sizeof buf, out);

    if (sceIoClose(fd) < 0)
        (void)wb_out_puts(out, "WARN staging-close-failed\n");
    if (sceIoRemove(stage) < 0)
        (void)wb_out_puts(out, "WARN staging-cleanup-failed\n");
    if (rc != WB_OK) {
        (void)wb_out_printf(out, "ERR upload-failed %s got=%" PRIu64 "/%" PRIu64 "\n",
                            wb_err_name(rc), got, want);
        ui_refresh(NULL, "UPLOAD FAILED");
        return rc;
    }
    (void)wb_out_printf(out, "OK put path=%s bytes=%" PRIu64 " sha256=%s\n", path, got, hexdigest);
    ui_refresh(NULL, "UPLOAD OK");

    if (c->install_after) {
        wb_inst_result res;
        wb_cmd install_cmd;
        memset(&install_cmd, 0, sizeof install_cmd);
        install_cmd.force = c->force;
        install_cmd.keep_stage = c->keep_stage;
        memcpy(install_cmd.sha256, c->sha256, sizeof install_cmd.sha256);
        const int irc = do_install(path, &install_cmd, out, &res);
        if (irc != WB_OK) return irc;
    }
    return WB_OK;
}

static int do_get(const char *path, wb_out *out) {
    if (!wb_path_under(path, WB_ROOT) || !wb_icmp(path, WB_PIN_PATH)) {
        (void)wb_out_printf(out, "ERR path-denied: get only reads " WB_ROOT "\n");
        return WB_E_PATH;
    }
    const int fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) { (void)wb_out_printf(out, "ERR not-found\n"); return WB_E_IO; }
    char buf[4096];
    int rc = WB_OK;
    for (;;) {
        const int n = sceIoRead(fd, buf, sizeof buf);
        if (n < 0) { rc = WB_E_IO; break; }
        if (n == 0) break;
        if (out->write(out->ctx, buf, (size_t)n) != WB_OK) { rc = WB_E_IO; break; }
    }
    sceIoClose(fd);
    return rc;
}

#ifdef WB_TTY_FILE
#include "wb_tty_file.h"
#include "wb_tty_vita.inc"
#endif

static int do_reload(wb_out *out) {
    char ver[32] = {0};
    startup_mark("PAYLOAD LOAD ENTER", 0);
    const int rc = wb_vita_payload_boot(ver, sizeof ver);
    startup_mark("PAYLOAD LOAD RC", rc);
    if (rc != WB_OK) {
        wb_payload_diag d;
        wb_vita_payload_diag(&d);
        startup_mark("PAYLOAD MOD RC", d.load_rc);
        startup_mark("PAYLOAD MOD STATUS", d.load_status);
        startup_mark("PAYLOAD BOOT MAGIC", (int32_t)d.boot_magic);
        startup_mark("PAYLOAD TABLE", d.table);
        startup_mark("PAYLOAD SEEN ARGS", (int32_t)d.seen_args);
        startup_mark("PAYLOAD SEEN MAGIC", (int32_t)d.seen_magic);
        startup_mark("PAYLOAD SEEN ABI", (int32_t)d.seen_abi);
        startup_mark("PAYLOAD RESULT", (int32_t)d.payload_result);
    }
    if (rc != WB_OK) {
        (void)wb_out_printf(out, "ERR reload-failed %s\n", wb_err_name(rc));
        return rc;
    }
    wb_strcpy(a.payload_ver, sizeof a.payload_ver, ver);
    (void)wb_out_printf(out, "OK reload payload=%s session=kept\n", ver);
    return WB_OK;
}

static int do_shot(wb_out *out) {
    const char *path = WB_ROOT "/shot.bmp";
    if (!display_capture(path)) return wb_out_puts(out, "ERR capture-failed\n");
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (sceIoGetstat(path, &st) < 0) return wb_out_puts(out, "ERR stat-failed\n");
    return wb_out_printf(out, "OK shot path=%s bytes=%" PRIu64 "\n", path, (uint64_t)st.st_size);
}

/* Deploy a payload module that was uploaded separately: copy to the candidate
 * slot, then swap it live. Same path install uses for the packaged payload. */
static int do_deploy(const char *path, wb_out *out,bool checked_terminal) {
    if (!wb_install_source_ok(path)) return wb_out_puts(out, "ERR path-denied\n");
    int rc = wb_vita_copy_file(path, WB_PAYLOAD_NEW);
    if (rc != WB_OK) {
        if(checked_terminal)(void)sceIoRemove(WB_PAYLOAD_NEW);
        (void)wb_out_printf(out,"ERR deploy-copy %s\n", wb_err_name(rc));
        return rc;
    }
    if(checked_terminal){
        /* Only the reviewed bundled p2.1 SELF, never an arbitrary uploaded module.
         * Verify the exact protected candidate copy that swap() is about to use. */
        wb_vfile f;wb_reader rd;char actual[65]={0};
        rc=wb_vita_reader_open(WB_PAYLOAD_NEW,&rd,&f);
        if(rc==WB_OK){
            if(rd.size!=20162)rc=WB_E_SHA;
            else rc=wb_checked_hash(&rd,actual,malloc);
            wb_vita_reader_close(&f);
        }
        if(rc!=WB_OK||strcmp(actual,"0e3a633929b7069a5a194c86bd92eb770515d1766101f597139af61b0a45a66b")){
            (void)sceIoRemove(WB_PAYLOAD_NEW);
            (void)wb_out_puts(out,"ERR payload-not-approved; active payload unchanged\n");
            return rc==WB_OK?WB_E_SHA:rc;
        }
    }
    char ver[32] = {0};
    rc = wb_vita_payload_swap(WB_PAYLOAD_NEW, ver, sizeof ver);
    if (rc != WB_OK) return wb_out_printf(out, "ERR deploy-swap %s\n", wb_err_name(rc));
    wb_strcpy(a.payload_ver, sizeof a.payload_ver, ver);
    return wb_out_printf(out, "OK deploy payload=%s session=kept\n", ver);
}

static int do_rollback(wb_out *out) {
    char ver[32] = {0};
    const int rc = wb_vita_payload_reload_previous(ver, sizeof ver);
    if (rc != WB_OK) {
        (void)wb_out_printf(out, "ERR rollback-failed %s\n", wb_err_name(rc));
        return rc;
    }
    wb_strcpy(a.payload_ver, sizeof a.payload_ver, ver);
    (void)wb_out_printf(out, "OK rollback payload=%s session=kept\n", ver);
    return WB_OK;
}

/* The paired interactive command chooses typed metrics, never a filename.
 * Check EOF after the fixed-size record and sync before acknowledging a save. */
static wb_font_state font_state;
static const char *const font_slot[2]={WB_ROOT "/font-a.cfg",WB_ROOT "/font-b.cfg"};
static bool font_read(unsigned slot,uint8_t dst[WB_FONT_REC]){
    if(slot>=2)return false;
    int fd=sceIoOpen(font_slot[slot],SCE_O_RDONLY,0);if(fd<0)return false;
    unsigned n=0;uint8_t extra;
    while(n<WB_FONT_REC){
        int got=sceIoRead(fd,dst+n,WB_FONT_REC-n);
        if(got<=0||got>WB_FONT_REC-(int)n)break;
        n+=(unsigned)got;
    }
    bool ok=n==WB_FONT_REC && sceIoRead(fd,&extra,1)==0;
    if(sceIoClose(fd)<0)ok=false;
    return ok;
}
static bool font_write(unsigned slot,const uint8_t src[WB_FONT_REC]){
    if(slot>=2)return false;
    int fd=sceIoOpen(font_slot[slot],SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC,0600);if(fd<0)return false;
    unsigned n=0;
    while(n<WB_FONT_REC){
        int wrote=sceIoWrite(fd,src+n,WB_FONT_REC-n);
        if(wrote<=0||wrote>WB_FONT_REC-(int)n)break;
        n+=(unsigned)wrote;
    }
    bool ok=n==WB_FONT_REC && sceIoSyncByFd(fd,0)>=0;
    if(sceIoClose(fd)<0)ok=false;
    return ok;
}
static const wb_font_storage font_storage={font_read,font_write};
#include "wb_wake_probe_vita.h"
#include "wb_app_running_vita.h"
static int wb_running_sweep(const wb_cmd *cmd,wb_out *out,int *status);
static int core_exec(void *ctx, const wb_cmd *cmd, wb_out *out, wb_upload *up, int *status) {
    (void)ctx;
    *status = 0;
    switch (cmd->kind) {
        case WB_CMD_TERM_WB_STATUS: return wb_status_snapshot(cmd,out,status);
        case WB_CMD_TERM_R1_SIGNED: return wb_standing_issue(cmd,out,status);
        case WB_CMD_TERM_R1_AUTO_STATUS: return wb_standing_status(cmd,out,status);
        case WB_CMD_TERM_CLOSE_WB:
            *status=1;
            if(!g_ssh.authenticated || !g_ssh.mode.accepted || g_ssh.mode.mode!=MODE_B_KEY ||
               !g_ssh.session || !g_ssh.channel || !g_ssh.shell || !g_ssh.shell_pty || g_ssh.sftp_ro)
                return wb_out_puts(out,"ERR close-wb no-pty\n");
            if(cmd->argc!=0)return wb_out_puts(out,"ERR close-wb usage: close wb\n");
            /* No enrolled device-authenticated wake observer or local close
             * grant is available. Never consume/update R1 or exit here. */
            return wb_out_puts(out,"ERR close-wb wake-not-ready\n");
        case WB_CMD_TERM_R1_REVIEW:
            return wb_review_describe(g_ssh.authenticated && g_ssh.mode.accepted && g_ssh.mode.mode==MODE_B_KEY &&
                                      g_ssh.session && g_ssh.channel && g_ssh.shell && g_ssh.shell_pty && !g_ssh.sftp_ro,
                                      cmd->argc,a.run_hex,r1_queue,out,status);
        case WB_CMD_TERM_CRASH_INDEX:
            return wb_crash_index(cmd,g_ssh.authenticated && g_ssh.mode.accepted && g_ssh.mode.mode==MODE_B_KEY &&
                                  g_ssh.session && g_ssh.channel && g_ssh.shell && g_ssh.shell_pty && !g_ssh.sftp_ro,out,status);
        case WB_CMD_TERM_R1_NOTICE: {
            const bool pty=g_ssh.authenticated && g_ssh.mode.accepted && g_ssh.mode.mode==MODE_B_KEY &&
                           g_ssh.session && g_ssh.channel && g_ssh.shell && g_ssh.shell_pty && !g_ssh.sftp_ro;
            int rc=wb_notice_request(&r1_notice,pty,pty && !r1_source_live && !r1_bound &&
                  !r1_notice.receipt[0] && foreground(false),cmd->argc,cmd->argv[0],a.run_hex,
                  now_ms(),a.power_calls,r1_queue,out,status);
            if(!*status)ui_refresh(NULL,"UPDATE RECEIVED / LOCAL APPROVAL");
            return rc;
        }
        case WB_CMD_TERM_USER_STATUS:
        case WB_CMD_TERM_USER_PLAN:
        case WB_CMD_TERM_USER_REMOVE:{
            /* A shell request alone is not a PTY. Use the negotiated live channel
             * state, never argv, an echo setting, or client-supplied flags. */
            if (!g_ssh.authenticated || !g_ssh.mode.accepted || g_ssh.mode.mode!=MODE_B_KEY ||
                !g_ssh.session || !g_ssh.channel || !g_ssh.shell || !g_ssh.shell_pty || g_ssh.sftp_ro) {
                *status=1;return wb_out_puts(out,"ERR paired interactive PTY required\n");
            }
            const int action=cmd->kind==WB_CMD_TERM_USER_STATUS?0:(cmd->kind==WB_CMD_TERM_USER_PLAN?1:2);
            if(cmd->argc!=(action==2?2:1)){*status=1;return wb_out_puts(out,"ERR app-uninstall operands\n");}
            return wb_vita_managed_app_command(cmd->argv[0],action,action==2?cmd->argv[1]:NULL,
                                               a.run_hex,out,status);
        }
        case WB_CMD_TERM_SSH_VITA_STATUS:
        case WB_CMD_TERM_SSH_VITA_UNINSTALL:
            if(cmd->argc!=1){*status=1;return wb_out_puts(out,"ERR app-target: VSSH00001 only\n");}
            return wb_vita_ssh_vita_command(cmd->argv[0],cmd->kind==WB_CMD_TERM_SSH_VITA_UNINSTALL,out,status);
        case WB_CMD_TERM_FONT:
            return wb_font_command(cmd,out,status,&font_state,&font_storage);
        case WB_CMD_PHOTO_EXPORT: {
            int cleanup=0;
            const int rc=wb_photo_export_command(cmd->argv[0],cmd->argv[1],out,status,
                &wb_sftp_vita_ops,wb_vita_photo_export,malloc,&cleanup);
            if (cleanup<0) (void)log_event("PHOTO MODULE CLEANUP FAILED");
            return rc;
        }
        case WB_CMD_VER:
            return cmd_ver(out);
        case WB_CMD_DF: {
            uint64_t needed=0;
            if (cmd->argc && !wb_parse_u64(cmd->argv[0],&needed)) {
                *status=1; return wb_out_puts(out,"ERR invalid-required-bytes\n");
            }
            int rc=wb_ux0_budget(needed,out,true); *status=rc==WB_OK ? 0 : 1; return rc;
        }
        case WB_CMD_STATUS:
            return cmd_status(out, &g_ssh);
        case WB_CMD_HELP:
            return wb_out_puts(out, wb_cmd_help_text());
        case WB_CMD_INSTALL: {
            wb_inst_result res;
            const int rc = do_install(cmd->argv[0], cmd, out, &res);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_PUT: {
            const int rc = do_put(cmd, out, up);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_GET: {
            const int rc = do_get(cmd->argv[0], out);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_RELOAD: {
            const int rc = do_reload(out);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_ROLLBACK: {
            const int rc = do_rollback(out);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_SHOT: {
            const int rc = do_shot(out);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_TERM_DEPLOY:
        case WB_CMD_DEPLOY: {
            const int rc = do_deploy(cmd->argv[0], out,cmd->kind==WB_CMD_TERM_DEPLOY);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_HASH_SELFTEST:
            if (wb_s2_selftest() != WB_OK) { *status = 1; return wb_out_puts(out, "ERR hash-selftest\n"); }
            return wb_out_puts(out, "OK hash-selftest normal=known empty=known oom=nomem partial=io-error failure_digest=none\n");
        case WB_CMD_PLAN: {
            const int rc = do_plan(cmd->argv[0], out);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_TIMELINE: {
            int rc;
            if(cmd->argc==1 && !strcmp(cmd->argv[0],"selftest")) {
                const unsigned s4=wb_arm_selftest(), c2=wb_timeline_selftest();
                rc=s4==8 && c2==4?WB_OK:WB_E_STATE;
                (void)wb_out_printf(out,"%s memory-only S4=%u/8 C2=%u/4\n",rc==WB_OK?"OK":"ERR",s4,c2);
            } else rc=wb_timeline_dump(out,40);
            if(rc!=WB_OK) *status=1;
            return rc;
        }
        case WB_CMD_TERM_APP_LIST: {
            for(size_t k=0;k<WB_REG_ROWS;k++){
                const wb_reg_entry *r=&wb_reg_entries[k];
                if(wb_out_printf(out,"approved title=%s app_ver=%s sha256=%s cases=%s source=compiled\n",
                        r->title,r->version,r->sha256,r->cases[0]?r->cases:"-")<0)return WB_E_IO;
            }
            for(unsigned k=0;k<wb_app_local_count;k++){
                const wb_app_row *r=&wb_app_local_rows[k];
                if(wb_out_printf(out,"approved title=%s app_ver=%s sha256=%s cases=- source=owner-signed\n",
                        r->title,r->ver,r->sha)<0)return WB_E_IO;
            }
            return WB_OK;
        }
        case WB_CMD_TERM_APP_APPROVE: {
            /* One exact artifact, authorized by the enrolled release key. The
             * package is read from disk and hashed in place; the operator
             * supplies only the signature. Installation-only by construction. */
            if(!wb_standing_owner_pty()){*status=1;return wb_out_puts(out,"ERR app-approve no-pty\n");}
            if(cmd->argc!=3){*status=1;return wb_out_puts(out,"ERR app-approve usage\n");}
            wb_vfile file={0};wb_reader rd={0};wb_zip zip={0};
            int rc=wb_vita_reader_open(cmd->argv[0],&rd,&file);
            if(rc!=WB_OK){*status=1;return wb_out_printf(out,"ERR app-approve open rc=%s\n",wb_err_name(rc));}
            wb_sha256 sh;wb_sha256_init(&sh);
            uint8_t chunk[4096];uint64_t off=0;bool hashed=true;
            while(off<rd.size){
                size_t take=rd.size-off>sizeof chunk?sizeof chunk:(size_t)(rd.size-off);
                if(rd.read_at(rd.ctx,off,chunk,take)!=WB_OK){hashed=false;break;}
                wb_sha256_update(&sh,chunk,take);off+=take;
            }
            char shahex[65]={0},title[16]={0},ver[16]={0};
            if(hashed){uint8_t digest[32];wb_sha256_final(&sh,digest);wb_sha_hex(digest,32,shahex);}
            if(hashed)rc=wb_zip_open(&zip,&rd);
            if(rc==WB_OK)rc=wb_app_parse_sfo(&zip,title,ver);
            const uint64_t bytes=rd.size;
            wb_vita_reader_close(&file);
            if(!hashed||rc!=WB_OK){*status=1;return wb_out_puts(out,"ERR app-approve package\n");}
            if(!wb_app_local_approve(title,ver,(unsigned long long)bytes,shahex,cmd->argv[1],cmd->argv[2])){
                *status=1;
                return wb_out_puts(out,"ERR app-approve signature-or-storage\n");
            }
            return wb_out_printf(out,"OK app-approve title=%s app_ver=%s sha256=%s bytes=%llu scope=install-only source=owner-signed\n",
                                 title,ver,shahex,(unsigned long long)bytes);
        }
        case WB_CMD_TERM_APP_PLAN: {
            if(cmd->argc<1 || cmd->argc>2){*status=1;return wb_out_puts(out,"ERR app-plan operands\n");}
            int rc=wb_app_operation(cmd->argv[0],cmd->argc==2?cmd->argv[1]:NULL,true,out);
            if(rc!=WB_OK)*status=1;
            return rc;
        }
        case WB_CMD_TERM_RESULT: {
            int rc=cmd->argc==2 ? wb_terminal_result(cmd->argv[0],cmd->argv[1],out) : WB_E_ARG;
            if(rc!=WB_OK)*status=1;
            return rc;
        }
        case WB_CMD_APP_INSTALL: {
            const int rc = do_app_install(cmd->argv[0], out);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_LAUNCH: {
            const int rc = do_launch(cmd->argv[0], cmd->argv[1], cmd->argv[2], out);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_INSPECT: {
            const int rc = do_inspect(cmd->argv[0], out);
            if (rc != WB_OK) *status = 1;
            return rc;
        }
        case WB_CMD_PENDING: {
            char buf[WBQ_CAP+1];
            size_t n = 0;
            if (wb_vita_read_small(WB_PENDING_PATH, buf, sizeof buf - 1, &n) == WB_OK) {
                buf[n] = 0;
                return wb_out_printf(out, "pending-core: %s\n", buf);
            }
            return wb_out_puts(out, "pending-core: no\n");
        }
        case WB_CMD_TERM_UPDATER_CHECK: {
            if (cmd->argc!=0 || !g_ssh.authenticated || !g_ssh.mode.accepted ||
                g_ssh.mode.mode!=MODE_B_KEY || !g_ssh.session || !g_ssh.channel ||
                !g_ssh.shell || !g_ssh.shell_pty || g_ssh.sftp_ro) {
                *status=1;return wb_out_puts(out,"ERR paired interactive PTY required\n");
            }
            int detail=0;
            int rc=wb_updater_probe(&detail);
            if(rc!=WB_OK) {
                *status=1;
                return wb_out_printf(out,"ERR updater-check title=%s %s rc=%s detail=%08X\n",
                                     WB_UPDATER_TITLE_ID,wb_updater_decision(),wb_err_name(rc),(unsigned)detail);
            }
            return wb_out_printf(out,"OK updater-check title=%s %s\n",
                                 WB_UPDATER_TITLE_ID,wb_updater_decision());
        }
        case WB_CMD_R1_STATUS: return r1_status(out);
        case WB_CMD_APPLY_RETURN:
        case WB_CMD_PROMOTE: /* No direct native promote of the public stage. */
        case WB_CMD_S1_CHECK:
        case WB_CMD_APPLY_CORE: {
            const bool selfcheck=cmd->kind==WB_CMD_S1_CHECK;
            const bool unattended=cmd->kind==WB_CMD_APPLY_RETURN;
            const bool signed_transaction=unattended && r1_signed_armed;
            wb_signed_focus transaction_focus={0},handoff_focus={0};
            char handoff_receipt[WBQ_CAP]={0};
            /* A signed update is one bounded transaction, including savedata,
             * helper verification and the durable dispatch write. Individual
             * hash brackets do not cover that intervening work by themselves. */
            if(signed_transaction && (!r1_signed_begin || !r1_signed_end ||
               !r1_signed_begin(&transaction_focus))){
                (void)log_event("R1 SIGNED HANDOFF BRACKET START REFUSED");
                *status=1;return wb_out_puts(out,"ERR R1 handoff-focus-start; no updater launched\n");
            }
            if(unattended && r1_apply(cmd->argv[0],false)!=WB_OK){
                *status=1;return wb_out_puts(out,"ERR R1 grant-required; no updater launched\n");
            }
            /* Endpoints surround the actual main handoff I/O, not a sleep or
             * a caller-provided duration. Never refresh the ordinary baseline
             * unless the same owner/pins/receipt and both snapshots pass. */
            if(signed_transaction && (!r1_signed_armed || !r1_signed_begin ||
               !r1_signed_begin(&handoff_focus) ||
               wq_sealed_receipt(WB_PENDING_PATH,WBQ_SEAL,handoff_receipt)!=WB_OK)){
                (void)log_event("R1 SIGNED HANDOFF BRACKET START REFUSED");
                *status=1;return wb_out_puts(out,"ERR R1 handoff-focus-start; no updater launched\n");
            }
            if (selfcheck && (wb_vita_exists(WB_PENDING_PATH) || wb_vita_exists(WBQ_TEST))) {
                *status=1;return wb_out_puts(out,"ERR s1-check busy; no operation performed\n");
            }
            if (!selfcheck) {
                /* A signed R1 already rehashed the exact sealed tree via
                 * its bounded r1_apply precheck above, and rehashes again
                 * before dispatch. Do not add a third unbracketed hash. */
                int qrc=unattended&&r1_signed_armed?WB_OK:queued_core_check();
                if (qrc || wb_vita_exists(WBQ_TEST)) {
                    (void)timeline_event("refused", "", a.run_hex);
                    *status=1;return wb_out_puts(out,"ERR WBQ2 stage-or-receipt refused; restage with approved sha256\n");
                }
            }
            /* v1.38: mint a single-use return intent for the *next* boot.
             * The returning core consumes it and may then skip the paired-open
             * square and the pin cross, and accept exactly one 0x1080 power
             * notification when the supply is still online. Without this the
             * new core has no way to tell "return from our own update" from a
             * cold start, which is what stopped 01.37 at PAIRED OPEN. */
            {
                char receipt[64];
                size_t rn = 0;
                char qver[6] = {0};
                if (wb_vita_read_small(WB_PENDING_PATH, receipt, sizeof receipt - 1, &rn) == WB_OK) {
                    receipt[rn] = 0;
                    if (rn >= 10 && !strncmp(receipt, "WBQ2 ", 5)) {
                        memcpy(qver, receipt + 5, 5);
                        qver[5] = 0;
                    }
                }
                if (qver[0]) {
                    /* file intent first: independent of the arm-id charset */
                    SceRtcTick tick;
                    if (sceRtcGetCurrentTick(&tick) == 0 && tick.tick) {
                        char intent[64];
                        const int in = snprintf(intent, sizeof intent, "build=%s\nissued=%" PRIu64 "\n",
                                                qver, (uint64_t)tick.tick);
                        int fd = -1;
                        bool ok = false;
                        if (in > 0) {
                            fd = sceIoOpen(WB_ROOT "/return-intent.txt",
                                           SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
                            if (fd >= 0) {
                                ok = sceIoWrite(fd, intent, (SceSize)in) == in;
                                /* the process is killed by the platform moments
                                 * after the updater starts; without this sync the
                                 * intent can vanish before the next boot reads it */
                                if (sceIoSyncByFd(fd, 0) < 0) ok = false;
                                (void)sceIoClose(fd);
                            }
                        }
                        if (ok) {
                            (void)log_event("RETURN INTENT WRITTEN");
                            (void)timeline_event("return-arm", qver, a.run_hex);
                        } else {
                            (void)log_event("RETURN INTENT WRITE FAILED");
                        }
                    }
                    /* arm intent as well, with a legal job id (no dot) */
                    char rjob[24];
                    snprintf(rjob, sizeof rjob, "return-%c%c_%c%c", qver[0], qver[1], qver[3], qver[4]);
                    if (wb_arm_issue(rjob, "core-return") == WB_OK) (void)log_event("RETURN ARM ISSUED");
                    else (void)log_event("RETURN ARM FAILED");
                }
            }
            if(!unattended && r1_revoke()!=WB_OK){
                *status=1;return wb_out_puts(out,"ERR R1 cancel-failed; no updater launched\n");
            }
            int detail = 0;
            if(timeline_event("updater", "", a.run_hex)!=WB_OK)
                (void)wb_out_puts(out,"WARN timeline-not-saved before updater launch\n");
            startup_mark("UPDATER INSTALL ENTER", 0);
            int urc = wb_updater_install(&detail);
            startup_mark("UPDATER INSTALL RC", urc);
            /* Source prefix is this running core, epoch describes the helper. */
            wb_handoff_note(wb_updater_decision(),urc);
            if (urc != WB_OK) {
                *status = 1;
                return wb_out_printf(out, "ERR updater-install %s %s detail=%08X; no updater launched\n",
                                     wb_err_name(urc),wb_updater_decision(),(unsigned)detail);
            }
            if(!quick_barrier()){
                *status=1;return wb_out_puts(out,"ERR quick-open-fence not saved; no updater launched\n");
            }
            if(signed_transaction && (!r1_signed_armed || !r1_signed_end ||
               !r1_signed_end(&handoff_focus,handoff_receipt))){
                (void)log_event("R1 SIGNED HANDOFF BRACKET END REFUSED");
                *status=1;return wb_out_puts(out,"ERR R1 handoff-focus-end; no updater launched\n");
            }
            if(unattended && r1_apply(cmd->argv[0],true)!=WB_OK){
                *status=1;return wb_out_puts(out,"ERR R1 grant-required; no updater launched\n");
            }
            /* Enforce the same 10s total budget and unchanged event/power/
             * clock generation across BOTH hashes and all handoff operations.
             * A late fault after DISPATCHED was persisted must revoke that
             * request before returning; no launch occurs even if revoke fails. */
            if(signed_transaction && (!r1_signed_armed || !r1_signed_end ||
               !r1_signed_end(&transaction_focus,handoff_receipt))){
                (void)log_event("R1 SIGNED HANDOFF TRANSACTION REFUSED");
                const int cancel=r1_revoke();
                *status=1;return wb_out_puts(out,cancel==WB_OK?
                    "ERR R1 handoff-transaction; no updater launched\n":
                    "ERR R1 handoff-cancel-failed; no updater launched\n");
            }
            if(selfcheck && (wq_mkdir(WBQ_STORE) || wq_save(WBQ_TEST,a.run_hex,strlen(a.run_hex)))){
                *status=1;return wb_out_puts(out,"ERR s1-check fixture request failed\n");
            }
            a.guard_grace = now_ms() + 15000;
            const int lrc = wb_updater_launch();
            startup_mark("UPDATER LAUNCH RC", lrc);
            if (lrc < 0) {
                if(unattended)(void)r1_revoke();
                if(selfcheck)(void)sceIoRemove(WBQ_TEST);
                *status = 1;
                return wb_out_printf(out, "ERR updater-launch 0x%08X; start %s from LiveArea\n",
                                     (unsigned)lrc, WB_UPDATER_TITLE_ID);
            }
            /* From this point the fixed-title launch is outstanding; do not
             * take any other command or wait for Sony to close this app. */
            a.updater_accepted = true;
            return wb_out_printf(out, "OK updater %s (detail=%d), launching %s; "
                                 "ssh will drop\n", detail ? "reused" : "installed", detail, WB_UPDATER_TITLE_ID);
        }
        case WB_CMD_TERM_APP_RUNNING:
            if(cmd->argc==1&&!strcmp(cmd->argv[0],"all"))return wb_running_sweep(cmd,out,status);
            return wb_app_running_command(cmd,out,status);
        case WB_CMD_TERM_WAKE_PROBE:
        case WB_CMD_TERM_WAKE_PROBE_STATUS:
            return wb_probe_command(cmd,out,status);
        case WB_CMD_BYE:
            return wb_out_puts(out, "OK bye\n");
        case WB_CMD_EXT: {
            const wb_payload_v1 *t = wb_vita_payload_table();
            const char *pcmd = cmd->name;
            int first = 0;
            if (cmd->argc < 0 || cmd->argc > WB_CMD_MAX_ARGS)
                return wb_out_puts(out, "ERR invalid argument count\n");
            if (!strcmp(cmd->name, "ext")) {
                if (cmd->argc < 1) return wb_out_puts(out, "ERR usage: ext <cmd>\n");
                pcmd = cmd->argv[0];
                first = 1;
            }
            const int parc = cmd->argc - first;
            char *pargv[WB_CMD_MAX_ARGS + 1] = {0};
            /* The parser owns fixed-width character rows. ABI v3 requires
             * pointers to those rows for the duration of this synchronous call. */
            for (int i = 0; i < parc; ++i)
                pargv[i] = (char *)cmd->argv[first + i];
            if (!wb_ext_operands_ok(pcmd, parc, pargv)) {
                *status = 1;
                return wb_out_puts(out, "ERR path-denied\n");
            }
            if (!wb_payload_ok(t)) {
                char ver[32] = {0};
                startup_mark("PAYLOAD LAZY LOAD", 0);
                const int lrc = wb_vita_payload_boot(ver, sizeof ver);
                startup_mark("PAYLOAD LAZY RC", lrc);
                t = wb_vita_payload_table();
                if (!wb_payload_ok(t))
                    return wb_out_printf(out, "ERR no-payload %s\n", wb_err_name(lrc));
                wb_strcpy(a.payload_ver, sizeof a.payload_ver, ver);
            }
            return t->dispatch(pcmd, parc, pargv, out, (void *)&g_ssh);
        }
        default:
            return wb_out_puts(out, "ERR bad-command\n");
    }
}

/* EXEC admission: resilient mode serves while the console is locked, strict
 * mode keeps the original foreground+link requirement. */
static bool gate_ok(void *ctx) {
    (void)ctx;
    if (a.remote_start) return private_link();
    if (a.resilient) return true;
    return foreground(false) && private_link();
}

static const wb_core g_core = {
    .ctx = NULL,
    .foreground = core_foreground,
    .gate = gate_ok,
    .link_ok = core_link,
    .exec = core_exec,
    .note = core_note,
    .run_hex = NULL,
    .user_pin_hex = NULL
};

/* ---- startup gate: CROSS arms the listener ---- */

static const char *prep_listener(void) {
    const uint64_t start = now_ms();
    PrepGate g = { .start = start, .last = start };
    for (;;) {
        SceCtrlData pad = {0};
        const uint64_t t = now_ms();
        const bool fg = foreground(false);
        const bool input = fg && sceCtrlPeekBufferPositive(0, &pad, 1) > 0;
        char label[55];
        snprintf(label, sizeof label, "CROSS ENABLES LIVE UPDATE - %03" PRIu64 " SEC",
                 prep_seconds_left(&g, t));
        const bool drawn = input && display_frame(label, a.pin, 0);
        switch (prep_tick(&g, t, fg, input, drawn, pad.buttons, SCE_CTRL_CROSS, SCE_CTRL_START)) {
            case PREP_ENABLE: return NULL;
            case PREP_EXIT: return "USER EXIT";
            case PREP_EXPIRED: return "PREP EXPIRED";
            case PREP_FOCUS_LOST: return "FOCUS LOST";
            case PREP_INPUT_ERROR: return "INPUT ERROR";
            case PREP_RENDER_ERROR: return "DISPLAY ERROR";
            case PREP_CLOCK_ERROR: return "CLOCK ERROR";
            default: break;
        }
        sceKernelDelayThread(16000);
    }
}

static int await_choice(const char *label, const char *pin, unsigned choice, uint64_t ttl) {
    const uint64_t began = now_ms();
    bool released = false;
    for (;;) {
        const uint64_t current = now_ms();
        if (current < began || current - began >= ttl) return 0;
        SceCtrlData p = {0};
        if (sceCtrlPeekBufferPositive(0, &p, 1) <= 0 || !foreground(false) ||
            !display_frame_prompt(label, pin, 0, pin ? NULL : choice==SCE_CTRL_SQUARE?"RELEASE THEN SQUARE / START EXITS":"CROSS RETRIES"))
            return 0;
        const int action = fresh_choice(&released, p.buttons, choice, SCE_CTRL_START);
        if (action) return action;
        sceKernelDelayThread(16000);
    }
}

/* Either local △ or a matching notice after the SSH transport closes opens
 * the prompt. Only a fresh local hardware × grants approval. While open
 * (up to 30 seconds), this prompt does not service SSH or accept an install. */
static void review_return_expected(const char *expected) {
    wb_review_model m;bool neutral=false;
    if(!foreground(false) || !wb_review_snapshot(&m,r1_queue) ||
       (expected && strcmp(expected,m.receipt))){ui_refresh(NULL,"R1 NO VERIFIED UPDATE");return;}
    const uint64_t start=now_ms();
    while(now_ms()>=start && now_ms()-start<30000){
        SceCtrlData pad={0};
        if(!foreground(false) || sceCtrlPeekBufferPositive(0,&pad,1)<=0 ||
           !display_frame_prompt(m.label,m.groups,0,"CROSS APPROVES THIS UPDATE RETURN"))break;
        if(pad.buttons & (SCE_CTRL_START|SCE_CTRL_SELECT)){
            const bool persisted=!(pad.buttons&SCE_CTRL_SELECT) || wb_standing_veto();
            (void)r1_revoke();ui_refresh(NULL,persisted?"R1 CANCELLED":"R1 STANDING REVOKE SAVE FAILED");return;
        }
        if(!pad.buttons)neutral=true;
        else if(neutral){
            if(pad.buttons==SCE_CTRL_CROSS){
                bool ok=foreground(false) && r1_issue_local(m.receipt)==WB_OK;
                r1_bound=false;
                ui_refresh(NULL,ok?"R1 AUTHORIZED / SELECT REVOKES":"R1 NOT SAVED");
                (void)log_event(ok?"R1 LOCAL GRANT SAVED":"R1 LOCAL GRANT REFUSED");
                return;
            }
            neutral=false;
        }
        sceKernelDelayThread(16000);
    }
    ui_refresh(NULL,"R1 REVIEW ENDED");
}
static void review_return_local(void){review_return_expected(NULL);}
static int inactive_screen(const char *label) {
    for (;;) {
        if (!display_frame_prompt(label, NULL, 0, "REOPEN APP TO CONTINUE")) return 1;
        SceCtrlData pad = {0};
        if (sceCtrlPeekBufferPositive(0, &pad, 1) <= 0) { sceKernelDelayThread(16000); continue; }
        if (pad.buttons & SCE_CTRL_START) return 0;
        sceKernelDelayThread(16000);
    }
}


int main(void) {
    startup_mark("MAIN ENTER", 0);
    if (!display_init()) { display_plain_error("DISPLAY INIT STOPPED"); return 1; }

    const char *reason = "STARTUP STOPPED";
    bool owner_exit_from_listener = false;
    if (sceKernelGetRandomNumber(a.run, sizeof a.run) < 0) { reason = "RNG FAILED"; goto out; }
    unsigned rng_or = 0;
    for (size_t i = 0; i < sizeof a.run; i++) rng_or |= a.run[i];
    if (!rng_or) { reason = "RNG FAILED"; goto out; }
    hex(a.run_hex, a.run, sizeof a.run);

    sceIoMkdir(WB_ROOT, 0777);
    wb_font_boot(&font_state,&font_storage);
    a.log = sceIoOpen(WB_LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (a.log < 0) { reason = "RUN LOG UNAVAILABLE"; goto out; }
    (void)log_event("STARTUP " WB_VERSION " build=" WB_BUILD_TAG);

    load_config();
#if defined(WB_APP_LOCAL_PATH)
    wb_app_local_load();   /* owner-signed runtime approvals, if any */
#endif
    a.resilient = true;
    {
        char mode[16];
        size_t mode_len = 0;
        if (wb_vita_read_small(WB_ROOT "/mode.txt", mode, sizeof mode - 1, &mode_len) == WB_OK) {
            mode[mode_len] = 0;
            if (strstr(mode, "strict")) a.resilient = false;
        }
    }
    load_peers();

    /* Only a complete existing pair can select owner-authorized recovery. */
    if (!import_public_pin()) { reason = "MAC PUBLIC PIN INVALID"; goto out; }
    const bool remote_start=remote_start_allowed();
    if(remote_start){
        if(!remote_start_observe("initial")){reason="REMOTE AUDIT FAILED";goto out;}
    }else{
        reason = wait_initial_focus();
        if (reason) goto out;
    }
    reason = "STARTUP STOPPED";

    wb_quick_route qr=quick_route();
    bool quick_ok=false;
    wb_r1_ticket ret={0};bool return_ok=r1_boot(&ret);
    bool owner_confirmed = false;
    char arm_job[64]={0};
    const bool consumed = wb_arm_consume(arm_job);
    const bool return_intent = return_intent_take();
    /* A return marker may reuse a verified, complete identity, never create
     * one. wb_ssh_prepare separately enforces this at its point of use. */
    if(return_ok){
        /* r1_boot already checked the actually enrolled key. Do not enroll. */
        (void)log_event("R1 RETURN PROOF ACCEPTED");
        /* The host may chain a further update: this run cannot grant one, but a
         * fresh process starts unbound. Only the host marker authorises the
         * restart, and it is removed before the call so it can never loop. */
#if defined(WB_REOPEN_MARKER)
        /* Compiled only where the reopen header is present; partial-core host
         * fixtures slice this function without it. verify_package.py asserts
         * the strings below really are in the shipped eboot. */
        if(wb_reopen_requested()){
            const int rm=(int)r1_remove(WB_REOPEN_MARKER);
            if(rm==WB_OK && wb_reopen_self()){
                (void)log_event("R1 REOPEN SELF FOR CLEAN RUN");
                return 0;   /* LoadExec returned without replacing us: stop here. */
            }
            (void)log_event("R1 REOPEN DECLINED");
        }
#endif
    }else if (return_intent && wb_ssh_host_identity_enrolled()) {
        (void)log_event("RETURN INTENT BRANCH");
        startup_mark("RETURN INTENT", 1);
    }else if (consumed && wb_ssh_host_identity_enrolled()) {
        char note[120];
        snprintf(note,sizeof note,"RETURN ARM OK job=%s",arm_job);
        (void)log_event(note);
        startup_mark("AUTOARM MARKER", 1);
    } else if(remote_start || qr!=WB_Q_NONE){
        /* An existing owner+host pair may open its listener even when a
         * pending queue or an unclassified launch requires recovery. This
         * grants no update/return authority: r1_boot, signatures and WBQ2
         * remain separate, and foreground/power/veto/pin checks below stay.
         * Never turn this route into permission to create an identity. */
        if(remote_start?remote_start_veto():quick_veto()){reason="QUICK OPEN VETO";goto out;}
        (void)log_event("PAIRED LISTENER AUTO ENTRY; UPDATE GRANT UNCHANGED");
        quick_ok=true;
    }else {
        if (await_choice("CHECK MAC PUBLIC PIN", a.user_pin, SCE_CTRL_CROSS, 90000) != 1) {
            reason = "MAC PUBLIC PIN NOT CONFIRMED";
            goto out;
        }
        owner_confirmed = true;
    }

    if (wb_ssh_prepare(&g_ssh, a.user_pin, owner_confirmed) != WB_OK) {
        reason = g_ssh.error[0] ? g_ssh.error : "SSH IDENTITY FAILED";
        goto out;
    }
    if(return_ok && !wb_r1_pin_equal(ret.host_pin,g_ssh.host_pin)){reason="R1 HOST CHANGED";goto out;}
    if(quick_ok && !wb_quick_pair(a.user_pin,g_ssh.host_pin)){reason="QUICK HOST CHANGED";goto out;}
    wb_strcpy(a.pin, sizeof a.pin, g_ssh.host_pin);
    startup_mark("HOST IDENTITY READY", 0);
    if(remote_start){
        if(!quick_enabled() || !wb_quick_pair(a.user_pin,g_ssh.host_pin) || remote_start_veto()){
            reason="REMOTE PAIR OR VETO";goto out;
        }
        a.remote_start=true;
        a.resilient=true; /* owner policy; the strict-mode file is not rewritten */
        if(!log_event("REMOTE OWNER START ENABLED; NO UPDATE GRANT")){reason="REMOTE AUDIT FAILED";goto out;}
    }else{
        reason = wait_initial_focus();
        if (reason) goto out;
    }
    a.power_cb = sceKernelCreateCallback("WbPower", 0, power_note, NULL);
    const uint64_t registration = now_ms();
    if (a.power_cb < 0 || scePowerRegisterCallback(a.power_cb) < 0) { reason = "POWER WATCH FAILED"; goto out; }
    a.power_registered = true;
    const bool update_return = consumed || return_ok || return_intent;
    const bool hands_free=return_ok || update_return || quick_ok;
    if(return_ok)memcpy(pw_diag_source,ret.source_run,sizeof pw_diag_source); /* public correlation only, never read by a gate */
    if(remote_start){
        /* Telemetry is sampled, not changed or misrepresented as foreground.
         * Registration flags are not an approval prerequisite for this
         * already-paired owner's listener. R1 update guards stay separate. */
        if(remote_start_veto()){reason="REMOTE LOCAL VETO";goto out;}
        if(!remote_start_observe("power")){reason="REMOTE AUDIT FAILED";goto out;}
    }else{
        reason = initial_power_drain(registration,hands_free,quick_ok,return_ok,update_return || quick_ok);
        if (reason) goto out;
        if (!foreground(false)) { reason = "FOCUS LOST AFTER POWER WATCH"; goto out; }
    }

    if(return_ok){
        SceCtrlData veto={0};
        if(!wb_r1_valid(&ret,r1_now()) || (remote_start?remote_start_veto():
           (sceCtrlPeekBufferPositive(0,&veto,1)<=0 || (veto.buttons & (SCE_CTRL_START|SCE_CTRL_SELECT))))){reason="R1 VETO OR EXPIRED";goto out;}
    }else if(update_return){
        /* A verified return (arm intent / return-intent file) must not fall
         * through to the 01.09 "CROSS ENABLES LIVE UPDATE" consent gate: the
         * owner already authorized this exact staged build before the updater
         * ran. START/SELECT still veto, exactly like the R1 path. */
        SceCtrlData veto={0};
        if(remote_start?remote_start_veto():(sceCtrlPeekBufferPositive(0,&veto,1)<=0 ||
           (veto.buttons & (SCE_CTRL_START|SCE_CTRL_SELECT)))){reason="RETURN VETO";goto out;}
        (void)log_event("RETURN SKIP CONSENT");
    }else if(quick_ok){
        if(remote_start?remote_start_veto():quick_veto()){reason="QUICK OPEN VETO";goto out;}
    }else{
        reason = prep_listener();
        if (reason) goto out;
    }
    if (!remote_start && !foreground(false)) { reason = "FOCUS LOST BEFORE NETWORK"; goto out; }
    if (!net_setup()) { reason = "LAN ADDRESS NOT READY"; goto out; }
    if (!remote_start && !foreground(false)) { reason = "FOCUS LOST BEFORE BIND"; goto out; }

    /* The payload is loaded on demand (reload / ext), not at arm time: a bad
     * module then costs one command instead of the whole startup path, and
     * startup.log records whether the loader was entered at all. */
    (void)log_event("PAYLOAD DEFERRED");

    if(return_ok){
        SceCtrlData veto={0};
        if(!wb_r1_valid(&ret,r1_now()) || (remote_start?remote_start_veto():
           (sceCtrlPeekBufferPositive(0,&veto,1)<=0 || (veto.buttons & (SCE_CTRL_START|SCE_CTRL_SELECT))))){reason="R1 VETO OR EXPIRED";goto out;}
    }
    if(quick_ok){
        /* v1.56: the old guard also demanded quick_pref()==Q_REMEMBER, but
         * apply-core deliberately fences the preference (Q_FENCE) before every
         * update while wb_quick_decide() already grants WB_Q_REMEMBERED for a
         * clean bubble launch. The two disagreed, so the first cold start after
         * each update died with QUICK BIND REFUSED. Decide once, log the parts. */
        const bool veto=remote_start?remote_start_veto():quick_veto();
        const bool pair=wb_quick_pair(a.user_pin,g_ssh.host_pin);
        const bool enabled=quick_enabled();
        if(veto || !pair || !enabled){
            char note[128];
            snprintf(note,sizeof note,"QUICK BIND REFUSED veto=%d pair=%d en=%d pref=%d qr=%d",
                     veto?1:0,pair?1:0,enabled?1:0,quick_pref(),(int)qr);
            (void)log_event(note);
            (void)timeline_event("quick-refused",note,a.run_hex);
            reason="QUICK BIND REFUSED";goto out;
        }
    }
    /* Every recovery route, including return-intent without quick_ok, must
     * recheck the exact pair, opt-out and any observed local veto at bind. */
    if(remote_start && (!quick_enabled() || !wb_quick_pair(a.user_pin,g_ssh.host_pin) || remote_start_veto())){
        reason="REMOTE PAIR OR VETO BEFORE BIND";goto out;
    }
    if (wb_ssh_open(&g_ssh, a.ip, WB_PORT, (const char (*)[16])a.peer, a.peer_count) != WB_OK) {
        reason = "LISTEN FAILED";
        goto out;
    }
    if(remote_start)remote_start_installed_audit();
    if(return_ok){
        char line[160];snprintf(line,sizeof line,"R1 RETURN LISTENING source=%s nonce=%s",ret.source_run,ret.nonce);
        if(!log_event(line)){reason="R1 AUDIT FAILED";goto out;}
        r1_completed=ret;r1_bound=true;
        wb_standing_bootstrap(&ret);
    }
    if(quick_ok && !log_event(qr==WB_Q_DIRECT?"QUICK OPEN LISTENING origin=livearea buttons=0":
                             qr==WB_Q_REMEMBERED?"QUICK OPEN LISTENING origin=remembered-empty buttons=0":"QUICK OPEN LISTENING origin=paired-recovery buttons=0")){
        reason="QUICK AUDIT FAILED";goto out;
    }
    if(remote_start && !log_event("REMOTE OWNER LISTENING; BACKGROUND ALLOWED")){reason="REMOTE AUDIT FAILED";goto out;}
    ui_refresh(NULL,remote_start?"REMOTE OWNER MODE / SELECT REVOKES":"TRIANGLE REVIEW UPDATE / SELECT REVOKES");
    (void)log_event("LISTENING " WB_VERSION);

    /* One boot line per process: the PC compares it with the queued receipt to
     * tell "updater started" from "the new core is actually running". A queued
     * receipt whose version is already running is stale and gets dropped. */
    (void)timeline_event("boot", WB_VERSION, a.run_hex);
    /* Updater consumes the seal only after the platform reports success.
     * Never classify a leftover marker as verified merely from a version. */

    bool local_released=false,remote_input_unknown=false,remote_select_down=false;uint64_t last_r1_poll=0;
    wb_panel_keys panel_keys={0};
    unsigned ui_seen=0; /* per-listener, bounded presentation evidence; no per-frame I/O */
    for (;;) {
        SceCtrlData pad = {0};
        /* 01.92: the OLED-off timer is a SEPARATE timer from auto-suspend. Its
         * expiry (about 3 min without local input) is reported by the platform
         * as a system-UI overlay, which no signed focus bracket may accept and
         * which cannot be dismissed from inside the app. Tick it every
         * iteration, regardless of g_ssh.busy and of the guard grace, so an
         * untouched console keeps a takeable bracket. */
        (void)sceKernelPowerTick(SCE_KERNEL_POWER_TICK_DISABLE_OLED_OFF);
        uint64_t mono=now_ms();
        if(r1_source_live && (mono<last_r1_poll || mono-last_r1_poll>=1000)){
            last_r1_poll=mono;(void)r1_clock(r1_now());
        }
        const bool input = sceCtrlPeekBufferPositive(0, &pad, 1) > 0;
        if (input && (pad.buttons & SCE_CTRL_START)) {
            owner_exit_from_listener = !g_ssh.busy && foreground(false);
            (void)r1_revoke();
            reason = "USER EXIT"; break;
        }
        if (!input && !a.remote_start) { reason = "LOCAL INPUT ERROR"; break; }
        if(!input){
            if(!remote_input_unknown)(void)log_event("REMOTE LOCAL INPUT UNKNOWN; SSH KEPT");
            remote_input_unknown=true;local_released=false;
        }else remote_input_unknown=false;
        if(input && (pad.buttons&SCE_CTRL_SELECT))wb_notice_cancel(&r1_notice);
        /* A positive SELECT observation remains a veto even when background
         * input was unavailable before it. Never fabricate a neutral release,
         * nor repeatedly toggle opt-out while the button stays held. */
        if(a.remote_start && input && (pad.buttons&SCE_CTRL_SELECT)){
            local_released=false;
            if(pad.buttons==(SCE_CTRL_SELECT|SCE_CTRL_SQUARE)){
                const bool ok=quick_switch(false);
                ui_refresh(NULL,ok?"QUICK OPEN DISABLED":"QUICK DISABLE NOT SAVED");
                /* Even failed persistence closes this listener. Do not claim
                 * that a failed write has disabled a later cold start. */
                reason=ok?"QUICK OPEN DISABLED":"QUICK DISABLE NOT SAVED";break;
            }
            if(!remote_select_down){
                const bool disabled=wb_standing_veto();
                const int rv=r1_revoke();
                ui_refresh(NULL,rv==WB_OK&&disabled?"R1 AUTHORIZATION REVOKED":"R1 REVOKE ERROR");
            }
            remote_select_down=true;
        }else if(input)remote_select_down=false;

        /* Only local foreground gestures change the viewport. Never inject a byte into the PTY. */
        if(input && wb_mirror_active()){
            unsigned key=wb_panel_action(&panel_keys,pad.buttons,mono);
            if(key){
                if(foreground(false))wb_panel_apply(key,panel_keys.repeating);
                else panel_keys=(wb_panel_keys){0};
            }
        }else panel_keys=(wb_panel_keys){0};

        if(input && !pad.buttons)local_released=true;
        else if(input && local_released){
            local_released=false;
            if(foreground(false) || (a.remote_start && (pad.buttons&SCE_CTRL_SELECT))){
                if(pad.buttons==SCE_CTRL_TRIANGLE && !g_ssh.session){
                    wb_notice_cancel(&r1_notice);review_return_local();
                }
                else if(pad.buttons==(SCE_CTRL_SELECT|SCE_CTRL_SQUARE)){
                    bool enable=!quick_enabled();
                    bool ok=quick_switch(enable);
                    ui_refresh(NULL,!ok?"QUICK SETTING NOT SAVED":enable?"QUICK OPEN ENABLED":"QUICK OPEN DISABLED");
                    if(ok && !enable){reason="QUICK OPEN DISABLED";break;}
                }else if(pad.buttons==SCE_CTRL_SELECT){
                    bool disabled=wb_standing_veto();
                    int rv=r1_revoke();ui_refresh(NULL,rv==WB_OK&&disabled?"R1 AUTHORIZATION REVOKED":"R1 REVOKE ERROR");
                }
            }
        }

        /* Lock screen: keep the listener alive, absorb the power/RTC jump, and
         * stop the shell from suspending us. Strict mode keeps the old policy. */
        const bool guard_active = !g_ssh.busy && now_ms() >= a.guard_grace;
        if (guard_active && a.resilient) {
            (void)sceKernelPowerTick(SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND);
            const uint64_t rnow = now_ms();
            if (a.absorb_last == 0 || rnow - a.absorb_last >= 1000) {
                a.absorb_last = rnow;
                absorb_focus();
            }
        }
        const bool fg_ok = !guard_active || a.resilient || foreground(false);
        const bool link_ok = !guard_active || (a.remote_start?private_link():(a.resilient || private_link()));
        if (guard_active && ((!a.resilient && !fg_ok) || !link_ok)) {
            const uint64_t gnow = now_ms();
            if (a.guard_strikes == 0 || gnow - a.guard_last > 900) {
                a.guard_strikes++;
                a.guard_last = gnow;
                (void)log_event(fg_ok ? "GUARD LINK STRIKE" : "GUARD FOCUS STRIKE");
            }
            if (a.guard_strikes >= 3) { reason = fg_ok ? "NETWORK LOST" : "FOCUS LOST"; break; }
        } else {
            a.guard_strikes = 0;
        }

        const int served = wb_ssh_service(&g_ssh, (wb_core *)&g_core);
        if (a.updater_accepted) {
            /* Never wait on input, inactive_screen, or the peer. The request
             * has already been sent; a lost receipt must never trigger retry. */
            int drain = wb_ssh_flush_handoff(&g_ssh);
            wb_handoff_note("core voluntary-exit requested; tty-drain", drain);
            sceKernelExitProcess(0);
            return 0;
        }
        if (!served) { reason = "SSH ERROR"; break; }

        if (a.restart_at && now_ms() >= a.restart_at) {
            a.restart_at = 0;
            (void)log_event("APPLY CORE - LOADEXEC");
            display_frame_prompt("RESTARTING WORKBENCH", NULL, 0, "SSH RECONNECTS AFTER BOOT");
            if(!quick_barrier()){reason="QUICK FENCE NOT SAVED";break;}
            sceAppMgrLoadExec("app0:eboot.bin", NULL, NULL);
            reason = "LOADEXEC REFUSED";
            break;
        }

        if (!g_ssh.listening) { reason = "LISTENER CLOSED"; break; }
        if(r1_notice.pending){
            const bool notice_focus=foreground(false);
            if(wb_notice_ready(&r1_notice,g_ssh.session!=NULL,notice_focus,now_ms(),a.power_calls)){
                review_return_expected(r1_notice.receipt);
                local_released=false; /* next ordinary listener key also needs a fresh release */
            }
        }
        phase_begin("PHASE DISPLAY PRESENT");
        const bool agent_online = g_ssh.authenticated && wb_ssh_connected(&g_ssh);
        const bool drew = display_terminal(a.pin,a.ui_line2,agent_online);
        phase_end(drew ? 0 : -1);
        if (!drew) { reason = "DISPLAY ERROR"; break; }
        const unsigned ui_bit = agent_online ? 2u : 1u;
        if (!(ui_seen & ui_bit)) {
            ui_seen |= ui_bit; /* even a failed log write must not retry every frame */
            (void)log_event(agent_online ? "UI PRESENT TERMINAL ONLINE" : "UI PRESENT TERMINAL IDLE");
        }
        sceKernelDelayThread(16000);
    }

out:
    (void)log_event(reason);
    if (owner_exit_from_listener && wb_vita_exists(WB_PENDING_PATH)) {
        /* No direct promote from the mutable staging area on owner exit. */
        (void)log_event("QUEUED CORE RETAINED: use apply-core");
    }
    startup_mark(reason, 0);
    wb_ssh_close_listener(&g_ssh);
    wb_vita_payload_unload();
    wb_ssh_shutdown(&g_ssh);
    if (a.ctl) { sceNetCtlTerm(); a.ctl = false; }
    if (a.net) { sceNetTerm(); a.net = false; }
    if (a.own_net_module) { sceSysmoduleUnloadModule(SCE_SYSMODULE_NET); a.own_net_module = false; }
    if (a.power_registered) scePowerUnregisterCallback(a.power_cb);
    if (a.power_cb >= 0) sceKernelDeleteCallback(a.power_cb);
    if (a.log >= 0) sceIoClose(a.log);
    auth_end(&g_ssh.mode);
    (void)inactive_screen(reason);
    display_close();
    return 0;
}

/* WB_APPROVED_TABLE_BEGIN */
/* Bounded approval snapshot, NOT an installed-app/process/foreground list.
 * Version/provenance below describe approvals only, never the PID's image.
 * One SDK query per unique title is a per-title observation, not an atomic
 * global process snapshot. No new provider or launch authority is introduced. */
#define WB_RUNNING_TABLE_ROWS_MAX 16u
#define WB_RUNNING_TABLE_META_SIZE (20u*WB_RUNNING_TABLE_ROWS_MAX+1u)
typedef struct {
    char title[10],version[6],sha[65];bool owner;
} wb_running_approval;
typedef struct {
    unsigned first,approvals;bool conflict;int rc;SceUID pid;
} wb_running_table_row;
static bool wb_running_table_field(char *dst,const char *src,size_t n) {
    if(!src)return false;
    for(size_t k=0;k<=n;k++){
        if(k==n){if(src[k])return false;}
        else if(!src[k])return false;
        dst[k]=src[k];
    }
    return true;
}
static bool wb_running_approval_copy(wb_running_approval *dst,const char *title,
        const char *version,const char *sha,bool owner) {
    if(!wb_running_table_field(dst->title,title,9) ||
       !wb_running_table_field(dst->version,version,5) ||
       !wb_running_table_field(dst->sha,sha,64))return false;
    for(unsigned k=0;k<9;k++)if(!((dst->title[k]>='A'&&dst->title[k]<='Z') ||
        (dst->title[k]>='0'&&dst->title[k]<='9')))return false;
    for(unsigned k=0;k<5;k++)if(k==2?dst->version[k]!='.':
        !(dst->version[k]>='0'&&dst->version[k]<='9'))return false;
    for(unsigned k=0;k<64;k++)if(!((dst->sha[k]>='0'&&dst->sha[k]<='9') ||
        (dst->sha[k]>='a'&&dst->sha[k]<='f')))return false;
    dst->owner=owner;return true;
}
static bool wb_running_local_unchanged(unsigned count,const wb_app_row *snapshot) {
    return wb_app_local_count==count &&
        (!count || !memcmp(wb_app_local_rows,snapshot,count*sizeof *snapshot));
}
static int wb_running_table_error(wb_out *out,int *status,const char *why) {
    *status=1;
    return wb_out_printf(out,"ERR app-running-table INCONCLUSIVE %s scope=approved-titles; not-a-process-list; no-foreground-claim\n",why);
}
static int wb_running_sweep(const wb_cmd *cmd,wb_out *out,int *status) {
    *status=1;
    const char *why=wb_running_admission(cmd);
    if(why)return wb_running_error(out,status,why,0);
    if(cmd->argc!=1 || strcmp(cmd->argv[0],"all"))
        return wb_running_table_error(out,status,"usage: app running all");
    const size_t compiled=WB_REG_ROWS;const unsigned runtime=wb_app_local_count;
    if(compiled>WB_RUNNING_TABLE_ROWS_MAX || runtime>WB_APP_LOCAL_ROWS ||
       compiled>WB_RUNNING_TABLE_ROWS_MAX-runtime)
        return wb_running_table_error(out,status,"approval-table-capacity");
    const size_t rows=compiled+runtime;
    wb_app_row local[WB_APP_LOCAL_ROWS];
    if(runtime)memcpy(local,wb_app_local_rows,runtime*sizeof *local);
    wb_running_approval approvals[WB_RUNNING_TABLE_ROWS_MAX];
    for(size_t k=0;k<compiled;k++)
        if(!wb_running_approval_copy(&approvals[k],wb_reg_entries[k].title,
            wb_reg_entries[k].version,wb_reg_entries[k].sha256,false))
            return wb_running_table_error(out,status,"invalid-compiled-approval");
    for(unsigned k=0;k<runtime;k++)
        if(!wb_running_approval_copy(&approvals[compiled+k],local[k].title,local[k].ver,local[k].sha,true))
            return wb_running_table_error(out,status,"invalid-owner-approval");
    if(!wb_running_local_unchanged(runtime,local))
        return wb_running_table_error(out,status,"approval-table-changed");
    wb_running_table_row table[WB_RUNNING_TABLE_ROWS_MAX]={0};unsigned count=0;
    for(size_t k=0;k<rows;k++){
        unsigned at=0;
        while(at<count && strcmp(approvals[table[at].first].title,approvals[k].title))++at;
        if(at==count){table[at].first=(unsigned)k;++count;}
        ++table[at].approvals;
        for(size_t j=0;j<k;j++)if(!strcmp(approvals[j].title,approvals[k].title) &&
            !strcmp(approvals[j].version,approvals[k].version) &&
            strcmp(approvals[j].sha,approvals[k].sha))table[at].conflict=true;
    }
    unsigned started=0,not_started=0,unknown=0,conflicts=0;
    for(unsigned k=0;k<count;k++){
        why=wb_running_admission(cmd);
        if(why)return wb_running_error(out,status,why,0);
        table[k].pid=0;
        table[k].rc=sceAppMgrGetIdByName(&table[k].pid,approvals[table[k].first].title);
        if(!wb_running_local_unchanged(runtime,local))
            return wb_running_table_error(out,status,"approval-table-changed");
        const char *state=wb_running_query_state(table[k].rc,table[k].pid);
        if(!strcmp(state,"started"))++started;
        else if(!strcmp(state,"not-started"))++not_started;
        else ++unknown;
        if(table[k].conflict)++conflicts;
    }
    why=wb_running_admission(cmd);
    if(why)return wb_running_error(out,status,why,0);
    if(!wb_running_local_unchanged(runtime,local))
        return wb_running_table_error(out,status,"approval-table-changed");
    for(unsigned k=0;k<count;k++){
        char metadata[WB_RUNNING_TABLE_META_SIZE];size_t used=0;metadata[0]=0;
        const char *title=approvals[table[k].first].title;
        for(size_t j=0;j<rows;j++)if(!strcmp(title,approvals[j].title)){
            int n=snprintf(metadata+used,sizeof metadata-used,"%s%s:%s",used?",":"",
                approvals[j].owner?"owner-signed":"compiled",approvals[j].version);
            if(n<0 || (size_t)n>=sizeof metadata-used)
                return wb_running_table_error(out,status,"approval-metadata-capacity");
            used+=(size_t)n;
        }
        const int native=table[k].rc;const SceUID pid=table[k].pid;
        const char *state=wb_running_query_state(native,pid);
        const char *symbol=native==0?(pid>0?"OK":"INVALID_RESULT"):wb_running_symbol(native);
        int rc=wb_out_printf(out,"app-running title=%s rc=%d (0x%08X) symbol=%s state=%s pid=%d raw_pid=%d approval_rows=%u approval_conflict=%s approvals=%s\n",
            title,native,(unsigned)native,symbol,state,!strcmp(state,"started")?(int)pid:0,
            (int)pid,table[k].approvals,table[k].conflict?"yes":"no",metadata);
        if(rc<0)return rc;
    }
    if(!wb_running_local_unchanged(runtime,local))
        return wb_running_table_error(out,status,"approval-table-changed");
    int rc=wb_out_puts(out,"app-running note=approval-versions-only; not-running-image-identity; single-query-per-title; not-a-process-list; no-foreground-claim\n");
    if(rc<0)return rc;
    const bool partial=unknown!=0 || conflicts!=0;
    rc=wb_out_printf(out,"app-running table titles=%u started=%u not_started=%u unknown=%u approval_rows=%u approval_conflicts=%u partial=%s scope=approved-titles source=GetIdByName\n",
        count,started,not_started,unknown,(unsigned)rows,conflicts,partial?"yes":"no");
    if(rc<0)return rc;
    *status=partial?1:0;return WB_OK;
}
