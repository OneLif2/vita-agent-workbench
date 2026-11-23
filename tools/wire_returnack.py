from pathlib import Path

root = Path(r"D:\OneDrive\_python_test\PS-Vita-REA\v1.37")
p = root / "source" / "vita_ssh_status.c"
t = p.read_text(encoding="utf-8")

# 1. power drain gains a bounded resume-ack allowance
old_sig = "static bool initial_power_drain(uint64_t start,bool unattended,bool paired_open,bool return_ok) {"
new_sig = "static bool initial_power_drain(uint64_t start,bool unattended,bool paired_open,bool return_ok,bool resume_ack) {"
assert old_sig in t
t = t.replace(old_sig, new_sig, 1)

# 2. the single place that decides PW_LOCAL_ACK
old = """        if (step == PW_LOCAL_ACK) {
            if(unattended){pw_diag_stop(unattended,paired_open,step,dt,&e,focus,seen,ac,suspend,low);(void)log_event(paired_open?"QUICK NEEDS OWNER: POWER ACK":"R1 NEEDS OWNER: POWER ACK");return false;}"""
new = """        if (step == PW_LOCAL_ACK) {
            /* v1.37: this boot is a *return* (verified R1 proof or a consumed
             * arm intent written before the updater/app launch). The Vita
             * reports AFTER_RESUME together with AC online even when the
             * previous app was merely closed for the update; the platform does
             * not distinguish "system closed us" from "real suspend". Inside a
             * return, accept exactly that shape once, with the supply still
             * online and no low-battery/suspend-required veto, and record it.
             * Anything else (0x80 alone, supply change, repeat, late) still
             * stops and asks the owner. */
            if (resume_ack && seen.bits == (uint32_t)(WB_AC_ONLINE | WB_AFTER_RESUME) &&
                ac == 1 && !suspend && !low) {
                (void)log_event("RETURN AUTO ACK 0x1080");
                (void)log_event(return_ok ? "RETURN ACK BRANCH R1" : "RETURN ACK BRANCH ARM");
                step = PW_READY;
            } else
            if(unattended){pw_diag_stop(unattended,paired_open,step,dt,&e,focus,seen,ac,suspend,low);(void)log_event(paired_open?"QUICK NEEDS OWNER: POWER ACK":"R1 NEEDS OWNER: POWER ACK");return false;}"""
assert old in t
t = t.replace(old, new, 1)

# 3. boot: a consumed arm intent means "this boot is a return"
old = """    }else if (consumed && wb_ssh_host_identity_enrolled()) {
        char note[100];
        snprintf(note,sizeof note,"AUTOARM JOB OK job=%s",arm_job);
        (void)log_event(note);
        startup_mark("AUTOARM MARKER", 1);"""
new = """    }else if (consumed && wb_ssh_host_identity_enrolled()) {
        char note[120];
        snprintf(note,sizeof note,"RETURN ARM OK job=%s",arm_job);
        (void)log_event(note);
        startup_mark("AUTOARM MARKER", 1);"""
assert old in t
t = t.replace(old, new, 1)

# 4. pass the allowance at the call site
old = """    const bool hands_free=return_ok || (quick_ok && (qr==WB_Q_DIRECT || qr==WB_Q_REMEMBERED));"""
new = """    const bool update_return = consumed || return_ok;
    const bool hands_free=return_ok || update_return || (quick_ok && (qr==WB_Q_DIRECT || qr==WB_Q_REMEMBERED));"""
assert old in t
t = t.replace(old, new, 1)

old = "    if (!initial_power_drain(registration,hands_free,quick_ok,return_ok)) { reason = \"POWER EVENT - REOPEN APP\"; goto out; }"
new = "    if (!initial_power_drain(registration,hands_free,quick_ok,return_ok,update_return)) { reason = \"POWER EVENT - REOPEN APP\"; goto out; }"
assert old in t
t = t.replace(old, new, 1)
p.write_text(t, encoding="utf-8", newline="\n")

# 5. version bump
v = root / "source" / "wb_ver.h"
t = v.read_text(encoding="utf-8").replace('#define WB_VERSION      "01.36"', '#define WB_VERSION      "01.37"')
t = t.replace('#define WB_BUILD_TAG    WB_VERSION "-live-r1power"', '#define WB_BUILD_TAG    WB_VERSION "-live-returnack"')
v.write_text(t, encoding="utf-8", newline="\n")

b = root / "source" / "build.sh"
t = b.read_text(encoding="utf-8")
t = t.replace("APP_VER=01.36", "APP_VER=01.37").replace("workbench_0136.vpk", "workbench_0137.vpk")
b.write_text(t, encoding="utf-8", newline="\n")

vp = root / "source" / "verify_package.py"
t = vp.read_text(encoding="utf-8")
t = t.replace('APP_VER = "01.36"', 'APP_VER = "01.37"').replace("workbench_0136.vpk", "workbench_0137.vpk")
vp.write_text(t, encoding="utf-8", newline="\n")
print("v1.37 patched: resume-ack on return boots")
