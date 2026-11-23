/* workbench payload: the live-updatable half of the app.
 *
 * Everything that changes between releases lives here, so an update can be
 * delivered by swapping this module while the core keeps the SSH socket.
 *
 * Linked -shared? no: -nostartfiles -e module_start, and it must not reference
 * newlib (strcmp/memset/... become PLT slots and vita-elf-create rejects
 * R_ARM_JUMP_SLOT). All formatting and string work is local. */

#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/power.h>

#include <stdbool.h>
#include <stdint.h>

#include "wb_out.h"
#include "wb_payload.h"
#include "wb_ver.h"

#define WB_PAYLOAD_VERSION "01.22-p2.1"

static unsigned str_len(const char *s) {
    unsigned n = 0;
    while (s && s[n]) n++;
    return n;
}

static bool str_eq(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

static bool starts_with(const char *s, const char *p) {
    if (!s || !p) return false;
    while (*p) { if (*s++ != *p++) return false; }
    return true;
}

static int out_str(wb_out *out, const char *s) {
    if (!out || !out->write) return -1;
    return out->write(out->ctx, s, str_len(s));
}

static char *u64_dec(char *end, unsigned long long v) {
    *end = 0;
    char *p = end;
    do {
        *--p = (char)('0' + (v % 10ull));
        v /= 10ull;
    } while (v);
    return p;
}

static int out_num(wb_out *out, unsigned long long v) {
    char buf[24];
    char *p = u64_dec(buf + sizeof buf - 1, v);
    return out->write(out->ctx, p, str_len(p));
}

static int out_kv(wb_out *out, const char *key, unsigned long long v) {
    if (out_str(out, key) < 0) return -1;
    if (out_num(out, v) < 0) return -1;
    return out_str(out, "\n");
}

/* ---- path policy ---- */

static bool readable(const char *p) {
    return p && (starts_with(p, "ux0:data/") || starts_with(p, "ux0:/VITA-POC/") ||
                 starts_with(p, "ux0:/app/") || starts_with(p, "ux0:data") ||
                 starts_with(p, "ux0:/VITA-POC") || starts_with(p, "ux0:/app"));
}

static bool writable(const char *p) {
    return p && (starts_with(p, "ux0:data/") || starts_with(p, "ux0:/VITA-POC/"));
}

/* ---- commands ---- */

static SceIoDirent g_ent;
static SceIoStat g_stat;

static int cmd_sys(wb_out *out) {
    if (out_str(out, "payload sys version=" WB_PAYLOAD_VERSION "\n") < 0) return -1;
    if (out_kv(out, "payload abi=", (unsigned long long)WB_PAYLOAD_ABI) < 0) return -1;
    if (out_kv(out, "payload uptime_ms=", (unsigned long long)(sceKernelGetProcessTimeWide() / 1000u)) < 0)
        return -1;
    if (out_kv(out, "payload battery=", (unsigned long long)scePowerGetBatteryLifePercent()) < 0) return -1;
    const int temp_raw = scePowerGetBatteryTemp();
    /* VitaSDK reports hundredths of a degree. Do not guess units from the
     * magnitude or convert a negative/unavailable reading to unsigned. */
    if (temp_raw < 0) {
        if (out_str(out, "payload temp_c=unavailable\n") < 0) return -1;
    } else if (out_kv(out, "payload temp_c=", (unsigned)(temp_raw / 100)) < 0) return -1;
    if (out_kv(out, "payload charging=", (unsigned long long)(scePowerIsBatteryCharging() != 0)) < 0) return -1;
    return out_kv(out, "payload online=", (unsigned long long)(scePowerIsPowerOnline() != 0));
}

static int cmd_ls(wb_out *out, const char *dir) {
    if (!readable(dir)) return out_str(out, "ERR path-denied\n");
    const int fd = sceIoDopen(dir);
    if (fd < 0) return out_str(out, "ERR open-failed\n");
    int rc = 0;
    for (;;) {
        /* sceIoDread expects a zeroed SceIoDirent on every call. */
        unsigned char *raw = (unsigned char *)&g_ent;
        for (unsigned i = 0; i < sizeof g_ent; i++) raw[i] = 0;
        const int got = sceIoDread(fd, &g_ent);
        if (got == 0) break; /* only zero is end of directory */
        if (got < 0) {
            (void)out_str(out, "ERR read-failed\n");
            rc = -1; break;
        }
        const char *name = g_ent.d_name;
        unsigned name_len = 0;
        while (name_len < sizeof g_ent.d_name && name[name_len]) name_len++;
        if ((name_len == 1 && name[0] == '.') ||
            (name_len == 2 && name[0] == '.' && name[1] == '.')) continue;
        const bool is_dir = SCE_S_ISDIR(g_ent.d_stat.st_mode) != 0;
        if (out_str(out, is_dir ? "D " : "F ") < 0) { rc = -1; break; }
        if (out->write(out->ctx, name, name_len) < 0) { rc = -1; break; }
        if (!is_dir) {
            if (out_str(out, " ") < 0 || out_num(out, (unsigned long long)g_ent.d_stat.st_size) < 0) {
                rc = -1; break;
            }
        }
        if (out_str(out, "\n") < 0) { rc = -1; break; }
    }
    if (sceIoDclose(fd) < 0 && rc == 0) {
        (void)out_str(out, "ERR close-failed\n");
        rc = -1;
    }
    return rc;
}

static int cmd_stat(wb_out *out, const char *path) {
    if (!readable(path)) return out_str(out, "ERR path-denied\n");
    if (sceIoGetstat(path, &g_stat) < 0) return out_str(out, "ERR not-found\n");
    const bool is_dir = SCE_S_ISDIR(g_stat.st_mode) != 0;
    if (out_str(out, is_dir ? "D " : "F ") < 0) return -1;
    if (out_str(out, path) < 0) return -1;
    if (is_dir) return out_str(out, "\n");
    return out_kv(out, " ", (unsigned long long)g_stat.st_size);
}

static int cmd_rm(wb_out *out, const char *path) {
    if (!writable(path)) return out_str(out, "ERR path-denied\n");
    const int rc = sceIoRemove(path);
    if (rc >= 0) return out_str(out, "OK rm\n");
    if (sceIoRmdir(path) >= 0) return out_str(out, "OK rmdir\n");
    return out_str(out, "ERR rm-failed\n");
}

static int cmd_mv(wb_out *out, const char *from, const char *to) {
    if (!writable(from) || !writable(to)) return out_str(out, "ERR path-denied\n");
    if (sceIoRename(from, to) < 0) return out_str(out, "ERR mv-failed\n");
    return out_str(out, "OK mv\n");
}

static int cmd_mkdir(wb_out *out, const char *path) {
    if (!writable(path)) return out_str(out, "ERR path-denied\n");
    if (sceIoMkdir(path, 0777) < 0) {
        if (sceIoGetstat(path, &g_stat) >= 0 && SCE_S_ISDIR(g_stat.st_mode)) return out_str(out, "OK mkdir (exists)\n");
        return out_str(out, "ERR mkdir-failed\n");
    }
    return out_str(out, "OK mkdir\n");
}

static int ext_dispatch(const char *cmd, int argc, char *const argv[], wb_out *out, void *core) {
    (void)core;
    if (!cmd) return out_str(out, "ERR payload-command\n");
    if (str_eq(cmd, "hello")) return out_str(out, "payload hello version=" WB_PAYLOAD_VERSION "\n");
    if (str_eq(cmd, "features")) return out_str(out, "payload features=sys ls stat rm mv mkdir hello features\n");
    if (str_eq(cmd, "sys")) return cmd_sys(out);
    if (str_eq(cmd, "ls")) {
        if (argc != 1) return out_str(out, "ERR usage: ls <dir>\n");
        return cmd_ls(out, argv[0]);
    }
    if (str_eq(cmd, "stat")) {
        if (argc != 1) return out_str(out, "ERR usage: stat <path>\n");
        return cmd_stat(out, argv[0]);
    }
    if (str_eq(cmd, "rm")) {
        if (argc != 1) return out_str(out, "ERR usage: rm <path>\n");
        return cmd_rm(out, argv[0]);
    }
    if (str_eq(cmd, "mv")) {
        if (argc != 2) return out_str(out, "ERR usage: mv <from> <to>\n");
        return cmd_mv(out, argv[0], argv[1]);
    }
    if (str_eq(cmd, "mkdir")) {
        if (argc != 1) return out_str(out, "ERR usage: mkdir <path>\n");
        return cmd_mkdir(out, argv[0]);
    }
    if (str_eq(cmd, "tick")) {
        return out_kv(out, "payload tick uptime_ms=",
                      (unsigned long long)(sceKernelGetProcessTimeWide() / 1000u));
    }
    if (out_str(out, "ERR payload-unknown ") < 0) return -1;
    if (out_str(out, cmd) < 0) return -1;
    return out_str(out, "\n");
}

static const wb_payload_v1 g_table = {
    .magic = WB_PAYLOAD_MAGIC,
    .abi = WB_PAYLOAD_ABI,
    .size = sizeof(wb_payload_v1),
    .version = WB_PAYLOAD_VERSION,
    .build = __DATE__ " " __TIME__,
    .features = "sys ls stat rm mv mkdir hello features",
    .dispatch = ext_dispatch
};

/* modulemgr passes module_start a *copy* of argp, so writing boot->table never
 * reaches the core. Publish the address instead; the core deletes this file
 * before every load and validates what it reads. */
static void publish_table(const void *table) {
    const int fd = sceIoOpen("ux0:data/INAP00018/payload/table.txt",
                             SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (fd < 0) return;
    char hex[9];
    unsigned long v = (unsigned long)(uintptr_t)table;
    for (int i = 7; i >= 0; i--) { hex[i] = "0123456789ABCDEF"[v & 0xF]; v >>= 4; }
    hex[8] = '\n';
    (void)sceIoWrite(fd, hex, 9);
    (void)sceIoClose(fd);
}

int module_start(SceSize args, void *argp) {
    publish_table(&g_table);
    if (!argp) return 1;
    wb_payload_boot *boot = (wb_payload_boot *)argp;
    boot->seen_args = (uint32_t)args;
    boot->seen_magic = boot->magic;
    boot->seen_abi = boot->abi;
    if (boot->magic != WB_BOOT_MAGIC) { boot->result = 2; return 2; }
    if (boot->abi != WB_PAYLOAD_ABI) { boot->result = 3; return 3; }
    boot->table = &g_table;
    boot->result = 0;
    return 0;
}

int module_stop(SceSize args, void *argp) {
    (void)args; (void)argp;
    return 0;
}

int module_exit(void) {
    return 0;
}
