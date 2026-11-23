#include "wb_vita_payload.h"

#include "startup.h"

#include "wb_err.h"
#include "wb_str.h"
#include "wb_ver.h"
#include "wb_vita_io.h"

#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/modulemgr.h>

#include <stdio.h>
#include <string.h>

static SceUID g_mod = -1;
static const wb_payload_v1 *g_table;
static char g_version[32] = "none";
static int g_load_rc;
static int g_load_status;
static wb_payload_boot g_last_boot;

void wb_vita_payload_diag(wb_payload_diag *out) {
    if (!out) return;
    out->load_rc = g_load_rc;
    out->load_status = g_load_status;
    out->boot_magic = g_last_boot.magic;
    out->table = g_last_boot.table != NULL;
    out->seen_args = g_last_boot.seen_args;
    out->seen_magic = g_last_boot.seen_magic;
    out->seen_abi = g_last_boot.seen_abi;
    out->payload_result = g_last_boot.result;
}

/* Load a module without touching the globals. Returns the table through
 * table_out so the caller can decide when the switch happens. */
/* The payload publishes its table address in table.txt (argp is copied by
 * modulemgr). The file is deleted before every load, so a stale address from a
 * previous module can never be picked up, and the parsed pointer is validated
 * before it is dereferenced for real. */
static const wb_payload_v1 *table_from_file_strict(void) {
    char buf[16];
    size_t n = 0;
    if (wb_vita_read_small(WB_PAYLOAD_DIR "/table.txt", buf, sizeof buf - 1, &n) != WB_OK) return NULL;
    buf[n] = 0;
    uintptr_t v = 0;
    unsigned digits = 0;
    for (size_t i = 0; i < n; i++) {
        const char c = buf[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else break;
        v = (v << 4) | (uintptr_t)d;
        digits++;
    }
    if (digits < 4 || !v) return NULL;
    const wb_payload_v1 *table = (const wb_payload_v1 *)v;
    return wb_payload_ok(table) ? table : NULL;
}

static int load_module(const char *path, SceUID *mod_out, const wb_payload_v1 **table_out,
                       char *version, size_t cap) {
    wb_payload_boot boot;
    memset(&boot, 0, sizeof boot);
    boot.magic = WB_BOOT_MAGIC;
    boot.abi = WB_PAYLOAD_ABI;
    boot.size = sizeof boot;
    boot.table = NULL;

    int status = 0;
    (void)sceIoRemove(WB_PAYLOAD_DIR "/table.txt");
    SceUID mod = sceKernelLoadStartModule(path, sizeof boot, &boot, 0, NULL, &status);
    g_load_rc = mod;
    g_load_status = status;
    if (mod < 0) {
        int start_status = 0;
        const SceUID m2 = sceKernelLoadModule(path, 0, NULL);
        g_load_rc = m2;
        if (m2 < 0) return WB_E_ABI;
        const int sr = sceKernelStartModule(m2, sizeof boot, &boot, 0, NULL, &start_status);
        g_load_status = sr;
        if (sr < 0) {
            (void)sceKernelUnloadModule(m2, 0, NULL);
            return WB_E_ABI;
        }
        mod = m2;
    }
    if (boot.table == NULL && mod >= 0 && status == 0) boot.table = table_from_file_strict();
    g_last_boot = boot;

    if (boot.magic != WB_BOOT_MAGIC || !wb_payload_ok(boot.table)) {
        (void)sceKernelStopUnloadModule(mod, 0, NULL, 0, NULL, NULL);
        return WB_E_ABI;
    }
    *mod_out = mod;
    *table_out = boot.table;
    if (version) wb_strcpy(version, cap, boot.table->version ? boot.table->version : "?");
    return WB_OK;
}

static void set_live(SceUID mod, const wb_payload_v1 *table) {
    g_mod = mod;
    g_table = table;
    wb_strcpy(g_version, sizeof g_version, table && table->version ? table->version : "none");
    if (table) (void)wb_vita_write_file(WB_PAYLOAD_MARK, g_version, strlen(g_version), false);
}

static int unload(SceUID mod) {
    if (mod < 0) return WB_OK;
    int rc = sceKernelStopUnloadModule(mod, 0, NULL, 0, NULL, NULL);
    if (rc < 0) {
        (void)sceKernelStopModule(mod, 0, NULL, 0, NULL, NULL);
        rc = sceKernelUnloadModule(mod, 0, NULL);
    }
    return rc < 0 ? WB_E_BUSY : WB_OK;
}

void wb_vita_payload_unload(void) {
    (void)unload(g_mod);
    g_mod = -1;
    g_table = NULL;
    wb_strcpy(g_version, sizeof g_version, "none");
}

const wb_payload_v1 *wb_vita_payload_table(void) { return g_table; }
const char *wb_vita_payload_version(void) { return g_version; }

int wb_vita_payload_boot(char *version, size_t cap) {
    const bool confirmed = wb_vita_exists(WB_PAYLOAD_MARK);
    if (confirmed && wb_vita_exists(WB_PAYLOAD_CUR)) {
        SceUID mod = -1;
        const wb_payload_v1 *table = NULL;
        if (load_module(WB_PAYLOAD_CUR, &mod, &table, version, cap) == WB_OK) {
            set_live(mod, table);
            return WB_OK;
        }
    }
    if (wb_vita_exists(WB_PAYLOAD_MARK)) sceIoRemove(WB_PAYLOAD_MARK);
    if (wb_vita_exists(WB_PAYLOAD_CUR)) sceIoRemove(WB_PAYLOAD_CUR);
    if (wb_vita_exists(WB_PAYLOAD_APP)) {
        (void)wb_vita_mkdir_p(WB_PAYLOAD_DIR);
        if (wb_vita_copy_file(WB_PAYLOAD_APP, WB_PAYLOAD_CUR) == WB_OK) {
            SceUID mod = -1;
            const wb_payload_v1 *table = NULL;
            if (load_module(WB_PAYLOAD_CUR, &mod, &table, version, cap) == WB_OK) {
                set_live(mod, table);
                return WB_OK;
            }
        }
    }
    wb_strcpy(g_version, sizeof g_version, "none");
    if (version) wb_strcpy(version, cap, "none");
    return WB_E_ABI;
}

/* Unload, then load, then switch. The previous file is kept until the new
 * module actually runs, so a failed load always has a real file to return to.
 * Every step writes a startup mark: a crash then names its own stage. */
int wb_vita_payload_swap(const char *candidate, char *version, size_t cap) {
    if (!candidate || !wb_vita_exists(candidate)) return WB_E_IO;
    (void)wb_vita_mkdir_p(WB_PAYLOAD_DIR);
    (void)sceIoRemove(WB_PAYLOAD_DIR "/table.txt");

    if (wb_vita_exists(WB_PAYLOAD_PREV)) (void)sceIoRemove(WB_PAYLOAD_PREV);
    if (wb_vita_exists(WB_PAYLOAD_CUR)) (void)sceIoRename(WB_PAYLOAD_CUR, WB_PAYLOAD_PREV);
    startup_mark("SWAP 1 FILES", 0);

    const SceUID old = g_mod;
    g_mod = -1;
    g_table = NULL;
    const int unload_rc = unload(old);
    startup_mark("SWAP 2 UNLOAD", unload_rc);
    if (unload_rc != WB_OK) return WB_E_BUSY;

    SceUID mod = -1;
    const wb_payload_v1 *table = NULL;
    char ver[32] = {0};
    int rc = load_module(candidate, &mod, &table, ver, sizeof ver);
    startup_mark("SWAP 3 LOAD", rc);

    if (rc != WB_OK) {
        if (wb_vita_exists(WB_PAYLOAD_PREV)) {
            SceUID back_mod = -1;
            const wb_payload_v1 *back = NULL;
            char back_ver[32] = {0};
            if (load_module(WB_PAYLOAD_PREV, &back_mod, &back, back_ver, sizeof back_ver) == WB_OK) {
                (void)sceIoRename(WB_PAYLOAD_PREV, WB_PAYLOAD_CUR);
                set_live(back_mod, back);
                startup_mark("SWAP 4 ROLLBACK", 0);
                return WB_E_ABI;
            }
        }
        startup_mark("SWAP 4 ROLLBACK", -1);
        return rc;
    }

    (void)sceIoRename(candidate, WB_PAYLOAD_CUR);
    set_live(mod, table);
    startup_mark("SWAP 5 LIVE", 0);
    if (version) wb_strcpy(version, cap, ver);
    return WB_OK;
}

int wb_vita_payload_reload_previous(char *version, size_t cap) {
    if (!wb_vita_exists(WB_PAYLOAD_PREV)) return WB_E_IO;
    SceUID mod = -1;
    const wb_payload_v1 *table = NULL;
    const int rc = load_module(WB_PAYLOAD_PREV, &mod, &table, version, cap);
    if (rc != WB_OK) return rc;
    (void)unload(g_mod);
    g_mod = -1;
    g_table = NULL;
    if (wb_vita_exists(WB_PAYLOAD_CUR)) (void)sceIoRemove(WB_PAYLOAD_CUR);
    (void)sceIoRename(WB_PAYLOAD_PREV, WB_PAYLOAD_CUR);
    set_live(mod, table);
    return WB_OK;
}
