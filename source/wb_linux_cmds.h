#ifndef WB_LINUX_CMDS_H
#define WB_LINUX_CMDS_H
/* Interactive Linux-style terminal commands for Workbench 02.17+ (02.18: grep, find, hexdump, multi-mount).
 * Strictly obeys existing device read/write path boundaries:
 * - Writes (cp, touch) are confined exclusively to ux0:/VITA-POC with
 *   private staging and no-clobber publication.
 * - Reads (ll, sha256sum, head, tail, du) allow only public projections
 *   (ux0:/VITA-POC, public INAP00018 diag files, game Logs, and read-only
 *   ux0:/app/... for ll/sha256sum/du). Private identity files are always denied.
 */
#include "wb_cmd.h"
#include "wb_err.h"
#include "wb_game_logs_path.h"
#include "wb_out.h"
#include "wb_sha256.h"
#include "wb_ver.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WB_FAST_SHA_UPDATE
#define WB_FAST_SHA_UPDATE(c,p,n) wb_sha256_update((c),(p),(n))
#endif
#ifndef WB_OP_PROGRESS
#define WB_OP_PROGRESS(tag,done,total) ((void)0)
#endif

enum {
    WB_LX_PATH_CAP = 128,
    WB_LX_NAME_CAP = 100,
    WB_LX_DEPTH_MAX = 12,
    WB_LX_LIST_MAX = 16384,
    WB_LX_DU_MAX = 8192,
    WB_LX_TEXT_MAX = 65536
};

enum wb_lx_area {
    WB_LX_BLOCKED = 0,
    WB_LX_ROOT,
    WB_LX_INCOMING,
    WB_LX_DATA,
    WB_LX_DIAG_DIR,
    WB_LX_DIAG_FILE,
    WB_LX_GAME_PARENT,
    WB_LX_GAME_LOGS,
    WB_LX_APP_RO,
    WB_LX_GENERAL
};

static size_t wb_lx_mount(const char *p) {
    if (!strncmp(p, "ux0:/", 5)) return 5;
#ifdef WB_SHELL2
    if (!strncmp(p, "ur0:/", 5)) return 5;
    if (!strncmp(p, "uma0:/", 6)) return 6;
#endif
    return 0;
}

static bool wb_lx_name_ok(const char *s, size_t n) {
    if (!n || n > WB_LX_NAME_CAP || s[0] == '.' || s[0] == ' ' || s[n - 1] == ' ' || s[n - 1] == '.')
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned c = (unsigned char)s[i];
        if (c < 32 || c >= 127 || strchr(":\\\"*?<>|/", (int)c))
            return false;
    }
    return true;
}

static bool wb_lx_diag_rel_ok(const char *rel, bool text_only) {
    if (!strcmp(rel, "run.log") || !strcmp(rel, "startup.log") ||
        !strcmp(rel, "install.log") || !strcmp(rel, "timeline.txt") ||
        !strcmp(rel, "testapp/result.txt"))
        return true;
    return !text_only && !strcmp(rel, "shot.bmp");
}

static enum wb_lx_area wb_lx_area(const char *p) {
    const size_t m = p ? wb_lx_mount(p) : 0;
    if (!m || strlen(p) >= WB_LX_PATH_CAP)
        return WB_LX_BLOCKED;
    if (!p[m]) return WB_LX_ROOT;
    const char *s = p + m;
    unsigned depth = 0;
    for (;;) {
        const char *end = strchr(s, '/');
        size_t n = end ? (size_t)(end - s) : strlen(s);
        if (++depth > WB_LX_DEPTH_MAX || !wb_lx_name_ok(s, n))
            return WB_LX_BLOCKED;
        if (!end) break;
        s = end + 1;
    }
    if (!strcmp(p, "ux0:/VITA-POC") || !strncmp(p, "ux0:/VITA-POC/", 14))
        return WB_LX_INCOMING;
    if (!strcmp(p, "ux0:/app") || !strncmp(p, "ux0:/app/", 9))
        return WB_LX_APP_RO;
    if (!strcmp(p, "ux0:/data"))
        return WB_LX_DATA;
    if (wb_game_data_parent(p))
        return WB_LX_GAME_PARENT;
    if (wb_game_logs_path(p))
        return WB_LX_GAME_LOGS;
    if (!strcmp(p, "ux0:/data/INAP00018"))
        return WB_LX_DIAG_DIR;
    if (!strncmp(p, "ux0:/data/INAP00018/", 20) && wb_lx_diag_rel_ok(p + 20, false))
        return WB_LX_DIAG_FILE;
#ifdef WB_SHELL2
    if (!strncmp(p, "ux0:/data/INAP00018", 19)) return WB_LX_BLOCKED; /* private identity */
    return WB_LX_GENERAL;
#else
    return WB_LX_BLOCKED;
#endif
}

static void wb_lx_native(const char *canon, char dst[WB_LX_PATH_CAP]) {
    if (!strncmp(canon, "ux0:/data", 9) && (!canon[9] || canon[9] == '/')) {
        snprintf(dst, WB_LX_PATH_CAP, "ux0:%s", canon + 5);
    } else {
        snprintf(dst, WB_LX_PATH_CAP, "%s", canon);
    }
}

static void wb_lx_hsize(uint64_t b, char out[24]) {
    if (b < 1024u) {
        snprintf(out, 24, "%" PRIu64 "B", b);
    } else if (b < 1048576u) {
        snprintf(out, 24, "%" PRIu64 ".%uK", b / 1024u, (unsigned)((b % 1024u) * 10u / 1024u));
    } else if (b < UINT64_C(1073741824)) {
        snprintf(out, 24, "%" PRIu64 ".%uM", b / 1048576u, (unsigned)((b % 1048576u) * 10u / 1048576u));
    } else {
        snprintf(out, 24, "%" PRIu64 ".%02uG", b / UINT64_C(1073741824),
                 (unsigned)((b % UINT64_C(1073741824)) * 100u / UINT64_C(1073741824)));
    }
}

static int wb_lx_ll_row(wb_out *out, const char *name, const SceIoStat *st) {
    const bool dir = SCE_S_ISDIR(st->st_mode) != 0;
    char mode[] = "----------";
    mode[0] = dir ? 'd' : '-';
    for (unsigned i = 0; i < 9; i++) {
        if (st->st_mode & (1u << (8u - i))) mode[i + 1] = "rwx"[i % 3];
    }
    char date[32] = "?";
    const unsigned y = st->st_mtime.year, m = st->st_mtime.month, d = st->st_mtime.day;
    const unsigned h = st->st_mtime.hour, mi = st->st_mtime.minute;
    if (y >= 1980 && y <= 9999 && m >= 1 && m <= 12 && d >= 1 && d <= 31 && h <= 23 && mi <= 59)
        snprintf(date, sizeof date, "%04u-%02u-%02u %02u:%02u", y, m, d, h, mi);
    char sz[24] = "-";
    if (!dir && st->st_size >= 0) wb_lx_hsize((uint64_t)st->st_size, sz);
    return wb_out_printf(out, "%s %8s %-16s %s%s\n", mode, sz, date, name, dir ? "/" : "");
}

static int wb_lx_ll(const char *canon, wb_out *out, int *status) {
    const enum wb_lx_area area = wb_lx_area(canon);
    if (area == WB_LX_BLOCKED) {
        *status = 1;
        return wb_out_puts(out, "ERR access denied\n");
    }
    char nat[WB_LX_PATH_CAP];
    wb_lx_native(canon, nat);
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (area != WB_LX_ROOT) {
        if (sceIoGetstat(nat, &st) < 0) {
            *status = 1;
            return wb_out_puts(out, "ERR not found\n");
        }
        if (!SCE_S_ISDIR(st.st_mode)) {
            if (!SCE_S_ISREG(st.st_mode) || st.st_size < 0) {
                *status = 1;
                return wb_out_puts(out, "ERR access denied\n");
            }
            const char *leaf = strrchr(canon, '/');
            return wb_lx_ll_row(out, leaf ? leaf + 1 : canon, &st);
        }
    }
    const int fd = sceIoDopen(nat);
    if (fd < 0) {
        *status = 1;
        return wb_out_puts(out, "ERR open-failed\n");
    }
    unsigned files = 0, dirs = 0, seen = 0;
    uint64_t total_bytes = 0;
    int rc = WB_OK;
    while (seen < WB_LX_LIST_MAX) {
        SceIoDirent ent;
        memset(&ent, 0, sizeof ent);
        const int n = sceIoDread(fd, &ent);
        if (n < 0) { rc = WB_E_IO; break; }
        if (n == 0) break;
        const char *nul = memchr(ent.d_name, 0, sizeof ent.d_name);
        if (!nul) continue;
        const size_t nlen = (size_t)(nul - ent.d_name);
        if (!wb_lx_name_ok(ent.d_name, nlen)) continue;
        char child[WB_LX_PATH_CAP];
        const int z = snprintf(child, sizeof child, "%s%s%s", canon, area == WB_LX_ROOT ? "" : "/", ent.d_name);
        if (z < 0 || (size_t)z >= sizeof child) continue;
        if (wb_lx_area(child) == WB_LX_BLOCKED) continue;
        const bool is_dir = SCE_S_ISDIR(ent.d_stat.st_mode) != 0;
        const bool is_reg = SCE_S_ISREG(ent.d_stat.st_mode) && ent.d_stat.st_size >= 0;
        if (!is_dir && !is_reg) continue;
        if (wb_lx_ll_row(out, ent.d_name, &ent.d_stat) < 0) { rc = WB_E_IO; break; }
        if (is_dir) dirs++;
        else { files++; total_bytes += (uint64_t)ent.d_stat.st_size; }
        seen++;
    }
    if (sceIoDclose(fd) < 0 && rc == WB_OK) rc = WB_E_IO;
    if (rc != WB_OK) {
        *status = 1;
        return wb_out_puts(out, "ERR directory read failed\n");
    }
    char htot[24];
    wb_lx_hsize(total_bytes, htot);
    return wb_out_printf(out, "total %u files, %u dirs, %s (%" PRIu64 " B)%s\n",
                         files, dirs, htot, total_bytes, seen >= WB_LX_LIST_MAX ? " [truncated]" : "");
}

static bool wb_lx_readable_file(const char *canon, bool text_only) {
    const enum wb_lx_area a = wb_lx_area(canon);
    if (a == WB_LX_INCOMING) return strcmp(canon, "ux0:/VITA-POC") != 0;
    if (a == WB_LX_DIAG_FILE) return wb_lx_diag_rel_ok(canon + 20, text_only);
    if (a == WB_LX_GAME_LOGS) return !wb_game_logs_exact(canon);
    if (!text_only && a == WB_LX_APP_RO) return strcmp(canon, "ux0:/app") != 0;
    if (a == WB_LX_GENERAL) return true;
    return false;
}

static int wb_lx_sha256sum(const wb_cmd *cmd, wb_out *out, int *status) {
#ifdef __vita__
    const size_t chunk_cap = 262144u;
#else
    const size_t chunk_cap = 65536u;
#endif
    uint8_t *buf = (uint8_t *)malloc(chunk_cap);
    size_t cap = chunk_cap;
    if (!buf) { cap = 16384u; buf = (uint8_t *)malloc(cap); }
    if (!buf) { *status = 1; return wb_out_puts(out, "ERR nomem\n"); }
    int any_err = 0;
    for (int i = 0; i < cmd->argc; i++) {
        const char *canon = cmd->argv[i];
        if (!wb_lx_readable_file(canon, false)) {
            any_err = 1;
            if (wb_out_printf(out, "ERR sha256sum access-denied %s\n", canon) < 0) { free(buf); return WB_E_IO; }
            continue;
        }
        char nat[WB_LX_PATH_CAP];
        wb_lx_native(canon, nat);
        SceIoStat st;
        memset(&st, 0, sizeof st);
        if (sceIoGetstat(nat, &st) < 0 || !SCE_S_ISREG(st.st_mode) || st.st_size < 0) {
            any_err = 1;
            if (wb_out_printf(out, "ERR sha256sum not-a-file %s\n", canon) < 0) { free(buf); return WB_E_IO; }
            continue;
        }
        const int fd = sceIoOpen(nat, SCE_O_RDONLY, 0);
        if (fd < 0) {
            any_err = 1;
            if (wb_out_printf(out, "ERR sha256sum open-failed %s\n", canon) < 0) { free(buf); return WB_E_IO; }
            continue;
        }
        wb_sha256 sha;
        wb_sha256_init(&sha);
        bool io_ok = true;
        for (;;) {
            const int n = sceIoRead(fd, buf, (SceSize)cap);
            if (n < 0 || (size_t)n > cap) { io_ok = false; break; }
            if (n == 0) break;
            WB_FAST_SHA_UPDATE(&sha, buf, (size_t)n);
        }
        if (sceIoClose(fd) < 0) io_ok = false;
        if (!io_ok) {
            any_err = 1;
            if (wb_out_printf(out, "ERR sha256sum read-failed %s\n", canon) < 0) { free(buf); return WB_E_IO; }
            continue;
        }
        uint8_t raw[32];
        char digest[65];
        wb_sha256_final(&sha, raw);
        wb_sha_hex(raw, sizeof raw, digest);
        if (wb_out_printf(out, "%s  %s\n", digest, canon) < 0) { free(buf); return WB_E_IO; }
    }
    free(buf);
    if (any_err) *status = 1;
    return WB_OK;
}

static int wb_lx_emit_sanitized(wb_out *out, const uint8_t *buf, size_t len) {
    char tmp[256];
    size_t u = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned c = buf[i];
        if (c == '\r') continue;
        tmp[u++] = (c == '\n' || c == '\t' || (c >= 32 && c < 127)) ? (char)c : '?';
        if (u == sizeof tmp) {
            if (out->write(out->ctx, tmp, u) < 0) return WB_E_IO;
            u = 0;
        }
    }
    if (u && out->write(out->ctx, tmp, u) < 0) return WB_E_IO;
    if (len && buf[len - 1] != '\n' && out->write(out->ctx, "\n", 1) < 0) return WB_E_IO;
    return WB_OK;
}

static int wb_lx_head_tail(const char *canon, unsigned max_lines, bool is_tail, wb_out *out, int *status) {
    if (!wb_lx_readable_file(canon, true)) {
        *status = 1;
        return wb_out_puts(out, "ERR access denied\n");
    }
    char nat[WB_LX_PATH_CAP];
    wb_lx_native(canon, nat);
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (sceIoGetstat(nat, &st) < 0 || !SCE_S_ISREG(st.st_mode) || st.st_size < 0) {
        *status = 1;
        return wb_out_puts(out, "ERR not a regular file\n");
    }
    const uint64_t fsize = (uint64_t)st.st_size;
    if (fsize == 0) return WB_OK;
    const size_t window = fsize > WB_LX_TEXT_MAX ? WB_LX_TEXT_MAX : (size_t)fsize;
    uint8_t *buf = (uint8_t *)malloc(window);
    if (!buf) { *status = 1; return wb_out_puts(out, "ERR nomem\n"); }
    const int fd = sceIoOpen(nat, SCE_O_RDONLY, 0);
    if (fd < 0) { free(buf); *status = 1; return wb_out_puts(out, "ERR open-failed\n"); }
    bool ok = true;
    if (is_tail && fsize > window) {
        const SceOff start_off = (SceOff)(fsize - window);
        if (sceIoLseek(fd, start_off, SCE_SEEK_SET) != start_off) ok = false;
    }
    size_t got = 0;
    while (ok && got < window) {
        const int n = sceIoRead(fd, buf + got, (SceSize)(window - got));
        if (n < 0 || (size_t)n > window - got) { ok = false; break; }
        if (n == 0) break;
        got += (size_t)n;
    }
    if (sceIoClose(fd) < 0) ok = false;
    if (!ok) { free(buf); *status = 1; return wb_out_puts(out, "ERR read-failed\n"); }
    if (memchr(buf, 0, got) != NULL) {
        free(buf);
        *status = 1;
        return wb_out_puts(out, "ERR binary file; use sha256sum or get\n");
    }
    size_t start = 0, len = got;
    if (!is_tail) {
        unsigned lines = 0;
        size_t pos = 0;
        while (pos < got && lines < max_lines) {
            if (buf[pos++] == '\n') lines++;
        }
        len = pos;
    } else {
        size_t pos = got;
        if (pos > 0 && buf[pos - 1] == '\n') pos--;
        unsigned lines = 0;
        while (pos > 0) {
            if (buf[pos - 1] == '\n') {
                if (++lines >= max_lines) break;
            }
            pos--;
        }
        start = pos;
        len = got - start;
    }
    const int rc = wb_lx_emit_sanitized(out, buf + start, len);
    free(buf);
    return rc;
}

typedef struct {
    uint64_t bytes;
    unsigned files, dirs, visited;
    bool truncated;
} wb_lx_du_acc;

static void wb_lx_du_walk(const char *canon, unsigned depth, wb_lx_du_acc *acc) {
    if (depth > WB_LX_DEPTH_MAX || acc->visited >= WB_LX_DU_MAX) {
        acc->truncated = true;
        return;
    }
    char nat[WB_LX_PATH_CAP];
    wb_lx_native(canon, nat);
    const int fd = sceIoDopen(nat);
    if (fd < 0) return;
    for (;;) {
        if (acc->visited >= WB_LX_DU_MAX) { acc->truncated = true; break; }
        SceIoDirent ent;
        memset(&ent, 0, sizeof ent);
        const int n = sceIoDread(fd, &ent);
        if (n <= 0) break;
        const char *nul = memchr(ent.d_name, 0, sizeof ent.d_name);
        if (!nul) continue;
        if (!wb_lx_name_ok(ent.d_name, (size_t)(nul - ent.d_name))) continue;
        char child[WB_LX_PATH_CAP];
        const int z = snprintf(child, sizeof child, "%s/%s", canon, ent.d_name);
        if (z < 0 || (size_t)z >= sizeof child) continue;
        if (wb_lx_area(child) == WB_LX_BLOCKED) continue;
        acc->visited++;
        if (SCE_S_ISDIR(ent.d_stat.st_mode)) {
            acc->dirs++;
            wb_lx_du_walk(child, depth + 1, acc);
        } else if (SCE_S_ISREG(ent.d_stat.st_mode) && ent.d_stat.st_size >= 0) {
            acc->files++;
            acc->bytes += (uint64_t)ent.d_stat.st_size;
        }
    }
    (void)sceIoDclose(fd);
}

static int wb_lx_du(const char *canon, bool human, wb_out *out, int *status) {
    const enum wb_lx_area area = wb_lx_area(canon);
    if (area != WB_LX_INCOMING && area != WB_LX_APP_RO && area != WB_LX_GENERAL &&
        area != WB_LX_GAME_LOGS && area != WB_LX_DIAG_DIR && area != WB_LX_DIAG_FILE) {
        *status = 1;
        return wb_out_puts(out, "ERR du allowed on /inbox, ux0:/app/*, diag, or game Logs\n");
    }
    char nat[WB_LX_PATH_CAP];
    wb_lx_native(canon, nat);
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (sceIoGetstat(nat, &st) < 0) {
        *status = 1;
        return wb_out_puts(out, "ERR not found\n");
    }
    wb_lx_du_acc acc;
    memset(&acc, 0, sizeof acc);
    if (SCE_S_ISDIR(st.st_mode)) {
        wb_lx_du_walk(canon, 0, &acc);
    } else if (SCE_S_ISREG(st.st_mode) && st.st_size >= 0) {
        acc.files = 1;
        acc.bytes = (uint64_t)st.st_size;
    } else {
        *status = 1;
        return wb_out_puts(out, "ERR access denied\n");
    }
    if (human) {
        char h[24];
        wb_lx_hsize(acc.bytes, h);
        return wb_out_printf(out, "%s\t%s (%u files, %u dirs)%s\n",
                             h, canon, acc.files, acc.dirs, acc.truncated ? " [truncated]" : "");
    }
    return wb_out_printf(out, "%" PRIu64 "\t%s\n", acc.bytes, canon);
}

#ifndef WB_LINUX_HOST_MOCK
static int wb_lx_touch(const char *canon, wb_out *out, int *status) {
    if (!tty_path(canon) || !tty_parent(canon)) {
        *status = 1;
        return wb_out_puts(out, "ERR touch path-denied\n");
    }
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (sceIoGetstat(canon, &st) >= 0) {
        if (SCE_S_ISREG(st.st_mode))
            return wb_out_printf(out, "OK touch (exists) %s\n", canon);
        *status = 1;
        return wb_out_puts(out, "ERR touch destination-is-not-file\n");
    }
    if (!tty_noreplace()) {
        *status = 1;
        return wb_out_puts(out, "ERR touch no-clobber-unavailable\n");
    }
    char stage[128];
    if (!tty_private_name(stage)) {
        *status = 1;
        return wb_out_puts(out, "ERR touch stage-name\n");
    }
    const int fd = open_staging(stage, NULL);
    if (fd < 0) {
        *status = 1;
        return wb_out_puts(out, "ERR touch stage-open\n");
    }
    const int s_rc = sceIoSyncByFd(fd, 0);
    const int c_rc = sceIoClose(fd);
    if (s_rc < 0 || c_rc < 0 || !tty_nofile(canon) || sceIoRename(stage, canon) < 0) {
        (void)sceIoRemove(stage);
        *status = 1;
        return wb_out_puts(out, "ERR touch publish-failed\n");
    }
    return wb_out_printf(out, "OK touch %s\n", canon);
}

static int wb_lx_cp(const char *src, const char *dst_in, wb_out *out, int *status) {
    if (!tty_path(src)) {
        *status = 1;
        return wb_out_puts(out, "ERR cp source path-denied\n");
    }
    SceIoStat sst;
    memset(&sst, 0, sizeof sst);
    if (sceIoGetstat(src, &sst) < 0 || !SCE_S_ISREG(sst.st_mode) || sst.st_size < 0) {
        *status = 1;
        return wb_out_puts(out, "ERR cp source not-a-file\n");
    }
    char dst[WB_LX_PATH_CAP];
    SceIoStat dst_st;
    memset(&dst_st, 0, sizeof dst_st);
    if (sceIoGetstat(dst_in, &dst_st) >= 0 && SCE_S_ISDIR(dst_st.st_mode)) {
        const char *leaf = strrchr(src, '/');
        if (!leaf || !leaf[1]) { *status = 1; return wb_out_puts(out, "ERR cp invalid-source\n"); }
        const int z = snprintf(dst, sizeof dst, "%s/%s", dst_in, leaf + 1);
        if (z < 0 || (size_t)z >= sizeof dst) { *status = 1; return wb_out_puts(out, "ERR cp path-too-long\n"); }
    } else {
        snprintf(dst, sizeof dst, "%s", dst_in);
    }
    if (!tty_path(dst) || !tty_parent(dst)) {
        *status = 1;
        return wb_out_puts(out, "ERR cp destination path-denied\n");
    }
    if (!tty_nofile(dst)) {
        *status = 1;
        return wb_out_puts(out, "ERR cp destination-exists (no-clobber)\n");
    }
    if (!tty_noreplace()) {
        *status = 1;
        return wb_out_puts(out, "ERR cp no-clobber-unavailable\n");
    }
    const uint64_t fsize = (uint64_t)sst.st_size;
    if (fsize > WB_TRANSFER_MAX) {
        *status = 1;
        return wb_out_puts(out, "ERR cp file-too-large\n");
    }
    if (wb_ux0_budget(fsize + 65536u, out, false) != WB_OK) {
        *status = 1;
        return WB_OK;
    }
    char stage[128];
    if (!tty_private_name(stage)) {
        *status = 1;
        return wb_out_puts(out, "ERR cp stage-name\n");
    }
    const int sfd = sceIoOpen(src, SCE_O_RDONLY, 0);
    if (sfd < 0) { *status = 1; return wb_out_puts(out, "ERR cp open-source\n"); }
    const int dfd = open_staging(stage, NULL);
    if (dfd < 0) { (void)sceIoClose(sfd); *status = 1; return wb_out_puts(out, "ERR cp open-stage\n"); }
    size_t cap = 262144u;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { cap = 32768u; buf = (uint8_t *)malloc(cap); }
    if (!buf) {
        (void)sceIoClose(sfd); (void)sceIoClose(dfd); (void)sceIoRemove(stage);
        *status = 1;
        return wb_out_puts(out, "ERR nomem\n");
    }
    wb_sha256 sha;
    wb_sha256_init(&sha);
    uint64_t copied = 0;
    bool ok = true;
    WB_OP_PROGRESS("COPY", 0, fsize);
    while (copied < fsize) {
        const size_t want = (fsize - copied) < cap ? (size_t)(fsize - copied) : cap;
        const int nr = sceIoRead(sfd, buf, (SceSize)want);
        if (nr <= 0 || (size_t)nr > want) { ok = false; break; }
        for (size_t off = 0; off < (size_t)nr;) {
            const int nw = sceIoWrite(dfd, buf + off, (SceSize)((size_t)nr - off));
            if (nw <= 0 || (size_t)nw > (size_t)nr - off) { ok = false; break; }
            off += (size_t)nw;
        }
        if (!ok) break;
        WB_FAST_SHA_UPDATE(&sha, buf, (size_t)nr);
        copied += (uint64_t)nr;
        WB_OP_PROGRESS("COPY", copied, fsize);
    }
    free(buf);
    if (sceIoClose(sfd) < 0) ok = false;
    if (ok && sceIoSyncByFd(dfd, 0) < 0) ok = false;
    if (sceIoClose(dfd) < 0) ok = false;
    if (!ok || copied != fsize || !tty_nofile(dst) || sceIoRename(stage, dst) < 0) {
        (void)sceIoRemove(stage);
        *status = 1;
        return wb_out_puts(out, "ERR cp failed\n");
    }
    uint8_t raw[32];
    char digest[65];
    wb_sha256_final(&sha, raw);
    wb_sha_hex(raw, sizeof raw, digest);
    return wb_out_printf(out, "OK cp bytes=%" PRIu64 " sha256=%s dst=%s\n", copied, digest, dst);
}
#endif

static int wb_lx_free(bool human, wb_out *out, int *status) {
    SceKernelFreeMemorySizeInfo mi;
    memset(&mi, 0, sizeof mi);
    mi.size = (int)sizeof mi;
    const int mrc = sceKernelGetFreeMemorySize(&mi);
    uint64_t total = 0, avail = 0;
    const int drc = sceAppMgrGetDevInfo("ux0:", &total, &avail);
    if (mrc < 0 && drc < 0) {
        *status = 1;
        return wb_out_puts(out, "ERR memory/storage info unavailable\n");
    }
    if (human) {
        if (wb_out_puts(out, "Resource       Free        Total\n") < 0) return WB_E_IO;
        if (mrc >= 0) {
            char hu[24], hc[24], hp[24];
            wb_lx_hsize(mi.size_user > 0 ? (uint64_t)mi.size_user : 0u, hu);
            wb_lx_hsize(mi.size_cdram > 0 ? (uint64_t)mi.size_cdram : 0u, hc);
            wb_lx_hsize(mi.size_phycont > 0 ? (uint64_t)mi.size_phycont : 0u, hp);
            if (wb_out_printf(out, "Mem (user)   %10s       -\nCDRAM        %10s       -\nPhyCont      %10s       -\n",
                              hu, hc, hp) < 0) return WB_E_IO;
        }
        if (drc >= 0 && total >= avail) {
            char ha[24], ht[24];
            wb_lx_hsize(avail, ha);
            wb_lx_hsize(total, ht);
            if (wb_out_printf(out, "ux0:         %10s %10s\n", ha, ht) < 0) return WB_E_IO;
        }
        return WB_OK;
    }
    if (wb_out_puts(out, "Resource     Free(KiB)   Total(KiB)\n") < 0) return WB_E_IO;
    if (mrc >= 0) {
        if (wb_out_printf(out, "Mem (user)   %10u       -\nCDRAM        %10u       -\nPhyCont      %10u       -\n",
                          mi.size_user > 0 ? (unsigned)(mi.size_user / 1024) : 0u,
                          mi.size_cdram > 0 ? (unsigned)(mi.size_cdram / 1024) : 0u,
                          mi.size_phycont > 0 ? (unsigned)(mi.size_phycont / 1024) : 0u) < 0)
            return WB_E_IO;
    }
    if (drc >= 0 && total >= avail) {
        if (wb_out_printf(out, "ux0:         %10" PRIu64 " %10" PRIu64 "\n",
                          avail / 1024u, total / 1024u) < 0) return WB_E_IO;
    }
    return WB_OK;
}

static int wb_lx_grep(const wb_cmd *cmd, wb_out *out, int *status) {
    const char *flags = cmd->argv[0], *pat = cmd->argv[1];
    const bool icase = strchr(flags, 'i') != NULL, inv = strchr(flags, 'v') != NULL;
    const bool num = strchr(flags, 'n') != NULL, count = strchr(flags, 'c') != NULL;
    const bool multi = cmd->argc > 3;
    const size_t plen = strlen(pat);
    uint8_t *buf = (uint8_t *)malloc(65536);
    char *line = (char *)malloc(2048);
    if (!buf || !line) { free(buf); free(line); *status = 1; return wb_out_puts(out, "ERR nomem\n"); }
    unsigned printed = 0;
    bool any = false, truncated = false;
    for (int f = 2; f < cmd->argc && !truncated; f++) {
        const char *canon = cmd->argv[f];
        if (!wb_lx_readable_file(canon, false)) {
            if (wb_out_printf(out, "ERR grep access-denied %s\n", canon) < 0) goto io;
            continue;
        }
        char nat[WB_LX_PATH_CAP];
        wb_lx_native(canon, nat);
        const int fd = sceIoOpen(nat, SCE_O_RDONLY, 0);
        if (fd < 0) { if (wb_out_printf(out, "ERR grep cannot open %s\n", canon) < 0) goto io; continue; }
        size_t ln = 0;
        unsigned lineno = 1, hits = 0;
        bool binary = false, stop = false, eof = false;
        for (;;) {
            int n = sceIoRead(fd, buf, 65536);
            if (n <= 0) {
                if (ln && !eof) { buf[0] = '\n'; n = 1; eof = true; } /* last line without newline */
                else break;
            }
            for (int i = 0; i <= n && !stop; i++) {
                const bool eol = (i == n) ? false : buf[i] == '\n';
                if (i < n && !eol) {
                    if (!buf[i]) binary = true;
                    if (ln < 2047) line[ln++] = (char)buf[i];
                    continue;
                }
                if (i == n) break;
                while (ln && line[ln - 1] == '\r') ln--;
                bool hit = !plen;
                for (size_t k = 0; !hit && k + plen <= ln; k++) {
                    size_t j = 0;
                    while (j < plen) {
                        char a = line[k + j], b = pat[j];
                        if (icase) { if (a >= 'A' && a <= 'Z') a = (char)(a + 32); if (b >= 'A' && b <= 'Z') b = (char)(b + 32); }
                        if (a != b) break;
                        j++;
                    }
                    hit = j == plen;
                }
                if (hit != inv) {
                    hits++; any = true;
                    if (binary) { stop = true; break; }
                    if (!count) {
                        for (size_t k = 0; k < ln; k++) {
                            const unsigned c = (unsigned char)line[k];
                            if (c != '\t' && (c < 32 || c >= 127)) line[k] = '?';
                        }
                        line[ln] = 0;
                        int rc;
                        if (multi && num) rc = wb_out_printf(out, "%s:%u:%s\n", canon, lineno, line);
                        else if (multi) rc = wb_out_printf(out, "%s:%s\n", canon, line);
                        else if (num) rc = wb_out_printf(out, "%u:%s\n", lineno, line);
                        else rc = wb_out_printf(out, "%s\n", line);
                        if (rc < 0) { (void)sceIoClose(fd); goto io; }
                        if (++printed >= 5000) { truncated = true; stop = true; break; }
                    }
                }
                ln = 0; lineno++;
            }
            if (stop || eof) break;
        }
        (void)sceIoClose(fd);
        if (binary && hits) { if (wb_out_printf(out, "Binary file %s matches\n", canon) < 0) goto io; }
        else if (count) {
            if ((multi ? wb_out_printf(out, "%s:%u\n", canon, hits) : wb_out_printf(out, "%u\n", hits)) < 0) goto io;
        }
    }
    free(buf); free(line);
    if (truncated) (void)wb_out_puts(out, "... [grep output truncated at 5000 lines]\n");
    if (!any) *status = 1;
    return WB_OK;
io:
    free(buf); free(line);
    return WB_E_IO;
}

static bool wb_lx_glob(const char *p, const char *s) {
    while (*p) {
        if (*p == '*') {
            while (*p == '*') p++;
            if (!*p) return true;
            for (; *s; s++) if (wb_lx_glob(p, s)) return true;
            return false;
        }
        char a = *p, b = *s;
        if (!b) return false;
        if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
        if (*p != '?' && a != b) return false;
        p++; s++;
    }
    return !*s;
}

typedef struct { const char *pat; char type; unsigned hits, visited; bool truncated; int io; } wb_lx_find_ctx;
static void wb_lx_find_walk(const char *canon, unsigned depth, wb_lx_find_ctx *fc, wb_out *out) {
    if (fc->io || fc->truncated) return;
    if (depth > WB_LX_DEPTH_MAX) return;
    char nat[WB_LX_PATH_CAP];
    wb_lx_native(canon, nat);
    const int fd = sceIoDopen(nat);
    if (fd < 0) return;
    const bool root = wb_lx_area(canon) == WB_LX_ROOT;
    for (;;) {
        if (fc->hits >= 4000 || fc->visited >= 20000) { fc->truncated = true; break; }
        SceIoDirent ent;
        memset(&ent, 0, sizeof ent);
        if (sceIoDread(fd, &ent) <= 0) break;
        const char *nul = memchr(ent.d_name, 0, sizeof ent.d_name);
        if (!nul || !wb_lx_name_ok(ent.d_name, (size_t)(nul - ent.d_name))) continue;
        char child[WB_LX_PATH_CAP];
        const int z = snprintf(child, sizeof child, "%s%s%s", canon, root ? "" : "/", ent.d_name);
        if (z < 0 || (size_t)z >= sizeof child || wb_lx_area(child) == WB_LX_BLOCKED) continue;
        fc->visited++;
        const bool dir = SCE_S_ISDIR(ent.d_stat.st_mode) != 0;
        if ((fc->type == 'a' || (fc->type == 'd') == dir) && wb_lx_glob(fc->pat, ent.d_name)) {
            if (wb_out_printf(out, "%s%s\n", child, dir ? "/" : "") < 0) { fc->io = 1; break; }
            fc->hits++;
        }
        if (dir) wb_lx_find_walk(child, depth + 1, fc, out);
        if (fc->io) break;
    }
    (void)sceIoDclose(fd);
}
static int wb_lx_find(const wb_cmd *cmd, wb_out *out, int *status) {
    const char *canon = cmd->argv[0];
    if (wb_lx_area(canon) == WB_LX_BLOCKED) { *status = 1; return wb_out_puts(out, "ERR access denied\n"); }
    wb_lx_find_ctx fc = { cmd->argv[1], cmd->argv[2][0], 0, 0, false, 0 };
    wb_lx_find_walk(canon, 0, &fc, out);
    if (fc.io) return WB_E_IO;
    if (fc.truncated) (void)wb_out_puts(out, "... [find truncated]\n");
    if (!fc.hits) *status = 1;
    return wb_out_printf(out, "find: %u match%s\n", fc.hits, fc.hits == 1 ? "" : "es");
}

static int wb_lx_hexdump(const char *canon, const char *count, wb_out *out, int *status) {
    unsigned want = 0;
    for (const char *p = count; *p; p++) want = want * 10u + (unsigned)(*p - '0');
    if (want < 1 || want > 4096) want = 256;
    if (!wb_lx_readable_file(canon, false)) { *status = 1; return wb_out_puts(out, "ERR access denied\n"); }
    char nat[WB_LX_PATH_CAP];
    wb_lx_native(canon, nat);
    const int fd = sceIoOpen(nat, SCE_O_RDONLY, 0);
    if (fd < 0) { *status = 1; return wb_out_puts(out, "ERR open-failed\n"); }
    uint8_t buf[4096];
    size_t got = 0;
    while (got < want) {
        const int n = sceIoRead(fd, buf + got, (SceSize)(want - got));
        if (n <= 0) break;
        got += (size_t)n;
    }
    (void)sceIoClose(fd);
    static const char hx[] = "0123456789abcdef";
    for (size_t off = 0; off < got; off += 16) {
        char row[96];
        size_t w = (size_t)snprintf(row, sizeof row, "%08x  ", (unsigned)off);
        for (size_t i = 0; i < 16; i++) {
            if (off + i < got) { row[w++] = hx[buf[off + i] >> 4]; row[w++] = hx[buf[off + i] & 15]; row[w++] = ' '; }
            else { row[w++] = ' '; row[w++] = ' '; row[w++] = ' '; }
            if (i == 7) row[w++] = ' ';
        }
        row[w++] = ' '; row[w++] = '|';
        for (size_t i = 0; i < 16 && off + i < got; i++) {
            const uint8_t c = buf[off + i];
            row[w++] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        row[w++] = '|'; row[w++] = '\n';
        if (out->write(out->ctx, row, w) < 0) return WB_E_IO;
    }
    return wb_out_printf(out, "%08x\n", (unsigned)got);
}

static int wb_linux_command(const wb_cmd *cmd, const char *ip, wb_out *out, int *status) {
    if (!cmd || !out) { *status = 1; return WB_E_ARG; }
    if (!strcmp(cmd->name, "grep") && cmd->argc >= 3)
        return wb_lx_grep(cmd, out, status);
    if (!strcmp(cmd->name, "find") && cmd->argc == 3)
        return wb_lx_find(cmd, out, status);
    if (!strcmp(cmd->name, "hexdump") && cmd->argc == 2)
        return wb_lx_hexdump(cmd->argv[0], cmd->argv[1], out, status);
    if (!strcmp(cmd->name, "ll") && cmd->argc == 1)
        return wb_lx_ll(cmd->argv[0], out, status);
    if (!strcmp(cmd->name, "sha256sum") && cmd->argc >= 1)
        return wb_lx_sha256sum(cmd, out, status);
    if ((!strcmp(cmd->name, "head") || !strcmp(cmd->name, "tail")) && cmd->argc == 2) {
        unsigned n = 0;
        for (const char *p = cmd->argv[1]; *p; p++) n = n * 10u + (unsigned)(*p - '0');
        if (n < 1 || n > 200) n = 20;
        return wb_lx_head_tail(cmd->argv[0], n, !strcmp(cmd->name, "tail"), out, status);
    }
    if (!strcmp(cmd->name, "du") && cmd->argc == 2)
        return wb_lx_du(cmd->argv[0], cmd->argv[1][0] == 'h', out, status);
#ifndef WB_LINUX_HOST_MOCK
    if (!strcmp(cmd->name, "touch") && cmd->argc == 1)
        return wb_lx_touch(cmd->argv[0], out, status);
    if (!strcmp(cmd->name, "cp") && cmd->argc == 2)
        return wb_lx_cp(cmd->argv[0], cmd->argv[1], out, status);
#endif
    if (!strcmp(cmd->name, "uname")) {
        if (cmd->argc == 1 && !strcmp(cmd->argv[0], "-a"))
            return wb_out_puts(out, "PSVita vita " WB_VERSION " " WB_BUILD_TAG " armv7l Cortex-A9 VitaAgentWorkbench\n");
        return wb_out_puts(out, "PSVita\n");
    }
    if (!strcmp(cmd->name, "whoami"))
        return wb_out_puts(out, WB_USER "\n");
    if (!strcmp(cmd->name, "hostname"))
        return wb_out_printf(out, "%s\n", (ip && ip[0]) ? ip : WB_DEFAULT_IP);
    if (!strcmp(cmd->name, "uptime")) {
        const uint64_t ms = sceKernelGetProcessTimeWide() / 1000u;
        const uint64_t sec = ms / 1000u;
        const int arm = scePowerGetArmClockFrequency();
        const int bus = scePowerGetBusClockFrequency();
        const int bat = scePowerGetBatteryLifePercent();
        const bool chg = scePowerIsBatteryCharging() != 0;
        return wb_out_printf(out, "up %" PRIu64 "h %02" PRIu64 "m %02" PRIu64 "s (%" PRIu64 " ms) arm=%dMHz bus=%dMHz battery=%d%%%s\n",
                             sec / 3600u, (sec % 3600u) / 60u, sec % 60u, ms,
                             arm, bus, bat, chg ? " charging" : "");
    }
    if (!strcmp(cmd->name, "free"))
        return wb_lx_free(cmd->argc == 1 && !strcmp(cmd->argv[0], "-h"), out, status);
    *status = 1;
    return wb_out_puts(out, "ERR unsupported linux command\n");
}
#endif
