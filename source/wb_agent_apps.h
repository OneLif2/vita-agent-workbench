#ifndef WB_AGENT_APPS_H
#define WB_AGENT_APPS_H
/* Generic Workbench 2.0 Agent App Management (paired SSH only).
 * Supports:
 * - app list-installed / app ls
 * - app install-vpk <INCOMING.vpk>
 * - app patch-eboot <TITLE_ID> <INCOMING.bin> [--ver XX.YY]
 * - app launch <TITLE_ID>
 * - app uninstall <TITLE_ID>
 * Always refuses INAP00018, INAP00019, NPXS titles and vs0 system titles.
 */
#include "wb_cmd.h"
#include "wb_err.h"
#include "wb_head.h"
#include "wb_out.h"
#include "wb_sfo.h"
#include "wb_sha256.h"
#include "wb_ver.h"
#include "wb_vita_install.h"
#include "wb_vita_io.h"
#include "wb_zip.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WB_OP_PROGRESS
#define WB_OP_PROGRESS(tag,done,total) ((void)0)
#endif

static bool wb_ag_tid_ok(const char *t) {
    if (!t || strlen(t) != 9) return false;
    for (int i = 0; i < 9; i++) {
        char c = t[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return false;
    }
    return true;
}

static bool wb_ag_tid_mutable(const char *t) {
    if (!wb_ag_tid_ok(t)) return false;
    if (!strcmp(t, WB_TITLE_ID) || !strcmp(t, WB_UPDATER_TITLE_ID) || !strncmp(t, "NPXS", 4))
        return false;
    char sp[64];
    snprintf(sp, sizeof sp, "vs0:/app/%.9s", t);
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (sceIoGetstat(sp, &st) >= 0) return false;
    return true;
}

static bool wb_ag_ver_ok(const char *v) {
    return v && strlen(v) == 5 && v[2] == '.' &&
           v[0] >= '0' && v[0] <= '9' && v[1] >= '0' && v[1] <= '9' &&
           v[3] >= '0' && v[3] <= '9' && v[4] >= '0' && v[4] <= '9';
}

static uint32_t wb_ag_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t wb_ag_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint64_t wb_ag_le64(const uint8_t *p) {
    return (uint64_t)wb_ag_le32(p) | ((uint64_t)wb_ag_le32(p + 4) << 32);
}

static int wb_ag_list_installed(wb_out *out, int *status) {
    const int fd = sceIoDopen("ux0:/app");
    if (fd < 0) { *status = 1; return wb_out_puts(out, "ERR cannot open ux0:/app\n"); }
    unsigned count = 0;
    for (;;) {
        SceIoDirent ent;
        memset(&ent, 0, sizeof ent);
        const int n = sceIoDread(fd, &ent);
        if (n <= 0) break;
        if (!SCE_S_ISDIR(ent.d_stat.st_mode)) continue;
        if (!wb_ag_tid_ok(ent.d_name)) continue;
        char sfo_path[96];
        snprintf(sfo_path, sizeof sfo_path, "ux0:/app/%.9s/sce_sys/param.sfo", ent.d_name);
        uint8_t sfo_buf[8192];
        size_t sfo_n = 0;
        char ver[16] = "?", title[96] = "?";
        if (wb_vita_read_small(sfo_path, sfo_buf, sizeof sfo_buf, &sfo_n) == WB_OK) {
            wb_sfo s;
            if (wb_sfo_parse(&s, sfo_buf, sfo_n) == WB_OK) {
                (void)wb_sfo_get(&s, "APP_VER", ver, sizeof ver);
                (void)wb_sfo_get(&s, "TITLE", title, sizeof title);
                for (char *p = title; *p; p++) if ((unsigned char)*p < 32 || (unsigned char)*p >= 127) *p = ' ';
            }
        }
        if (wb_out_printf(out, "installed title=%s app_ver=%s name=%s\n", ent.d_name, ver, title) < 0) {
            (void)sceIoDclose(fd);
            return WB_E_IO;
        }
        count++;
    }
    (void)sceIoDclose(fd);
    return wb_out_printf(out, "OK app-list-installed count=%u\n", count);
}

static bool wb_ag_check_self_file(const char *path) {
    const int fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) return false;
    uint8_t hdr[256];
    const int n = sceIoRead(fd, hdr, sizeof hdr);
    if (n < 0x90 || memcmp(hdr, "SCE\0", 4) != 0) { (void)sceIoClose(fd); return false; }
    const uint64_t elf_off = wb_ag_le64(hdr + 0x40);
    bool ok = false;
    if (elf_off <= UINT64_C(65536)) {
        uint8_t elf[24];
        if (sceIoLseek(fd, (SceOff)elf_off, SCE_SEEK_SET) == (SceOff)elf_off &&
            sceIoRead(fd, elf, sizeof elf) == (int)sizeof elf) {
            ok = memcmp(elf, "\x7f" "ELF\x01\x01\x01", 7) == 0 && wb_ag_le16(elf + 18) == 40u;
        }
    }
    (void)sceIoClose(fd);
    return ok;
}

static int wb_ag_copy_and_hash(const char *src, const char *dst, uint64_t *bytes_out, char hex_out[65]) {
    SceIoStat sst;
    memset(&sst, 0, sizeof sst);
    const uint64_t src_size = (sceIoGetstat(src, &sst) >= 0 && sst.st_size > 0) ? (uint64_t)sst.st_size : 0u;
    const int sfd = sceIoOpen(src, SCE_O_RDONLY, 0);
    if (sfd < 0) return WB_E_IO;
    const int dfd = sceIoOpen(dst, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (dfd < 0) { (void)sceIoClose(sfd); return WB_E_IO; }
    size_t cap = 262144u;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { cap = 32768u; buf = (uint8_t *)malloc(cap); }
    if (!buf) { (void)sceIoClose(sfd); (void)sceIoClose(dfd); return WB_E_NOMEM; }
    wb_sha256 sha;
    wb_sha256_init(&sha);
    uint64_t total = 0;
    int rc = WB_OK;
    if (src_size) WB_OP_PROGRESS("PATCH", 0, src_size);
    for (;;) {
        const int nr = sceIoRead(sfd, buf, (SceSize)cap);
        if (nr < 0 || (size_t)nr > cap) { rc = WB_E_IO; break; }
        if (nr == 0) break;
        for (size_t off = 0; off < (size_t)nr;) {
            const int nw = sceIoWrite(dfd, buf + off, (SceSize)((size_t)nr - off));
            if (nw <= 0 || (size_t)nw > (size_t)nr - off) { rc = WB_E_IO; break; }
            off += (size_t)nw;
        }
        if (rc != WB_OK) break;
        WB_FAST_SHA_UPDATE(&sha, buf, (size_t)nr);
        total += (uint64_t)nr;
        if (src_size) WB_OP_PROGRESS("PATCH", total, src_size);
    }
    free(buf);
    if (sceIoClose(sfd) < 0) rc = WB_E_IO;
    if (rc == WB_OK && sceIoSyncByFd(dfd, 0) < 0) rc = WB_E_IO;
    if (sceIoClose(dfd) < 0) rc = WB_E_IO;
    if (rc == WB_OK) {
        if (bytes_out) *bytes_out = total;
        if (hex_out) {
            uint8_t raw[32];
            wb_sha256_final(&sha, raw);
            wb_sha_hex(raw, sizeof raw, hex_out);
        }
    }
    return rc;
}

static int wb_ag_hash_file(const char *path, uint64_t *bytes_out, char hex_out[65]) {
    const int fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) return WB_E_IO;
    size_t cap = 262144u;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { cap = 32768u; buf = (uint8_t *)malloc(cap); }
    if (!buf) { (void)sceIoClose(fd); return WB_E_NOMEM; }
    wb_sha256 sha;
    wb_sha256_init(&sha);
    uint64_t total = 0;
    int rc = WB_OK;
    for (;;) {
        const int nr = sceIoRead(fd, buf, (SceSize)cap);
        if (nr < 0 || (size_t)nr > cap) { rc = WB_E_IO; break; }
        if (nr == 0) break;
        WB_FAST_SHA_UPDATE(&sha, buf, (size_t)nr);
        total += (uint64_t)nr;
    }
    free(buf);
    if (sceIoClose(fd) < 0) rc = WB_E_IO;
    if (rc == WB_OK) {
        if (bytes_out) *bytes_out = total;
        uint8_t raw[32];
        wb_sha256_final(&sha, raw);
        wb_sha_hex(raw, sizeof raw, hex_out);
    }
    return rc;
}

static int wb_ag_update_sfo_ver(const char *sfo_path, const char *new_ver) {
    uint8_t buf[16384];
    size_t n = 0;
    if (wb_vita_read_small(sfo_path, buf, sizeof buf, &n) != WB_OK || n < 20) return WB_E_FORMAT;
    if (memcmp(buf, "\x00PSF", 4) != 0) return WB_E_FORMAT;
    const uint32_t key_ofs = wb_ag_le32(buf + 8);
    const uint32_t val_ofs = wb_ag_le32(buf + 12);
    const uint32_t count = wb_ag_le32(buf + 16);
    if (20u + count * 16u > n) return WB_E_FORMAT;
    bool patched = false;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = buf + 20u + i * 16u;
        const uint16_t ko = wb_ag_le16(e);
        const uint16_t fmt = wb_ag_le16(e + 2);
        const uint32_t cap = wb_ag_le32(e + 8);
        const uint32_t vo = wb_ag_le32(e + 12);
        if ((size_t)key_ofs + ko >= n) return WB_E_FORMAT;
        const char *key = (const char *)(buf + key_ofs + ko);
        if (!strcmp(key, "APP_VER") && fmt == 0x0204u && cap >= 6u && (size_t)val_ofs + vo + cap <= n) {
            memset(buf + val_ofs + vo, 0, cap);
            memcpy(buf + val_ofs + vo, new_ver, 5);
            /* Update length field (offset +4) to 6 (5 chars + NUL) */
            buf[20u + i * 16u + 4] = 6;
            buf[20u + i * 16u + 5] = 0;
            buf[20u + i * 16u + 6] = 0;
            buf[20u + i * 16u + 7] = 0;
            patched = true;
            break;
        }
    }
    if (!patched) return WB_E_FORMAT;
    wb_sfo check;
    char verify_ver[16] = {0};
    if (wb_sfo_parse(&check, buf, n) != WB_OK || wb_sfo_get(&check, "APP_VER", verify_ver, sizeof verify_ver) != WB_OK ||
        strcmp(verify_ver, new_ver) != 0)
        return WB_E_FORMAT;
    const int fd = sceIoOpen(sfo_path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (fd < 0) return WB_E_IO;
    const int w = sceIoWrite(fd, buf, (SceSize)n);
    const int s = sceIoSyncByFd(fd, 0);
    const int c = sceIoClose(fd);
    return (w == (int)n && s >= 0 && c >= 0) ? WB_OK : WB_E_IO;
}

static int wb_ag_patch_eboot(const char *tid, const char *src_bin, const char *new_ver, wb_out *out, int *status) {
    if (!wb_ag_tid_mutable(tid)) { *status = 1; return wb_out_puts(out, "ERR app-patch-eboot protected-or-invalid title\n"); }
    if (!src_bin || strncmp(src_bin, WB_INCOMING "/", sizeof WB_INCOMING)) {
        *status = 1; return wb_out_puts(out, "ERR app-patch-eboot source must be in ux0:/VITA-POC/\n");
    }
    if (new_ver && !wb_ag_ver_ok(new_ver)) { *status = 1; return wb_out_puts(out, "ERR app-patch-eboot bad --ver (expected XX.YY)\n"); }
    char app_sfo[96], app_eboot[96], new_eboot[112], bak_path[128];
    snprintf(app_sfo, sizeof app_sfo, "ux0:/app/%.9s/sce_sys/param.sfo", tid);
    snprintf(app_eboot, sizeof app_eboot, "ux0:/app/%.9s/eboot.bin", tid);
    snprintf(new_eboot, sizeof new_eboot, "ux0:/app/%.9s/eboot.bin.new", tid);
    snprintf(bak_path, sizeof bak_path, WB_ROOT "/backups/%.9s-eboot.bak", tid);
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (sceIoGetstat(app_sfo, &st) < 0) { *status = 1; return wb_out_puts(out, "ERR app-patch-eboot title-not-installed\n"); }
    if (!wb_ag_check_self_file(src_bin)) { *status = 1; return wb_out_puts(out, "ERR app-patch-eboot source is not a valid ARM32 SELF\n"); }
    (void)wb_vita_mkdir_p(WB_ROOT "/backups");
    bool backed_up = false;
    if (sceIoGetstat(app_eboot, &st) >= 0) {
        if (wb_ag_copy_and_hash(app_eboot, bak_path, NULL, NULL) == WB_OK) backed_up = true;
    }
    /* Stage into sibling eboot.bin.new and verify SHA-256 BEFORE touching live eboot.bin. */
    (void)sceIoRemove(new_eboot);
    uint64_t written = 0, readback = 0;
    char src_sha[65] = {0}, dst_sha[65] = {0};
    if (wb_ag_copy_and_hash(src_bin, new_eboot, &written, src_sha) != WB_OK ||
        wb_ag_hash_file(new_eboot, &readback, dst_sha) != WB_OK ||
        written != readback || strcmp(src_sha, dst_sha) != 0) {
        (void)sceIoRemove(new_eboot);
        *status = 1;
        return wb_out_puts(out, "ERR app-patch-eboot stage-or-verify-failed (live eboot untouched)\n");
    }
    (void)sceIoRemove(app_eboot);
    if (sceIoRename(new_eboot, app_eboot) < 0) {
        (void)sceIoRemove(new_eboot);
        if (backed_up) (void)wb_ag_copy_and_hash(bak_path, app_eboot, NULL, NULL);
        *status = 1;
        return wb_out_puts(out, "ERR app-patch-eboot atomic-swap-failed (restored backup)\n");
    }
    char cur_ver[16] = "?";
    if (new_ver) {
        if (wb_ag_update_sfo_ver(app_sfo, new_ver) != WB_OK) {
            if (backed_up) (void)wb_ag_copy_and_hash(bak_path, app_eboot, NULL, NULL);
            *status = 1;
            return wb_out_printf(out, "ERR app-patch-eboot param.sfo update failed (restored backup)\n");
        }
        snprintf(cur_ver, sizeof cur_ver, "%s", new_ver);
    } else {
        uint8_t sbuf[8192]; size_t sn = 0;
        if (wb_vita_read_small(app_sfo, sbuf, sizeof sbuf, &sn) == WB_OK) {
            wb_sfo s;
            if (wb_sfo_parse(&s, sbuf, sn) == WB_OK) (void)wb_sfo_get(&s, "APP_VER", cur_ver, sizeof cur_ver);
        }
    }
    return wb_out_printf(out, "OK app-patch-eboot title=%s app_ver=%s bytes=%" PRIu64 " sha256=%s backup=%s\n",
                         tid, cur_ver, readback, dst_sha, backed_up ? "ok" : "none");
}

typedef struct {
    const wb_writer *base;
    wb_out *out;
    uint64_t bytes, total, last_wire;
} wb_ag_inst_wr;
static int wb_ag_imkdir(void *ctx, const char *p) { wb_ag_inst_wr *w = ctx; return w->base->mkdirs(w->base->ctx, p); }
static int wb_ag_icreate(void *ctx, const char *p, uint64_t n) { wb_ag_inst_wr *w = ctx; return w->base->create(w->base->ctx, p, n); }
static int wb_ag_iclose(void *ctx) { wb_ag_inst_wr *w = ctx; return w->base->close(w->base->ctx); }
static int wb_ag_iwrite(void *ctx, const void *buf, size_t n) {
    wb_ag_inst_wr *w = ctx;
    const int rc = w->base->write(w->base->ctx, buf, n);
    if (rc != WB_OK) return rc;
    w->bytes += (uint64_t)n;
    WB_APP_COOPERATE();
    WB_OP_PROGRESS("INSTALL", w->bytes, w->total);
    const uint64_t now = now_ms();
    if (w->out && (!w->last_wire || now < w->last_wire || now - w->last_wire >= 1000)) {
        w->last_wire = now;
        if (wb_out_printf(w->out, "app-progress phase=extract bytes=%llu total=%llu\n",
                          (unsigned long long)w->bytes, (unsigned long long)w->total) < 0)
            return WB_E_IO;
    }
    return WB_OK;
}

static int wb_ag_install_vpk(const char *path, wb_out *out, int *status) {
    if (!path || strncmp(path, WB_INCOMING "/", sizeof WB_INCOMING)) {
        *status = 1; return wb_out_puts(out, "ERR app-install-vpk source must be in ux0:/VITA-POC/\n");
    }
    wb_vfile vf = {.fd = -1};
    wb_reader rd;
    if (wb_vita_reader_open(path, &rd, &vf) != WB_OK) {
        *status = 1; return wb_out_puts(out, "ERR app-install-vpk open-failed\n");
    }
    wb_zip zip;
    char tid[16] = {0}, ver[16] = {0};
    int rc = wb_zip_open(&zip, &rd);
    if (rc == WB_OK) rc = wb_app_parse_sfo(&zip, tid, ver);
    if (rc != WB_OK || !wb_ag_tid_mutable(tid)) {
        wb_vita_reader_close(&vf);
        *status = 1;
        return wb_out_puts(out, "ERR app-install-vpk invalid-or-protected-title\n");
    }
    wb_zip_entry boot;
    if (wb_zip_find(&zip, "eboot.bin", &boot) != WB_OK || !boot.usize) {
        wb_vita_reader_close(&vf);
        *status = 1;
        return wb_out_puts(out, "ERR app-install-vpk missing-eboot\n");
    }
    /* Preflight free-space budget before extracting any bytes. */
    unsigned cursor = 0;
    uint64_t total_usize = WB_HEAD_SIZE;
    wb_zip_entry ze;
    while ((rc = wb_zip_next(&zip, &cursor, &ze)) == WB_OK) {
        if (ze.usize > UINT64_MAX - total_usize) { rc = WB_E_LIMIT; break; }
        total_usize += ze.usize;
    }
    if (rc != 1) {
        wb_vita_reader_close(&vf);
        *status = 1;
        return wb_out_printf(out, "ERR app-install-vpk zip-scan rc=%s\n", wb_err_name(rc));
    }
    const uint64_t reserve = UINT64_C(4) * 1024 * 1024 + (uint64_t)zip.count * 8192u;
    if (total_usize > UINT64_MAX - reserve || WB_APP_BUDGET(total_usize + reserve, out) != WB_OK) {
        wb_vita_reader_close(&vf);
        *status = 1;
        return WB_OK;
    }
    uint8_t head[WB_HEAD_SIZE];
    rc = wb_head_build(head, sizeof head, tid, NULL);
    if (rc == WB_OK) rc = wb_app_clear_stage();
    wb_vwriter vw;
    if (rc == WB_OK) rc = wb_vita_writer_init(&vw, WB_APP_STAGE);
    wb_zip_stats stats = {0};
    if (rc == WB_OK) {
        wb_ag_inst_wr proxy = { wb_vita_writer_ops(&vw), out, 0, total_usize, 0 };
        const wb_writer wops = { .ctx = &proxy, .mkdirs = wb_ag_imkdir, .create = wb_ag_icreate,
                                 .write = wb_ag_iwrite, .close = wb_ag_iclose };
        WB_OP_PROGRESS("INSTALL", 0, total_usize);
        rc = wb_zip_extract_all(&zip, &wops, &stats, NULL, NULL);
        if (rc == WB_OK) rc = wops.mkdirs(wops.ctx, "sce_sys/package");
        if (rc == WB_OK) rc = wops.create(wops.ctx, "sce_sys/package/head.bin", sizeof head);
        if (rc == WB_OK) {
            rc = wops.write(wops.ctx, head, sizeof head);
            const int crc = wops.close(wops.ctx);
            if (rc == WB_OK) rc = crc;
        }
    }
    wb_vita_reader_close(&vf);
    int detail = 0;
    if (rc == WB_OK) rc = wb_vita_promote_stage(WB_APP_STAGE, true, &detail);
    (void)wb_app_clear_stage();
    if (rc != WB_OK) {
        *status = 1;
        return wb_out_printf(out, "ERR app-install-vpk failed rc=%s detail=0x%08X\n", wb_err_name(rc), (unsigned)detail);
    }
    return wb_out_printf(out, "OK app-install-vpk title=%s app_ver=%s files=%u detail=%d session=kept\n",
                         tid, ver, stats.files, detail);
}

static int wb_ag_launch(const char *tid, wb_out *out, int *status) {
    if (!wb_ag_tid_mutable(tid)) { *status = 1; return wb_out_puts(out, "ERR app-launch invalid-or-protected-title\n"); }
    char sfo[96];
    snprintf(sfo, sizeof sfo, "ux0:/app/%.9s/sce_sys/param.sfo", tid);
    SceIoStat st;
    memset(&st, 0, sizeof st);
    if (sceIoGetstat(sfo, &st) < 0) { *status = 1; return wb_out_puts(out, "ERR app-launch title-not-installed\n"); }
    char uri[48];
    snprintf(uri, sizeof uri, "psgm:play?titleid=%.9s", tid);
    const int rc = sceAppMgrLaunchAppByUri(0xFFFFF, uri);
    if (rc < 0) { *status = 1; return wb_out_printf(out, "ERR app-launch rc=0x%08X\n", (unsigned)rc); }
    return wb_out_printf(out, "OK app-launch title=%s\n", tid);
}

static int wb_ag_uninstall(const char *tid, wb_out *out, int *status) {
    if (!wb_ag_tid_mutable(tid)) { *status = 1; return wb_out_puts(out, "ERR app-uninstall protected-or-invalid title\n"); }
    int detail = 0;
    const int rc = wb_vita_delete_pkg(tid, &detail);
    if (rc != WB_OK) {
        *status = 1;
        return wb_out_printf(out, "ERR app-uninstall title=%s rc=%s detail=0x%08X\n", tid, wb_err_name(rc), (unsigned)detail);
    }
    return wb_out_printf(out, "OK app-uninstall title=%s state=absent\n", tid);
}

static int wb_ag_prune(const char *tid_or_null, wb_out *out, int *status) {
    unsigned removed = 0;
    if (!wb_app_local_prune(tid_or_null, &removed)) {
        *status = 1;
        return wb_out_puts(out, "ERR app-prune storage-failed\n");
    }
    return wb_out_printf(out, "OK app-prune scope=%s removed=%u remaining=%u\n",
                         tid_or_null ? tid_or_null : "all", removed, wb_app_local_count);
}

static int wb_agent_app_command(const wb_cmd *cmd, wb_out *out, int *status) {
    if (!cmd || !out) { *status = 1; return WB_E_ARG; }
    if (!strcmp(cmd->name, "list-installed")) return wb_ag_list_installed(out, status);
    if (!strcmp(cmd->name, "patch-eboot") && (cmd->argc == 2 || cmd->argc == 3))
        return wb_ag_patch_eboot(cmd->argv[0], cmd->argv[1], cmd->argc == 3 ? cmd->argv[2] : NULL, out, status);
    if (!strcmp(cmd->name, "install-vpk") && cmd->argc == 1)
        return wb_ag_install_vpk(cmd->argv[0], out, status);
    if (!strcmp(cmd->name, "launch") && cmd->argc == 1)
        return wb_ag_launch(cmd->argv[0], out, status);
    if (!strcmp(cmd->name, "uninstall") && cmd->argc == 1)
        return wb_ag_uninstall(cmd->argv[0], out, status);
    if (!strcmp(cmd->name, "prune") && (cmd->argc == 0 || cmd->argc == 1))
        return wb_ag_prune(cmd->argc == 1 ? cmd->argv[0] : NULL, out, status);
    *status = 1;
    return wb_out_puts(out, "ERR agent-app usage\n");
}
#endif
