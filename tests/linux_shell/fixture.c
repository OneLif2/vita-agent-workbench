/* Host unit tests for 02.17 Linux-style terminal commands, ext ls ux0:/app,
 * clear PTY escape + mirror reset, and path-policy boundaries. No Vita access. */
#include "wb_shell.h"
#include "wb_shell_channel.h"
#include "wb_sha256.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal VitaSDK I/O & power mocks for wb_linux_cmds.h */
typedef int64_t SceOff;
typedef unsigned int SceSize;
typedef unsigned int SceMode;
typedef struct { uint16_t year, month, day, hour, minute, second; uint32_t microsecond; } SceDateTime;
typedef struct { SceMode st_mode; uint32_t st_attr; SceOff st_size; SceDateTime st_ctime, st_atime, st_mtime; uint32_t st_private[6]; } SceIoStat;
typedef struct { SceIoStat d_stat; char d_name[256]; void *d_private; int dummy; } SceIoDirent;
typedef struct { int size, size_user, size_cdram, size_phycont; } SceKernelFreeMemorySizeInfo;
#define SCE_O_RDONLY 1
#define SCE_SEEK_SET 0
#define SCE_S_ISDIR(m) (((m) & 0xF000) == 0x1000)
#define SCE_S_ISREG(m) (((m) & 0xF000) == 0x2000)

typedef struct { const char *path; int dir; const uint8_t *data; size_t len; } vnode;
static const uint8_t sample_log[] = "line1\nline2\nline3\nline4\nline5\n";
static const uint8_t sample_bin[] = { 0x7f, 'E', 'L', 'F', 0x00, 0x01, 0x02, 0x03 };
static const vnode vfs[] = {
    { "ux0:/", 1, NULL, 0 },
    { "ux0:/VITA-POC", 1, NULL, 0 },
    { "ux0:/VITA-POC/notes.txt", 0, sample_log, sizeof sample_log - 1 },
    { "ux0:/VITA-POC/eboot.bin", 0, sample_bin, sizeof sample_bin },
    { "ux0:/app", 1, NULL, 0 },
    { "ux0:/app/RJGM52237", 1, NULL, 0 },
    { "ux0:/app/RJGM52237/eboot.bin", 0, sample_bin, sizeof sample_bin },
    { "ux0:data", 1, NULL, 0 },
    { "ux0:data/INAP00018", 1, NULL, 0 },
    { "ux0:data/INAP00018/run.log", 0, sample_log, sizeof sample_log - 1 },
    { "ux0:data/INAP00018/mac-public-pin.txt", 0, (const uint8_t *)"SECRET", 6 },
};
static const size_t nvfs = sizeof vfs / sizeof vfs[0];
typedef struct { int used, dir, idx; size_t pos; } vfd;
static vfd fds[16];

static int find_node(const char *p) {
    for (size_t i = 0; i < nvfs; i++) if (!strcmp(vfs[i].path, p)) return (int)i;
    return -1;
}
static int sceIoGetstat(const char *p, SceIoStat *st) {
    int id = find_node(p); if (id < 0) return -1;
    memset(st, 0, sizeof *st);
    st->st_mode = (vfs[id].dir ? 0x1000 : 0x2000) | 0644;
    st->st_size = (SceOff)vfs[id].len;
    st->st_mtime.year = 2026; st->st_mtime.month = 11; st->st_mtime.day = 28;
    st->st_mtime.hour = 15; st->st_mtime.minute = 30;
    return 0;
}
static int sceIoDopen(const char *p) {
    int id = find_node(p); if (id < 0 || !vfs[id].dir) return -1;
    for (int i = 0; i < 16; i++) if (!fds[i].used) { fds[i] = (vfd){1, 1, id, 0}; return i; }
    return -1;
}
static int sceIoDread(int fd, SceIoDirent *e) {
    assert(fd >= 0 && fd < 16 && fds[fd].used && fds[fd].dir);
    const char *parent = vfs[fds[fd].idx].path;
    const size_t plen = strlen(parent);
    const bool root = parent[plen - 1] == '/';
    while (fds[fd].pos < nvfs) {
        size_t i = fds[fd].pos++;
        const char *cp = vfs[i].path;
        if (!strcmp(cp, parent)) continue;
        if (strncmp(cp, parent, plen)) continue;
        const char *rest = root ? cp + plen : (cp[plen] == '/' ? cp + plen + 1 : NULL);
        if (!rest || !*rest || strchr(rest, '/')) continue;
        memset(e, 0, sizeof *e);
        strcpy(e->d_name, rest);
        sceIoGetstat(cp, &e->d_stat);
        return 1;
    }
    return 0;
}
static int sceIoDclose(int fd) { assert(fd >= 0 && fd < 16 && fds[fd].used); fds[fd].used = 0; return 0; }
static int sceIoOpen(const char *p, int flags, SceMode mode) {
    (void)flags; (void)mode;
    int id = find_node(p); if (id < 0 || vfs[id].dir) return -1;
    for (int i = 0; i < 16; i++) if (!fds[i].used) { fds[i] = (vfd){1, 0, id, 0}; return i; }
    return -1;
}
static SceOff sceIoLseek(int fd, SceOff off, int whence) {
    assert(fd >= 0 && fd < 16 && fds[fd].used && !fds[fd].dir && whence == SCE_SEEK_SET);
    fds[fd].pos = (size_t)off; return off;
}
static int sceIoRead(int fd, void *dst, SceSize cap) {
    assert(fd >= 0 && fd < 16 && fds[fd].used && !fds[fd].dir);
    const vnode *v = &vfs[fds[fd].idx];
    if (fds[fd].pos >= v->len) return 0;
    size_t n = v->len - fds[fd].pos; if (n > cap) n = cap;
    memcpy(dst, v->data + fds[fd].pos, n); fds[fd].pos += n; return (int)n;
}
static int sceIoClose(int fd) { assert(fd >= 0 && fd < 16 && fds[fd].used); fds[fd].used = 0; return 0; }
static int sceKernelGetFreeMemorySize(SceKernelFreeMemorySizeInfo *info) {
    assert(info->size == (int)sizeof *info);
    info->size_user = 128 * 1024 * 1024;
    info->size_cdram = 64 * 1024 * 1024;
    info->size_phycont = 16 * 1024 * 1024;
    return 0;
}
static int sceAppMgrGetDevInfo(const char *dev, uint64_t *total, uint64_t *avail) {
    assert(!strcmp(dev, "ux0:"));
    *total = UINT64_C(128) * 1024 * 1024 * 1024;
    *avail = UINT64_C(64) * 1024 * 1024 * 1024;
    return 0;
}
static uint64_t sceKernelGetProcessTimeWide(void) { return UINT64_C(3723000000); } /* 1h 02m 03s */
static int scePowerGetArmClockFrequency(void) { return 444; }
static int scePowerGetBusClockFrequency(void) { return 222; }
static int scePowerGetBatteryLifePercent(void) { return 88; }
static int scePowerIsBatteryCharging(void) { return 1; }

#define WB_LINUX_HOST_MOCK 1
#include "wb_linux_cmds.h"

static char outbuf[16384];
static wb_cmd last_ext;
static int ext_calls;
static int sink(void *ctx, const char *p, size_t n) {
    (void)ctx;
    size_t u = strlen(outbuf);
    assert(u + n < sizeof outbuf);
    memcpy(outbuf + u, p, n); outbuf[u + n] = 0;
    return 0;
}
static int dummy_dir(void *ctx, const char *p, wb_out *o) { (void)ctx; (void)p; (void)o; return 0; }
static int dummy_ls(void *ctx, const char *p, bool l, wb_out *o) { (void)ctx; (void)p; (void)l; return wb_out_puts(o, "VFS_LS\n"); }
static int dummy_cat(void *ctx, const char *p, wb_out *o) { (void)ctx; (void)p; return wb_out_puts(o, "CAT\n"); }
static int core_dispatch(void *ctx, const wb_cmd *c, wb_out *o) {
    (void)ctx;
    if (c->kind == WB_CMD_TERM_LINUX) {
        int status = 0;
        return wb_linux_command(c, "192.0.2.10", o, &status);
    }
    if (c->kind == WB_CMD_EXT) {
        ext_calls++; last_ext = *c;
        return wb_out_puts(o, "EXT_OK\n");
    }
    return wb_out_puts(o, "OTHER\n");
}
static wb_out out = { NULL, sink };
static wb_shell_ops ops = { NULL, dummy_dir, dummy_ls, dummy_cat, core_dispatch };
static wb_shell_engine sh;

static void run(const char *cmd) {
    outbuf[0] = 0;
    assert(wb_shell_run(&sh, cmd, &out, &ops) == 0);
}

int main(void) {
    wb_shell_init(&sh);

    /* 1. ext ls ux0:/app/... forwards to WB_CMD_EXT while non-app stays on VFS */
    ext_calls = 0;
    run("ext ls /inbox");
    assert(ext_calls == 0 && strstr(outbuf, "VFS_LS"));
    run("ext ls ux0:/app/RJGM52237");
    assert(ext_calls == 1 && last_ext.kind == WB_CMD_EXT && !strcmp(last_ext.argv[1], "ux0:/app/RJGM52237"));

    /* 2. ll and ls -lh work on /inbox, ux0:/app/RJGM52237, and hide private files in INAP00018 */
    run("ll /inbox");
    assert(strstr(outbuf, "notes.txt") && strstr(outbuf, "eboot.bin") && strstr(outbuf, "total 2 files, 0 dirs"));
    run("ls -lh ux0:/app/RJGM52237");
    assert(strstr(outbuf, "eboot.bin") && strstr(outbuf, "total 1 files"));
    run("ll ux0:/data/INAP00018");
    assert(strstr(outbuf, "run.log") && !strstr(outbuf, "mac-public-pin.txt"));
    run("ll ux0:/tai");
    assert(strstr(outbuf, "ERR access denied"));

    /* 3. sha256sum hashes /inbox, diag logs, and ux0:/app/...; denies private pin */
    run("sha256sum /inbox/notes.txt ux0:/app/RJGM52237/eboot.bin");
    assert(strstr(outbuf, "  ux0:/VITA-POC/notes.txt\n") && strstr(outbuf, "  ux0:/app/RJGM52237/eboot.bin\n"));
    run("sha256sum ux0:/data/INAP00018/mac-public-pin.txt");
    assert(strstr(outbuf, "ERR sha256sum access-denied"));

    /* 4. head and tail slice lines accurately and refuse binary files */
    run("head -n 2 /inbox/notes.txt");
    assert(!strcmp(outbuf, "line1\nline2\n"));
    run("tail -n 2 /inbox/notes.txt");
    assert(!strcmp(outbuf, "line4\nline5\n"));
    run("head /inbox/eboot.bin");
    assert(strstr(outbuf, "ERR binary file"));
    run("tail -n 1 ux0:/data/INAP00018/run.log");
    assert(!strcmp(outbuf, "line5\n"));
    run("head -n 0 /inbox/notes.txt");
    assert(strstr(outbuf, "ERR line count"));

    /* 5. du computes bytes & human summary; denies /data root */
    run("du -h /inbox");
    assert(strstr(outbuf, "38B\tux0:/VITA-POC (2 files, 0 dirs)"));
    run("du ux0:/app/RJGM52237");
    assert(strstr(outbuf, "8\tux0:/app/RJGM52237"));
    run("du ux0:/data");
    assert(strstr(outbuf, "ERR du allowed"));

    /* 6. cp & touch enforce incoming-only write boundary */
    run("touch ux0:/data/INAP00018/evil.txt");
    assert(strstr(outbuf, "ERR path denied"));
    run("cp /inbox/notes.txt ux0:/app/RJGM52237/evil.txt");
    assert(strstr(outbuf, "ERR path denied"));

    /* 7. System info commands & help linux */
    run("uname"); assert(!strcmp(outbuf, "PSVita\n"));
    run("uname -a"); assert(strstr(outbuf, "VitaAgentWorkbench") && strstr(outbuf, WB_VERSION));
    run("whoami"); assert(!strcmp(outbuf, "pi\n"));
    run("hostname"); assert(!strcmp(outbuf, "192.0.2.10\n"));
    run("uptime"); assert(strstr(outbuf, "up 1h 02m 03s") && strstr(outbuf, "arm=444MHz") && strstr(outbuf, "battery=88% charging"));
    run("free -h"); assert(strstr(outbuf, "Mem (user)") && strstr(outbuf, "128.0M") && strstr(outbuf, "64.00G"));
    run("help linux"); assert(strstr(outbuf, "sha256sum") && strstr(outbuf, "head") && strstr(outbuf, "clear"));

    /* 8. wb_shell_streamed_app marks streaming Linux commands without affecting ls -l */
    assert(wb_shell_streamed_app("ll /inbox"));
    assert(wb_shell_streamed_app("ls -lh /inbox"));
    assert(wb_shell_streamed_app("sha256sum /inbox/notes.txt"));
    assert(wb_shell_streamed_app("head -n 5 /inbox/notes.txt"));
    assert(wb_shell_streamed_app("tail /inbox/notes.txt"));
    assert(wb_shell_streamed_app("cp /inbox/a /inbox/b"));
    assert(wb_shell_streamed_app("du -h /inbox"));
    assert(!wb_shell_streamed_app("ls -l /inbox"));

    /* 9. Tab completion for new commands */
    char edited[WB_SH_LINE];
    assert(wb_shell_complete(&sh, "sha256", &ops, edited) && !strcmp(edited, "sha256sum "));
    assert(wb_shell_complete(&sh, "whoa", &ops, edited) && !strcmp(edited, "whoami "));
    assert(wb_shell_complete(&sh, "upt", &ops, edited) && !strcmp(edited, "uptime "));
    assert(wb_shell_complete(&sh, "clea", &ops, edited) && !strcmp(edited, "clear "));

    for (int i = 0; i < 16; i++) assert(!fds[i].used);
    puts("PASS linux_shell: ext ls ux0:/app/*, ll, ls -lh, sha256sum, head, tail, du, uname, whoami, hostname, uptime, free, path policy, streaming, completion");
    return 0;
}
