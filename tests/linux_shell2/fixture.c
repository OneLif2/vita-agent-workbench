/* Host test for the Workbench 2.0 (WB_SHELL2) shell: multi-mount paths,
 * ; && | compound commands, text filters, grep/find/hexdump, echo, private
 * path denials and agent app parsing. No Vita access. */
#include "wb_shell.h"
#include "wb_sha256.h"
#include "wb_screen_mirror.h"
#include "wb_xfer_ui.h"
#include "wb_sftp_ro.h"
#include "active_terminal.h"
enum { W = 960, H = 544, PITCH = 1024 };
#include "screen.inc"
#include "mirror_panel.inc"
#include "wb_xfer_panel.inc"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
static const uint8_t sample_log[] = "line1\nline2\nline3\nline4\nline5";
static const uint8_t sample_bin[] = { 0x7f, 'E', 'L', 'F', 0x00, 0x01, 0x02, 0x03, 'A', 'B' };
static const uint8_t tai_cfg[] = "# tai config\n*KERNEL\nur0:tai/henkaku.skprx\n";
static const vnode vfs[] = {
    { "ux0:/", 1, NULL, 0 },
    { "ux0:/VITA-POC", 1, NULL, 0 },
    { "ux0:/VITA-POC/notes.txt", 0, sample_log, sizeof sample_log - 1 },
    { "ux0:/VITA-POC/eboot.bin", 0, sample_bin, sizeof sample_bin },
    { "ux0:data", 1, NULL, 0 },
    { "ux0:data/INAP00018", 1, NULL, 0 },
    { "ux0:data/INAP00018/run.log", 0, sample_log, sizeof sample_log - 1 },
    { "ux0:data/INAP00018/host.private", 0, (const uint8_t *)"SECRET", 6 },
    { "ur0:/", 1, NULL, 0 },
    { "ur0:/tai", 1, NULL, 0 },
    { "ur0:/tai/config.txt", 0, tai_cfg, sizeof tai_cfg - 1 },
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
    return 0;
}
static int sceIoDopen(const char *p) {
    int id = find_node(p); if (id < 0 || !vfs[id].dir) return -1;
    for (int i = 0; i < 16; i++) if (!fds[i].used) { fds[i] = (vfd){1, 1, id, 0}; return i; }
    return -1;
}
static int sceIoDread(int fd, SceIoDirent *e) {
    const char *parent = vfs[fds[fd].idx].path;
    const size_t plen = strlen(parent);
    const bool root = parent[plen - 1] == '/';
    while (fds[fd].pos < nvfs) {
        const char *cp = vfs[fds[fd].pos++].path;
        if (!strcmp(cp, parent) || strncmp(cp, parent, plen)) continue;
        const char *rest = root ? cp + plen : (cp[plen] == '/' ? cp + plen + 1 : NULL);
        if (!rest || !*rest || strchr(rest, '/')) continue;
        memset(e, 0, sizeof *e); strcpy(e->d_name, rest); sceIoGetstat(cp, &e->d_stat);
        return 1;
    }
    return 0;
}
static int sceIoDclose(int fd) { assert(fds[fd].used); fds[fd].used = 0; return 0; }
static int sceIoOpen(const char *p, int flags, SceMode mode) {
    (void)flags; (void)mode;
    int id = find_node(p); if (id < 0 || vfs[id].dir) return -1;
    for (int i = 0; i < 16; i++) if (!fds[i].used) { fds[i] = (vfd){1, 0, id, 0}; return i; }
    return -1;
}
static SceOff sceIoLseek(int fd, SceOff off, int whence) { (void)whence; fds[fd].pos = (size_t)off; return off; }
static int sceIoRead(int fd, void *dst, SceSize cap) {
    const vnode *v = &vfs[fds[fd].idx];
    if (fds[fd].pos >= v->len) return 0;
    size_t n = v->len - fds[fd].pos; if (n > cap) n = cap;
    memcpy(dst, v->data + fds[fd].pos, n); fds[fd].pos += n; return (int)n;
}
static int sceIoClose(int fd) { assert(fds[fd].used); fds[fd].used = 0; return 0; }
static int sceKernelGetFreeMemorySize(SceKernelFreeMemorySizeInfo *i) { i->size_user = 1 << 20; i->size_cdram = 1 << 20; i->size_phycont = 1 << 20; return 0; }
static int sceAppMgrGetDevInfo(const char *d, uint64_t *t, uint64_t *a) { (void)d; *t = 1u << 30; *a = 1u << 29; return 0; }
static uint64_t sceKernelGetProcessTimeWide(void) { return 1000000; }
static int scePowerGetArmClockFrequency(void) { return 333; }
static int scePowerGetBusClockFrequency(void) { return 222; }
static int scePowerGetBatteryLifePercent(void) { return 50; }
static int scePowerIsBatteryCharging(void) { return 0; }

#define WB_LINUX_HOST_MOCK 1
#include "wb_linux_cmds.h"

static char outbuf[16384];
static wb_cmd last_agent;
static int sink(void *ctx, const char *p, size_t n) {
    (void)ctx; size_t u = strlen(outbuf); assert(u + n < sizeof outbuf);
    memcpy(outbuf + u, p, n); outbuf[u + n] = 0; return 0;
}
static int isdir_ok(void *ctx, const char *p, wb_out *o) { (void)ctx; (void)o; int id = find_node(p); return (id >= 0 && vfs[id].dir) || !strcmp(p, "ux0:/data") ? 0 : 1; }
static int ls_stub(void *ctx, const char *p, bool l, wb_out *o) { (void)ctx; (void)l; return wb_out_printf(o, "LS %s\n", p); }
static int cat_stub(void *ctx, const char *p, wb_out *o) { (void)ctx; return wb_out_printf(o, "CAT %s\n", p); }
static int core_dispatch(void *ctx, const wb_cmd *c, wb_out *o) {
    (void)ctx; int status = 0;
    if (c->kind == WB_CMD_TERM_LINUX) return wb_linux_command(c, "192.0.2.10", o, &status);
    if (c->kind == WB_CMD_TERM_AGENT_APP) { last_agent = *c; return wb_out_printf(o, "AGENT %s %d\n", c->name, c->argc); }
    return wb_out_puts(o, "OTHER\n");
}
static wb_out out = { NULL, sink };
static wb_shell_ops ops = { NULL, isdir_ok, ls_stub, cat_stub, core_dispatch };
static wb_shell_engine sh;
static void run(const char *cmd) { outbuf[0] = 0; assert(wb_shell_run(&sh, cmd, &out, &ops) == 0); }
#define HAS(s) (strstr(outbuf, (s)) != NULL)

static int sftp_dummy_stat(void *c, const char *p, wb_sftp_attr *a) { (void)c; (void)p; a->size = 4096; a->is_dir = 0; return WB_SFTP_OK; }
static int sftp_dummy_open(void *c, const char *p, int d, int *fd) { (void)c; (void)p; (void)d; *fd = 7; return WB_SFTP_OK; }
static int sftp_dummy_close(void *c, int fd, int d) { (void)c; (void)fd; (void)d; return WB_SFTP_OK; }
static int sftp_dummy_read(void *c, int fd, uint64_t off, uint8_t *b, size_t cap, size_t *got) {
    (void)c; (void)fd; (void)off; memset(b, 'A', cap > 1024 ? 1024 : cap); *got = cap > 1024 ? 1024 : cap; return WB_SFTP_OK;
}
static int sftp_dummy_readdir(void *c, int fd, char *n, size_t nc, wb_sftp_attr *a) { (void)c; (void)fd; (void)n; (void)nc; (void)a; return WB_SFTP_EOF; }
static int sftp_dummy_fstat(void *c, int fd, int d, wb_sftp_attr *a) { (void)c; (void)fd; (void)d; a->size = 4096; a->is_dir = 0; return WB_SFTP_OK; }
static int sftp_dummy_wopen(void *c, const char *p, void **w) { (void)c; (void)p; *w = (void *)1; return WB_SFTP_OK; }
static int sftp_dummy_wwrite(void *c, void *w, const uint8_t *b, size_t n) { (void)c; (void)w; (void)b; (void)n; return WB_SFTP_OK; }
static int sftp_dummy_wfin(void *c, void *w, int commit) { (void)c; (void)w; (void)commit; return WB_SFTP_OK; }
static int sftp_dummy_wmkdir(void *c, const char *p) { (void)c; (void)p; return WB_SFTP_OK; }
static void put_be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

int main(void) {
    wb_shell_init(&sh);
    /* 02.19: real Linux prompt updates dynamically on cd, supports ~, cd -, virtual / */
    outbuf[0] = 0; assert(wb_shell_prompt(&sh, &out) == 0); assert(!strcmp(outbuf, "pi@vita:/ux0$ "));
    sh.color = true;
    outbuf[0] = 0; assert(wb_shell_prompt(&sh, &out) == 0); assert(!strcmp(outbuf, "\033[1;32mpi@vita\033[0m:\033[1;34m/ux0\033[0m$ "));
    sh.color = false;
    run("cd ux0:/VITA-POC"); outbuf[0] = 0; assert(wb_shell_prompt(&sh, &out) == 0); assert(!strcmp(outbuf, "pi@vita:/ux0/VITA-POC$ "));
    run("cd /"); run("pwd"); assert(!strcmp(outbuf, "/\n"));
    outbuf[0] = 0; assert(wb_shell_prompt(&sh, &out) == 0); assert(!strcmp(outbuf, "pi@vita:/$ "));
    run("ls"); assert(HAS("ux0/\n") && HAS("ur0/\n") && HAS("uma0/\n") && HAS("inbox/\n"));
    run("cd -"); assert(!strcmp(outbuf, "ux0:/VITA-POC\n"));
    run("cd ~"); run("pwd"); assert(!strcmp(outbuf, "ux0:/VITA-POC\n"));
    run("cd /ux0");
    /* Mounts and aliases */
    run("cd ur0:/tai"); run("pwd"); assert(!strcmp(outbuf, "ur0:/tai\n"));
    outbuf[0] = 0; assert(wb_shell_prompt(&sh, &out) == 0); assert(!strcmp(outbuf, "pi@vita:/ur0/tai$ "));
    run("cd .."); run("pwd"); assert(!strcmp(outbuf, "ur0:/\n"));
    run("cd .."); run("pwd"); assert(!strcmp(outbuf, "/\n"));
    run("cd /ux0"); run("pwd"); assert(!strcmp(outbuf, "ux0:/\n"));
    /* History inside pipes */
    static const char mock_hist[4][WB_SH_LINE] = { "pwd", "ls /inbox", "app ls", "df -h" };
    sh.hist = mock_hist; sh.hist_cap = 4; sh.hist_count = 4;
    run("history | tail -n 2"); assert(HAS("   3  app ls\n") && HAS("   4  df -h\n") && !HAS("pwd"));
    run("history | grep app"); assert(HAS("app ls\n") && !HAS("df -h"));
    /* 02.19: wb_xfer_format_pct real 0-100% progress formatting */
    wb_xfer_ui xm;
    wb_xfer_format_pct(&xm, "SFTP PUT", 2u * 1048576u, 4u * 1048576u, 1500000u);
    assert(xm.pct == 50 && strstr(xm.text, "SFTP PUT  50%") && strstr(xm.text, "2.00 MB/4.00 MB") && strstr(xm.text, "1.50 MB/s"));
    wb_xfer_format_pct(&xm, "SFTP GET", 4u * 1048576u, 4u * 1048576u, 2000000u);
    assert(xm.pct == 100 && strstr(xm.text, "100%") && strstr(xm.text, "VERIFY"));
    /* 02.19: SFTP OPEN size hint and READ fstat total + offset tracking */
    const wb_sftp_ops sops = { NULL, sftp_dummy_stat, sftp_dummy_open, sftp_dummy_close, sftp_dummy_read, sftp_dummy_readdir, sftp_dummy_fstat };
    const wb_sftp_write_ops swops = { NULL, sftp_dummy_wopen, sftp_dummy_wwrite, sftp_dummy_wfin, sftp_dummy_wmkdir };
    wb_sftp_ro sftp; wb_sftp_init(&sftp, &sops); wb_sftp_enable_write(&sftp, &swops);
    uint8_t req[64], resp[2048]; size_t rlen = 0;
    req[0] = 1; put_be32(req + 1, 3); assert(wb_sftp_reply(&sftp, req, 5, resp, sizeof resp, &rlen) == 0);
    /* OPEN for write with ATTR_SIZE = 4194304 */
    req[0] = 3; put_be32(req + 1, 1); put_be32(req + 5, 5); memcpy(req + 9, "/a.bi", 5);
    put_be32(req + 14, 26); put_be32(req + 18, 1); put_be32(req + 22, 0); put_be32(req + 26, 4194304u);
    assert(wb_sftp_reply(&sftp, req, 30, resp, sizeof resp, &rlen) == 0 && resp[0] == 102);
    assert(sftp.handles[0].used && sftp.handles[0].total == 4194304u);
    /* OPEN for read populates total=4096 via fstat, READ updates offset=1024 */
    req[0] = 3; put_be32(req + 1, 2); put_be32(req + 5, 5); memcpy(req + 9, "/b.bi", 5);
    put_be32(req + 14, 1); put_be32(req + 18, 0);
    assert(wb_sftp_reply(&sftp, req, 22, resp, sizeof resp, &rlen) == 0 && resp[0] == 102);
    assert(sftp.handles[1].used && sftp.handles[1].total == 4096u);
    req[0] = 5; put_be32(req + 1, 3); put_be32(req + 5, 8); memcpy(req + 9, resp + 9, 8);
    put_be32(req + 17, 0); put_be32(req + 21, 0); put_be32(req + 25, 1024);
    assert(wb_sftp_reply(&sftp, req, 29, resp, sizeof resp, &rlen) == 0 && resp[0] == 103);
    assert(sftp.handles[1].offset == 1024u);
    wb_sftp_reset(&sftp);
    /* 02.19: wb_screen_mirror ANSI SGR 16-color parsing */
    wb_mirror_begin();
    const char *colored = "\033[1;32mpi@vita\033[0m:\033[1;34m/ux0\033[0m$ ";
    wb_mirror_write((const uint8_t *)colored, strlen(colored));
    assert(!strcmp(wb_mirror_view_row(0, 22), "pi@vita:/ux0$ "));
    const uint8_t *fg = wb_mirror_view_fg(0, 22);
    assert(fg && fg[0] == 10 && fg[6] == 10 && fg[7] == 0 && fg[8] == 12 && fg[11] == 12 && fg[12] == 0);
    /* Exercise WB_SHELL2 computer-terminal OLED chrome + progress card pixel rendering */
    static uint32_t fb[H * PITCH];
    draw_mirror(fb, "pin", "AGENT MODE READY", true);
    assert(fb[17 * PITCH + 20] == COLOR(255, 95, 86));   /* red window dot */
    assert(fb[17 * PITCH + 40] == COLOR(255, 189, 46));  /* yellow window dot */
    assert(fb[17 * PITCH + 60] == COLOR(39, 201, 63));   /* green window dot */
    wb_xfer_draw(fb, &xm);
    wb_mirror_reset();
    draw_mirror(fb, "pin", "AGENT MODE READY", false);
    assert(fb[17 * PITCH + 20] == COLOR(255, 95, 86));
    run("ls /ur0/tai"); assert(!strcmp(outbuf, "LS ur0:/tai\n"));
    run("ll ur0:/tai"); assert(HAS("config.txt") && HAS("total 1 files"));
    run("head -n 2 /ur0/tai/config.txt"); assert(!strcmp(outbuf, "# tai config\n*KERNEL\n"));
    /* Private identity stays hidden/denied even with full read-only mounts */
    run("ll ux0:/data/INAP00018"); assert(HAS("run.log") && !HAS("host.private"));
    run("sha256sum ux0:/data/INAP00018/host.private"); assert(HAS("ERR sha256sum access-denied"));
    run("grep SECRET ux0:/data/INAP00018/host.private"); assert(HAS("ERR grep access-denied"));
    /* Device grep / find / hexdump */
    run("grep -n line3 /inbox/notes.txt"); assert(!strcmp(outbuf, "3:line3\n"));
    run("grep -c line /inbox/notes.txt"); assert(!strcmp(outbuf, "5\n")); /* last line has no newline */
    run("grep -i LINE5 /inbox/notes.txt"); assert(!strcmp(outbuf, "line5\n"));
    run("grep ELF /inbox/eboot.bin"); assert(HAS("Binary file ux0:/VITA-POC/eboot.bin matches"));
    run("find /inbox -name \"*.txt\""); assert(HAS("ux0:/VITA-POC/notes.txt\n") && HAS("find: 1 match\n") && !HAS("eboot"));
    run("find ur0:/ -type d"); assert(HAS("ur0:/tai/") && !HAS("config.txt"));
    run("hexdump -n 10 /inbox/eboot.bin"); assert(HAS("00000000  7f 45 4c 46 00 01 02 03  41 42") && HAS("|.ELF....AB|") && HAS("0000000a\n"));
    /* echo, chains, pipes, filters */
    run("echo hello world"); assert(!strcmp(outbuf, "hello world\n"));
    run("echo a ; echo b"); assert(!strcmp(outbuf, "a\nb\n"));
    run("echo a && echo b"); assert(!strcmp(outbuf, "a\nb\n"));
    run("sha256sum /inbox/missing.txt && echo NO"); assert(HAS("ERR") && !HAS("NO"));
    run("sha256sum /inbox/missing.txt ; echo YES"); assert(HAS("YES"));
    run("ll /inbox | grep notes"); assert(HAS("notes.txt") && !HAS("eboot.bin") && !HAS("total"));
    run("ll /inbox | grep -v total | wc -l"); assert(!strcmp(outbuf, "2\n"));
    run("head -n 5 /inbox/notes.txt | sort -r | head -n 1"); assert(!strcmp(outbuf, "line5\n"));
    run("head -n 5 /inbox/notes.txt | tail -n 2"); assert(!strcmp(outbuf, "line4\nline5\n"));
    run("echo x | grep -c x"); assert(!strcmp(outbuf, "1\n"));
    run("echo b ; echo b | uniq"); assert(!strcmp(outbuf, "b\nb\n"));
    run("echo 'a;b|c'"); assert(!strcmp(outbuf, "a;b|c\n")); /* quoted operators are literal */
    run("echo x | bogus"); assert(HAS("ERR pipe: only grep head tail wc sort uniq"));
    run("echo x &"); assert(HAS("ERR syntax: background"));
    assert(wb_shell_streamed_app("ll /inbox | grep x") && wb_shell_streamed_app("grep a /inbox/notes.txt"));
    /* Agent app command parsing */
    run("app ls"); assert(!strcmp(outbuf, "AGENT list-installed 0\n"));
    run("app patch-eboot RJGM52237 /inbox/eboot.bin --ver 01.17");
    assert(HAS("AGENT patch-eboot 3") && !strcmp(last_agent.argv[0], "RJGM52237") &&
           !strcmp(last_agent.argv[1], "ux0:/VITA-POC/eboot.bin") && !strcmp(last_agent.argv[2], "01.17"));
    run("app patch-eboot RJGM52237 ux0:/app/RJGM52237/eboot.bin"); assert(HAS("ERR usage: app patch-eboot"));
    run("app install-vpk /inbox/game.vpk"); assert(HAS("AGENT install-vpk 1") && !strcmp(last_agent.argv[0], "ux0:/VITA-POC/game.vpk"));
    assert(wb_shell_streamed_app("app install-vpk /inbox/game.vpk"));
    assert(wb_shell_streamed_app("app patch-eboot RJGM52237 /inbox/eboot.bin"));
    run("app prune"); assert(HAS("AGENT prune 0"));
    run("app prune RJGP52237"); assert(HAS("AGENT prune 1") && !strcmp(last_agent.argv[0], "RJGP52237"));
    run("app prune bad"); assert(HAS("ERR usage: app prune"));
    run("app launch RJGM52237"); assert(HAS("AGENT launch 1"));
    run("app remove rjgm52237"); assert(HAS("ERR usage: app launch|remove"));
    run("help linux"); assert(HAS("/ur0") && HAS("grep") && HAS("Up/Down history"));
    run("help app"); assert(HAS("app patch-eboot"));
    for (int i = 0; i < 16; i++) assert(!fds[i].used);
    puts("PASS linux_shell2: mounts, private denials, grep/find/hexdump, echo, ; && | filters, agent app parsing");
    return 0;
}
