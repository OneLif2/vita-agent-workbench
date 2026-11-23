/* Workbench TestApp (INAP00020)
 *
 * A cooperative device-side runner: workbench writes job.txt, launches this
 * title, and this app reports its own build + job id + assertion results to
 * result.txt before handing control back to workbench.
 *
 * "Launched" is not "passed": the PC only accepts a result file whose job id
 * matches the job it generated, and whose result line is PASS.
 *
 * No display init: the app runs headless so it works on any firmware state,
 * and so a failure here cannot be confused with a rendering problem. */

#include <psp2/appmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/power.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define JOB_PATH    "ux0:data/INAP00018/job.txt"
#define AUTOARM     "ux0:data/INAP00018/autoarm.txt"
#define RESULT_DIR  "ux0:data/INAP00018/testapp"
#define RESULT_PATH RESULT_DIR "/result.txt"
#define WORKBENCH   "INAP00018"
#define TEST_BUILD  "01.01-testapp"

static uint32_t fnv1a(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static int read_text(const char *path, char *buf, size_t cap) {
    if (!buf || cap < 2) return -1;
    const int fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) return -1;
    const int n = sceIoRead(fd, buf, (SceSize)(cap - 1));
    (void)sceIoClose(fd);
    if (n < 0 || (size_t)n == cap - 1 || memchr(buf, 0, (size_t)n)) return -1;
    buf[n] = 0;
    return n;
}

static void field(const char *text, const char *key, char *out, size_t cap) {
    out[0] = 0;
    const char *p = text;
    const size_t klen = strlen(key);
    while (p && *p) {
        if (!strncmp(p, key, klen)) {
            const char *v = p + klen;
            size_t i = 0;
            while (v[i] && v[i] != '\n' && v[i] != '\r' && i + 1 < cap) { out[i] = v[i]; i++; }
            out[i] = 0;
            return;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
}

int main(void) {
    (void)sceIoMkdir(RESULT_DIR, 0777);
    char job[64] = {0}, cse[32] = {0}, text[256] = {0};
    if (read_text(JOB_PATH, text, sizeof text) < 0) text[0]=0;
    field(text, "job=", job, sizeof job);
    field(text, "case=", cse, sizeof cse);

    int pass = 1;
    char detail[160] = {0};

    if (!strcmp(cse, "fs-smoke")) {
        static uint8_t wrote[64], readback[64];
        for (unsigned i = 0; i < sizeof wrote; i++) wrote[i] = (uint8_t)(i * 7u + 3u);
        const int fd = sceIoOpen(RESULT_DIR "/fs.bin", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
        if (fd < 0) { pass = 0; snprintf(detail, sizeof detail, "open-write-failed"); }
        else {
            const int w = sceIoWrite(fd, wrote, sizeof wrote);
            (void)sceIoClose(fd);
            const int rd = sceIoOpen(RESULT_DIR "/fs.bin", SCE_O_RDONLY, 0);
            const int r = rd < 0 ? -1 : sceIoRead(rd, readback, sizeof readback);
            if (rd >= 0) (void)sceIoClose(rd);
            const int same = (w == (int)sizeof wrote && r == (int)sizeof readback &&
                              memcmp(wrote, readback, sizeof wrote) == 0);
            (void)sceIoRemove(RESULT_DIR "/fs.bin");
            pass = same;
            snprintf(detail, sizeof detail, "write=%d read=%d match=%d", w, r, same);
        }
    } else if (!strcmp(cse, "power-smoke")) {
        const int pct = scePowerGetBatteryLifePercent();
        const int temp = scePowerGetBatteryTemp();
        pass = pct >= 0 && pct <= 100 && temp > -2000 && temp < 9000;
        snprintf(detail, sizeof detail, "battery=%d temp_raw=%d", pct, temp);
    } else if (!strcmp(cse, "compute-smoke")) {
        static uint8_t buf[1000];
        for (unsigned i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(i & 0xFF);
        const uint32_t h = fnv1a(buf, sizeof buf);
        pass = h == 0x655C5FFDu;
        snprintf(detail, sizeof detail, "fnv1a=0x%08X expected=0x655C5FFD", h);
    } else {
        pass = 0;
        snprintf(detail, sizeof detail, "unknown-case");
    }

    char out[512];
    const int n = snprintf(out, sizeof out,
        "job=%s\n"
        "title=INAP00020\n"
        "build=" TEST_BUILD "\n"
        "case=%s\n"
        "assert=%s\n"
        "result=%s\n",
        job[0] ? job : "missing", cse[0] ? cse : "missing", detail,
        pass ? "PASS" : "FAIL");
    const int fd = sceIoOpen(RESULT_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    int saved=0;
    if (fd >= 0) {
        saved=n>0 && n<(int)sizeof out && sceIoWrite(fd,out,(SceSize)n)==n && sceIoSyncByFd(fd,0)>=0;
        if (sceIoClose(fd)<0) saved=0;
    }

    /* Let workbench arm itself when it comes back, without needing the owner to
     * press X: single-use marker, deleted by workbench as soon as it boots. */
    /* Allow-list the job alphabet before serializing it. A malformed request
     * or unsaved result must return to the normal physical-confirmation path. */
    int valid=job[0]!=0;
    for (size_t i=0;job[i];i++) {
        char c=job[i];
        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_')) valid=0;
    }
    char ticket[32]={0},marker[144];
    field(text,"return=",ticket,sizeof ticket);
    if(strlen(ticket)!=16 || strspn(ticket,"0123456789ABCDEF")!=16) valid=0;
    int mn=snprintf(marker,sizeof marker,"job=%s\nreturn=%s\n",job,ticket);
    if (saved && valid && mn>0 && mn<(int)sizeof marker) {
        const int afd=sceIoOpen(AUTOARM,SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC,0666);
        if (afd>=0) {
            int ok=sceIoWrite(afd,marker,(SceSize)mn)==mn && sceIoSyncByFd(afd,0)>=0;
            if(sceIoClose(afd)<0) ok=0;
            if(!ok) (void)sceIoRemove(AUTOARM);
        }
    }

    (void)sceAppMgrLaunchAppByUri(0xFFFFF, "psgm:play?titleid=" WORKBENCH);
    sceKernelExitProcess(0);
    return 0;
}
