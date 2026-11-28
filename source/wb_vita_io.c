#include "wb_vita_io.h"

#include "wb_err.h"

#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/threadmgr.h>

#include <stdio.h>
#include <string.h>

#define EEXIST_VITA ((int)0x80010011u)

int wb_vita_mkdir_p(const char *path) {
    if (!path) return WB_E_ARG;
    char work[192];
    const size_t n = strlen(path);
    if (n >= sizeof work) return WB_E_LIMIT;
    memcpy(work, path, n + 1);
    for (size_t i = 5; i <= n; i++) {           /* skip "ux0:/" */
        if (work[i] != '/' && i != n) continue;
        work[i] = 0;
        const int rc = sceIoMkdir(work, 0777);
        if (rc < 0 && rc != EEXIST_VITA) {
            int exists = 1;
            SceIoStat st;
            memset(&st, 0, sizeof st);
            if (sceIoGetstat(work, &st) < 0 || !SCE_S_ISDIR(st.st_mode)) exists = 0;
            if (!exists) return WB_E_IO;
        }
        work[i] = '/';
    }
    return WB_OK;
}

static int remove_dir(const char *path) {
    const int fd = sceIoDopen(path);
    if (fd >= 0) {
        SceIoDirent ent;
        for (;;) {
            memset(&ent, 0, sizeof ent);
            if (sceIoDread(fd, &ent) <= 0) break;
            if (!strcmp(ent.d_name, ".") || !strcmp(ent.d_name, "..")) continue;
            char child[256];
            if (snprintf(child, sizeof child, "%s/%s", path, ent.d_name) >= (int)sizeof child) continue;
            if (SCE_S_ISDIR(ent.d_stat.st_mode)) (void)remove_dir(child);
            else sceIoRemove(child);
        }
        sceIoDclose(fd);
    }
    return sceIoRmdir(path);
}

int wb_vita_remove_tree(const char *path) {
    if (!path) return WB_E_ARG;
    const int rc = remove_dir(path);
    return rc < 0 ? WB_E_IO : WB_OK;
}

bool wb_vita_exists(const char *path) {
    SceIoStat st;
    memset(&st, 0, sizeof st);
    return path && sceIoGetstat(path, &st) >= 0;
}

static int read_at(const void *ctx, uint64_t off, void *buf, size_t n) {
    wb_vfile *f = (wb_vfile *)(uintptr_t)ctx;
    if (!f->pos_valid || f->pos != off) {
        if (sceIoLseek(f->fd, (SceOff)off, SCE_SEEK_SET) != (SceOff)off) {
            f->pos_valid = false;
            return WB_E_IO;
        }
        f->pos = off;
        f->pos_valid = true;
    }
    size_t done = 0;
    while (done < n) {
        const int rc = sceIoRead(f->fd, (char *)buf + done, (SceSize)(n - done));
        if (rc <= 0) { f->pos_valid = false; return WB_E_IO; }
        done += (size_t)rc;
    }
    f->pos += (uint64_t)n;
    return WB_OK;
}

int wb_vita_reader_open(const char *path, wb_reader *rd, wb_vfile *f) {
    if (!path || !rd || !f) return WB_E_ARG;
    f->pos = 0;
    f->pos_valid = false;
    f->fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (f->fd < 0) return WB_E_IO;
    const SceOff size = sceIoLseek(f->fd, 0, SCE_SEEK_END);
    if (size < 0) { sceIoClose(f->fd); f->fd = -1; return WB_E_IO; }
    rd->ctx = f;
    rd->size = (uint64_t)size;
    rd->read_at = read_at;
    return WB_OK;
}

void wb_vita_reader_close(wb_vfile *f) {
    if (f && f->fd >= 0) { sceIoClose(f->fd); f->fd = -1; }
}

/* ---- writer ---- */

static int w_mkdirs(void *ctx, const char *rel) {
    wb_vwriter *w = (wb_vwriter *)ctx;
    char path[224];
    if (snprintf(path, sizeof path, "%s/%s", w->root, rel) >= (int)sizeof path) return WB_E_LIMIT;
    const size_t n = strlen(path);
    if (n && path[n - 1] == '/') path[n - 1] = 0;
    return wb_vita_mkdir_p(path);
}

static int w_create(void *ctx, const char *rel, uint64_t size) {
    wb_vwriter *w = (wb_vwriter *)ctx;
    (void)size;
    char path[224];
    if (snprintf(path, sizeof path, "%s/%s", w->root, rel) >= (int)sizeof path) return WB_E_LIMIT;
    char dir[224];
    memcpy(dir, path, strlen(path) + 1);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        const int rc = wb_vita_mkdir_p(dir);
        if (rc != WB_OK) return rc;
    }
    w->fd = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    return w->fd < 0 ? WB_E_IO : WB_OK;
}

static int w_write(void *ctx, const void *buf, size_t n) {
    wb_vwriter *w = (wb_vwriter *)ctx;
    if (w->fd < 0) return WB_E_STATE;
    size_t done = 0;
    while (done < n) {
        const int rc = sceIoWrite(w->fd, (const char *)buf + done, (SceSize)(n - done));
        if (rc <= 0) return WB_E_IO;
        done += (size_t)rc;
    }
    return WB_OK;
}

static int w_close(void *ctx) {
    wb_vwriter *w = (wb_vwriter *)ctx;
    if (w->fd < 0) return WB_OK;
    const int rc = sceIoClose(w->fd);
    w->fd = -1;
    return rc < 0 ? WB_E_IO : WB_OK;
}

static int w_remove_tree(void *ctx, const char *rel) {
    wb_vwriter *w = (wb_vwriter *)ctx;
    char path[224];
    if (snprintf(path, sizeof path, "%s/%s", w->root, rel) >= (int)sizeof path) return WB_E_LIMIT;
    return wb_vita_remove_tree(path);
}

int wb_vita_writer_init(wb_vwriter *w, const char *root) {
    if (!w || !root) return WB_E_ARG;
    memset(w, 0, sizeof *w);
    w->fd = -1;
    if (strlen(root) >= sizeof w->root) return WB_E_LIMIT;
    memcpy(w->root, root, strlen(root) + 1);
    return wb_vita_mkdir_p(root);
}

const wb_writer *wb_vita_writer_ops(wb_vwriter *w) {
    static wb_writer ops;
    ops.ctx = w;
    ops.mkdirs = w_mkdirs;
    ops.create = w_create;
    ops.write = w_write;
    ops.close = w_close;
    ops.remove_tree = w_remove_tree;
    return &ops;
}

int wb_vita_copy_file(const char *src, const char *dst) {
    const int in = sceIoOpen(src, SCE_O_RDONLY, 0);
    if (in < 0) return WB_E_IO;
    const int out = sceIoOpen(dst, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (out < 0) { sceIoClose(in); return WB_E_IO; }
    char buf[16384];
    int rc = WB_OK;
    for (;;) {
        const int got = sceIoRead(in, buf, sizeof buf);
        if (got < 0) { rc = WB_E_IO; break; }
        if (got == 0) break;
        size_t done = 0;
        while (done < (size_t)got) {
            const int wr = sceIoWrite(out, buf + done, (SceSize)((size_t)got - done));
            if (wr <= 0) { rc = WB_E_IO; break; }
            done += (size_t)wr;
        }
        if (rc != WB_OK) break;
    }
    sceIoClose(in);
    sceIoClose(out);
    return rc;
}

int wb_vita_write_file(const char *path, const void *data, size_t n, bool append) {
    const int flags = SCE_O_WRONLY | SCE_O_CREAT | (append ? SCE_O_APPEND : SCE_O_TRUNC);
    const int fd = sceIoOpen(path, flags, 0666);
    if (fd < 0) return WB_E_IO;
    size_t done = 0;
    while (done < n) {
        const int rc = sceIoWrite(fd, (const char *)data + done, (SceSize)(n - done));
        if (rc <= 0) { sceIoClose(fd); return WB_E_IO; }
        done += (size_t)rc;
    }
    sceIoClose(fd);
    return WB_OK;
}

int wb_vita_read_small(const char *path, void *buf, size_t cap, size_t *n) {
    const int fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) return WB_E_IO;
    const int got = sceIoRead(fd, buf, (SceSize)cap);
    sceIoClose(fd);
    if (got < 0) return WB_E_IO;
    if (n) *n = (size_t)got;
    return WB_OK;
}
