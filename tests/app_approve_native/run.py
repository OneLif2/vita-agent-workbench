"""Host fixture for the 01.96 owner-signed runtime approval table (v2)."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
S = ROOT/'source'

FIXTURE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "wb_err.h"
#include "wb_vita_io.h"

/* Stubs for the two device I/O calls the row table uses. */
static char local_text[16384];
static size_t local_len;
static bool local_present;
int wb_vita_read_small(const char *p, void *buf, size_t cap, size_t *n) {
    (void)p;
    if (!local_present) return WB_E_IO;
    if (local_len > cap) return WB_E_FORMAT;
    memcpy(buf, local_text, local_len); *n = local_len; return WB_OK;
}
int wb_vita_write_file(const char *p, const void *d, size_t n, bool append) {
    (void)p;
    if (!append) local_len = 0;
    if (local_len + n > sizeof local_text) return WB_E_IO;
    memcpy(local_text + local_len, d, n); local_len += n; local_text[local_len] = 0;
    local_present = true; return WB_OK;
}

#define WB_STANDING_VERIFY_H 1     /* P-256 verifier is compiled by the Jetson build */
#define WB_APP_LOCAL_NO_MBEDTLS 1
#include "wb_app_local.h"
#include "wb_app_registry.h"

static void set_file(const char *text) {
    memset(local_text, 0, sizeof local_text);
    local_len = strlen(text);
    memcpy(local_text, text, local_len);
    local_present = local_len > 0;
    wb_app_local_load();
}

#define RK(r) do { if (r) { printf("FAIL line %d code %d\n", __LINE__, r); return r; } } while (0)

int main(void) {
    const char *sha = "8d1f6043edb6f594bd4bca0b8c42d31a9b91f6b0c0d963c4041313fdfad0d22d";
    const char *other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    set_file("");
    RK(wb_app_local_count != 0);
    RK(wb_app_local_title("RJGM52237"));
    RK(wb_app_local_match("RJGM52237", "01.02", sha) != -1);

    set_file("RJGM52237 01.02 8d1f6043edb6f594bd4bca0b8c42d31a9b91f6b0c0d963c4041313fdfad0d22d -\n");
    RK(wb_app_local_count != 1);
    RK(!wb_app_local_title("RJGM52237"));
    RK(wb_app_local_match("RJGM52237", "01.02", sha) != 1);
    RK(wb_app_local_match("RJGM52237", "01.01", sha) != -1);
    RK(wb_app_local_match("RJGM52237", "01.02", other) != 0);
    RK(wb_app_local_match("RJGM52238", "01.02", sha) != -1);

    RK(wb_reg_install("RJGM52237", "01.02", sha) != WB_REG_OK);
    RK(wb_reg_install("RJGM52237", "01.02", other) != WB_REG_SHA256);
    RK(wb_reg_install("RJGM52237", "09.99", sha) != WB_REG_VERSION);
    RK(wb_reg_launch("RJGM52237", "01.02", "fs-smoke") != WB_REG_CASE);
    RK(wb_reg_install("INAP00020", "01.01",
        "fea70dc69399200bdf00ca145044cac7725b4987d19da9d032ff2dbfd12a43e9") != WB_REG_OK);

    set_file("RJGM52237 01.02 short -\n"
             "rjsm52237 01.02 8d1f6043edb6f594bd4bca0b8c42d31a9b91f6b0c0d963c4041313fdfad0d22d -\n"
             "RJGM52237 01.02 8d1f6043edb6f594bd4bca0b8c42d31a9b91f6b0c0d963c4041313fdfad0d22d extra\n");
    RK(wb_app_local_count != 0);

    set_file("RJGM52237 01.02 8d1f6043edb6f594bd4bca0b8c42d31a9b91f6b0c0d963c4041313fdfad0d22d -\n"
             "RJGM52237 01.02 8d1f6043edb6f594bd4bca0b8c42d31a9b91f6b0c0d963c4041313fdfad0d22d -\n");
    RK(wb_app_local_count != 1);

    /* 02.20: capacity raised to 64 rows + prune by title and all */
    RK(WB_APP_LOCAL_ROWS != 64);
    set_file("");
    for (unsigned i = 0; i < 20; i++) {
        char ver[6];
        snprintf(ver, sizeof ver, "01.%02u", i);
        RK(!wb_app_local_add(i < 12 ? "RJGP52237" : "RJGM52237", ver, sha));
    }
    RK(wb_app_local_count != 20);
    unsigned removed = 0;
    RK(!wb_app_local_prune("RJGP52237", &removed));
    RK(removed != 12 || wb_app_local_count != 8);
    RK(!wb_app_local_prune(NULL, &removed));
    RK(removed != 8 || wb_app_local_count != 0);

    puts("PASS owner-signed runtime rows are exact, install-only, 64-row bounded and prunable");
    return 0;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='wb-app-approve-') as tmp:
        t = Path(tmp)
        gen = subprocess.run([sys.executable, '-B', str(ROOT/'tools/gen_app_registry.py'), str(t/'wb_registry_data.inc')],
                             capture_output=True, text=True)
        if gen.returncode:
            print(gen.stdout, gen.stderr)
            return gen.returncode
        (t/'fixture.c').write_text(FIXTURE, encoding='utf-8')
        exe = t/('fixture.exe' if os.name == 'nt' else 'fixture')
        cmd = [os.environ.get('CC', 'gcc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-I'+str(t), '-I'+str(S), str(t/'fixture.c'),
               str(S/'wb_str.c'), '-o', str(exe)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            print(r.stdout, r.stderr)
            return r.returncode
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        print(run.stdout.strip(), flush=True)
        if run.returncode:
            print(run.stderr)
        return run.returncode


if __name__ == '__main__':
    raise SystemExit(main())
