#ifndef WB_APP_LOCAL_H
#define WB_APP_LOCAL_H
/* Owner-signed runtime approvals: a bounded, install-only extension of the
 * compiled catalog.
 *
 * Why this exists: adding one game build to the compiled table costs a full
 * core rebuild and a core deployment hop. An owner who already holds the
 * enrolled P-256 release key can instead authorize one exact artifact at
 * runtime. The device verifies that signature itself before writing anything,
 * so an SSH session alone (even a paired, authenticated one) can never approve
 * a package — it can only ask the owner's key to.
 *
 * Deliberate limits, none of which can be relaxed by a device-side command:
 *   - rows live in application-private savedata-adjacent storage under WB_ROOT,
 *     never in the host-writable VITA-POC upload root;
 *   - a row is (title, version, sha256) exactly, the same identity the compiled
 *     table uses, and duplicates of a compiled identity are refused;
 *   - runtime rows are INSTALL-ONLY: launch/`app launch` still needs a compiled
 *     case, so this cannot become a way to run arbitrary code;
 *   - the file is parsed with the same shape rules as apps.txt and a malformed
 *     or oversized file simply contributes no rows. */
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/* The verifier is compiled only where a real mbedTLS lives (the Vita build).
 * Host fixtures that only exercise the row table either set
 * WB_APP_LOCAL_NO_MBEDTLS or simply lack the header; the core then fails
 * loudly if it calls the verifier, so a missing crypto dependency can never
 * pass silently. */
#if !defined(WB_APP_LOCAL_NO_MBEDTLS) && defined(__has_include)
#  if __has_include(<mbedtls/ecdsa.h>)
#    define WB_APP_LOCAL_HAVE_MBEDTLS 1
#    include <mbedtls/ecdsa.h>
#  endif
#endif

/* Values and scalar rules only: the row table must not depend on mbedTLS, so a
 * host fixture can compile it without a crypto toolchain. */
#include "wb_standing_message.h"
#include "wb_standing_provision.h"
#include "wb_sha256.h"
#include "wb_vita_io.h"

#define WB_APP_LOCAL_PATH "ux0:data/INAP00018/apps.local"
enum { WB_APP_LOCAL_ROWS = 64, WB_APP_LOCAL_FILE = 8192, WB_APP_LOCAL_MSG = 160 };

typedef struct { char title[10]; char ver[6]; char sha[65]; } wb_app_row;
static wb_app_row wb_app_local_rows[WB_APP_LOCAL_ROWS];
static unsigned wb_app_local_count;

static bool wb_app_local_hex(const char *h, size_t n) {
    return h && strlen(h) == n && strspn(h, "0123456789abcdef") == n;
}
static bool wb_app_local_shape(const char *t, const char *v, const char *h) {
    if (!t || !v || !h) return false;
    if (strlen(t) != 9 || strlen(v) != 5 || strlen(h) != 64) return false;
    for (unsigned i = 0; i < 9; ++i)
        if (!((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= '0' && t[i] <= '9'))) return false;
    if (v[2] != '.') return false;
    for (unsigned i = 0; i < 5; ++i)
        if (i != 2 && !(v[i] >= '0' && v[i] <= '9')) return false;
    return wb_app_local_hex(h, 64);
}
/* The exact bytes the owner's key signs. The device rebuilds them from what it
 * read off the package, so the signature binds the file, not a claim about it. */
#if defined(__GNUC__)
__attribute__((unused))
#endif
static bool wb_app_local_message(char out[WB_APP_LOCAL_MSG], const char *t, const char *v,
                                 unsigned long long bytes, const char *h) {
    if (!wb_app_local_shape(t, v, h)) return false;
    const int n = snprintf(out, WB_APP_LOCAL_MSG,
                           "WB-APP-APPROVE-v1\nTITLE %s\nVER %s\nBYTES %llu\nSHA256 %s\n",
                           t, v, bytes, h);
    return n > 0 && n < WB_APP_LOCAL_MSG;
}
static bool wb_app_local_add(const char *t, const char *v, const char *h) {
    if (!wb_app_local_shape(t, v, h)) return false;
    for (unsigned i = 0; i < wb_app_local_count; ++i)
        if (!strcmp(wb_app_local_rows[i].title, t) && !strcmp(wb_app_local_rows[i].ver, v))
            return !strcmp(wb_app_local_rows[i].sha, h);   /* same row: idempotent */
    if (wb_app_local_count >= WB_APP_LOCAL_ROWS) return false;
    wb_app_row *r = &wb_app_local_rows[wb_app_local_count++];
    memcpy(r->title, t, 10); memcpy(r->ver, v, 6); memcpy(r->sha, h, 65);
    return true;
}
#if defined(__GNUC__)
__attribute__((unused))
#endif
static void wb_app_local_load(void) {
    char buf[WB_APP_LOCAL_FILE];
    size_t n = 0;
    wb_app_local_count = 0;
    if (wb_vita_read_small(WB_APP_LOCAL_PATH, buf, sizeof buf - 1, &n) != WB_OK) return;
    buf[n] = 0;
    char *line = buf;
    while (line && *line) {
        char *end = strchr(line, '\n');
        if (end) *end = 0;
        char t[10], v[6], h[65], extra[2], junk[2];
        /* Exactly "TITLE VER SHA -" and nothing else: the fourth token must be
         * the literal '-', and a fifth token disqualifies the line. */
        if (sscanf(line, "%9s %5s %64s %1s %1s", t, v, h, extra, junk) == 4 && extra[0] == '-') {
            (void)wb_app_local_add(t, v, h);
        }
        line = end ? end + 1 : NULL;
    }
}
static bool wb_app_local_title(const char *t) {
    if (!t) return false;
    for (unsigned i = 0; i < wb_app_local_count; ++i)
        if (!strcmp(wb_app_local_rows[i].title, t)) return true;
    return false;
}
/* 1 = exact artifact, 0 = this title+version but a different digest,
 * -1 = no runtime row for that title+version. Same distinction a compiled row
 * gives, so the refusal code stays informative. */
static int wb_app_local_match(const char *t, const char *v, const char *h) {
    for (unsigned i = 0; i < wb_app_local_count; ++i)
        if (!strcmp(wb_app_local_rows[i].title, t) && !strcmp(wb_app_local_rows[i].ver, v))
            return (h && !strcmp(h, wb_app_local_rows[i].sha)) ? 1 : 0;
    return -1;
}
#if defined(__GNUC__)
__attribute__((unused))
#endif
static bool wb_app_local_persist(void) {
    char *buf = (char *)malloc(WB_APP_LOCAL_FILE);
    if (!buf) return false;
    size_t used = 0;
    bool ok = true;
    for (unsigned i = 0; i < wb_app_local_count; ++i) {
        const wb_app_row *r = &wb_app_local_rows[i];
        const int n = snprintf(buf + used, WB_APP_LOCAL_FILE - used, "%s %s %s -\n", r->title, r->ver, r->sha);
        if (n <= 0 || (size_t)n >= WB_APP_LOCAL_FILE - used) { ok = false; break; }
        used += (size_t)n;
    }
    if (ok) ok = (wb_vita_write_file(WB_APP_LOCAL_PATH, buf, used, false) == WB_OK);
    free(buf);
    if (ok) wb_app_local_load();
    return ok;
}
#if defined(__GNUC__)
__attribute__((unused))
#endif
static bool wb_app_local_prune(const char *title_or_null, unsigned *removed_out) {
    unsigned kept = 0, removed = 0;
    for (unsigned i = 0; i < wb_app_local_count; ++i) {
        if (!title_or_null || !strcmp(wb_app_local_rows[i].title, title_or_null)) {
            removed++;
        } else {
            if (kept != i) wb_app_local_rows[kept] = wb_app_local_rows[i];
            kept++;
        }
    }
    wb_app_local_count = kept;
    if (removed_out) *removed_out = removed;
    if (!removed) return true;
    return wb_app_local_persist();
}
/* Verify the owner's signature over this exact artifact, then persist the row.
 * Order matters: nothing is written before the signature checks out. */
#if defined(WB_APP_LOCAL_HAVE_MBEDTLS)
static bool wb_owner_verify_message(const char *msg,const char *rs,const char *ss) {
    char key_id[65];
    if (!msg || !*msg) return false;
    if (!wb_standing_scalars(rs, ss) || !wb_standing_hex(WB_STANDING_SEC1, 130)) return false;
    unsigned char sec[65], r[32], s[32], hash[32];
    wb_sha256 sh;
    wb_standing_decode(WB_STANDING_SEC1, sec, sizeof sec);
    if (sec[0] != 4) return false;
    wb_sha256_init(&sh); wb_sha256_update(&sh, sec, sizeof sec); wb_sha256_final(&sh, hash);
    wb_sha_hex(hash, sizeof hash, key_id);
    if (strcmp(key_id, WB_STANDING_SIGNER)) return false;
    wb_standing_decode(rs, r, sizeof r);
    wb_standing_decode(ss, s, sizeof s);
    wb_sha256_init(&sh); wb_sha256_update(&sh, msg, strlen(msg)); wb_sha256_final(&sh, hash);
    mbedtls_ecp_group group; mbedtls_ecp_point pt; mbedtls_mpi mr, ms;
    mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&pt);
    mbedtls_mpi_init(&mr); mbedtls_mpi_init(&ms);
    const bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
                    mbedtls_ecp_point_read_binary(&group, &pt, sec, sizeof sec) == 0 &&
                    mbedtls_ecp_check_pubkey(&group, &pt) == 0 &&
                    mbedtls_mpi_read_binary(&mr, r, sizeof r) == 0 &&
                    mbedtls_mpi_read_binary(&ms, s, sizeof s) == 0 &&
                    mbedtls_ecdsa_verify(&group, hash, sizeof hash, &pt, &mr, &ms) == 0;
    mbedtls_mpi_free(&ms); mbedtls_mpi_free(&mr);
    mbedtls_ecp_point_free(&pt); mbedtls_ecp_group_free(&group);
    return ok;
}
static bool wb_app_local_approve(const char *t, const char *v, unsigned long long bytes,
                                 const char *h, const char *rs, const char *ss) {
    char msg[WB_APP_LOCAL_MSG];
    if(!wb_app_local_message(msg,t,v,bytes,h)||!wb_owner_verify_message(msg,rs,ss))return false;
    /* Reload first so capacity/dedup checks reflect durable state. */
    wb_app_local_load();
    for (unsigned i = 0; i < wb_app_local_count; ++i) {
        if (!strcmp(wb_app_local_rows[i].title, t) && !strcmp(wb_app_local_rows[i].ver, v)) {
            /* Same title+ver: idempotent if same SHA, else update SHA in place. */
            if (!strcmp(wb_app_local_rows[i].sha, h)) return true;
            memcpy(wb_app_local_rows[i].sha, h, 65);
            return wb_app_local_persist();
        }
    }
    if (!wb_app_local_add(t, v, h)) return false;
    if (!wb_app_local_persist()) { wb_app_local_load(); return false; }
    return wb_app_local_match(t, v, h) == 1;
}
#endif /* WB_APP_LOCAL_HAVE_MBEDTLS */
#endif
