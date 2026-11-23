#ifndef WAKE_PROBE_PROTOCOL_H
#define WAKE_PROBE_PROTOCOL_H
/* PUBLIC DIAGNOSTICS ONLY. No network/receiver/readiness/close authority.
 * Wire format is little-endian, exact fixed size, no trailing bytes. Current
 * Vita ARM and build hosts are LE; offsets/sizes are checked below. RTC minus
 * system-time is only a bounded diagnostic reboot/clock fence, NOT a boot UUID. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#define WP_JOB_PATH "ux0:/data/INAP00018/wake-probe/job.bin"
#define WP_RESULT_PATH "ux0:/data/INAP00018/wake-probe/result.bin"
#define WP_JOB_BYTES 128u
#define WP_RESULT_BYTES 256u
#define WP_VERSION 1u
#define WP_JOB_TTL_US UINT64_C(30000000)
#define WP_LEASE_US UINT64_C(120000000)
#define WP_STEP_US UINT64_C(5000000)
#define WP_BOOT_TOLERANCE_US UINT64_C(2000000)
#define WP_DIAGNOSTIC_ONLY 1u
#define WP_RC_UNKNOWN INT32_MIN
#define WP_JOB_MAGIC "WBWPJ1\r\n"
#define WP_RESULT_MAGIC "WBWPR1\r\n"
typedef struct {
    char magic[8]; uint32_t version, bytes;
    char nonce[32], source_run[16], job_id[33]; uint8_t reserved[7];
    uint64_t issued_us, deadline_us, boot_epoch_us;
} wp_job;
typedef struct {
    char magic[8]; uint32_t version, bytes;
    char nonce[32], source_run[16], job_id[33]; uint8_t reserved[7];
    uint32_t stage, flags, first_error_step; int32_t first_error_rc, bg_rc, return_rc;
    uint64_t main_started_us, issued_us, deadline_us, arm_started_us;
    uint64_t observed_us, first_tick_us, last_tick_us, max_gap_us;
    uint32_t tick_count; int32_t worker_exit_rc; uint32_t main_exit_intent;
    uint8_t reserved_tail[52];
} wp_result;
_Static_assert(sizeof(wp_job)==WP_JOB_BYTES,"job wire size");
_Static_assert(offsetof(wp_job,issued_us)==104 && offsetof(wp_job,boot_epoch_us)==120,"job wire offsets");
_Static_assert(sizeof(wp_result)==WP_RESULT_BYTES,"result wire size");
_Static_assert(offsetof(wp_result,stage)==104 && offsetof(wp_result,main_started_us)==128 && offsetof(wp_result,tick_count)==192,"result wire offsets");
enum { WP_STAGE_VALIDATED=1, WP_STAGE_CLAIMED, WP_STAGE_ARMED, WP_STAGE_BG_REQUEST,
       WP_STAGE_RETURN_REQUEST, WP_STAGE_WORKER_TICK, WP_STAGE_WORKER_STOP, WP_STAGE_FAILURE };
enum { WP_E_INIT=1, WP_E_CLOCK, WP_E_JOB_READ, WP_E_JOB_INVALID, WP_E_ACTIVE,
       WP_E_CLAIM, WP_E_CONSUME, WP_E_TRACE, WP_E_ARM, WP_E_BG_MODULE,
       WP_E_BG_START, WP_E_RETURN, WP_E_RECEIPT, WP_E_PUBLIC, WP_E_WORKER };
enum { WP_BAD_SIZE=-7101, WP_BAD_JOB=-7102, WP_BAD_CLOCK=-7103, WP_REPLAY=-7104,
       WP_ACTIVE=-7105, WP_VERIFY=-7106, WP_BAD_STATE=-7107 };
static inline bool wp_zero(const void *p,size_t n){const uint8_t*b=p;for(size_t i=0;i<n;i++)if(b[i])return false;return true;}
static inline bool wp_hex(const char *p,size_t n,bool upper){bool nonzero=false;for(size_t i=0;i<n;i++){char c=p[i];if(!((c>='0'&&c<='9')||(c>='A'&&c<='F')||(!upper&&c>='a'&&c<='f')))return false;if(c!='0')nonzero=true;}return nonzero;}
static inline bool wp_job_id(const char p[33]){size_t n=0;for(;n<33&&p[n];n++){char c=p[n];if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-'))return false;}return n>0&&n<=32&&wp_zero(p+n+1,32-n);}
static inline bool wp_epoch_valid(uint64_t expected,uint64_t actual){return expected&&actual&&(expected>actual?expected-actual:actual-expected)<=WP_BOOT_TOLERANCE_US;}
static inline bool wp_job_shape(const wp_job*j){return j&&!memcmp(j->magic,WP_JOB_MAGIC,8)&&j->version==WP_VERSION&&j->bytes==WP_JOB_BYTES&&wp_hex(j->nonce,32,false)&&wp_hex(j->source_run,16,true)&&wp_job_id(j->job_id)&&wp_zero(j->reserved,sizeof j->reserved)&&j->issued_us&&j->deadline_us>j->issued_us&&j->deadline_us-j->issued_us<=WP_JOB_TTL_US&&j->boot_epoch_us;}
static inline bool wp_job_live(const wp_job*j,uint64_t now,uint64_t epoch){return wp_job_shape(j)&&now>=j->issued_us&&now<j->deadline_us&&wp_epoch_valid(j->boot_epoch_us,epoch);}
static inline void wp_result_init(wp_result*r,const wp_job*j){memset(r,0,sizeof *r);memcpy(r->magic,WP_RESULT_MAGIC,8);r->version=WP_VERSION;r->bytes=WP_RESULT_BYTES;memcpy(r->nonce,j->nonce,32);memcpy(r->source_run,j->source_run,16);memcpy(r->job_id,j->job_id,33);r->flags=WP_DIAGNOSTIC_ONLY;r->bg_rc=r->return_rc=r->worker_exit_rc=WP_RC_UNKNOWN;r->issued_us=j->issued_us;r->deadline_us=j->deadline_us;}
static inline bool wp_result_matches(const wp_result*r,const wp_job*j){return r&&wp_job_shape(j)&&!memcmp(r->magic,WP_RESULT_MAGIC,8)&&r->version==WP_VERSION&&r->bytes==WP_RESULT_BYTES&&r->flags==WP_DIAGNOSTIC_ONLY&&wp_zero(r->reserved,sizeof r->reserved)&&wp_zero(r->reserved_tail,sizeof r->reserved_tail)&&!memcmp(r->nonce,j->nonce,32)&&!memcmp(r->source_run,j->source_run,16)&&!memcmp(r->job_id,j->job_id,33)&&r->issued_us==j->issued_us&&r->deadline_us==j->deadline_us&&r->stage>=WP_STAGE_VALIDATED&&r->stage<=WP_STAGE_FAILURE&&r->tick_count<=24;}
static inline void wp_error(wp_result*r,uint32_t step,int32_t rc){if(!r->first_error_step){r->first_error_step=step;r->first_error_rc=rc;}r->stage=WP_STAGE_FAILURE;}
#endif
