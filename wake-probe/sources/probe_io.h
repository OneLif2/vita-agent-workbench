#ifndef WP_IO_H
#define WP_IO_H
#include "wake_probe_protocol.h"
#define WP_CLAIM_NAME "wake-probe-claim.bin"
#define WP_MAIN_NAME "wake-probe-main.bin"
#define WP_WORKER_ERROR_NAME "wake-probe-worker-error.bin"
int wp_read_exact(const char *path,void *out,unsigned len);
int wp_private_put(const char *name,const void *data,unsigned len);
int wp_load_claim(wp_job *job);
int wp_save_claim(const wp_job *job);
int wp_load_main(wp_result *result);
int wp_save_main(const wp_result *result);
int wp_publish(const wp_result *result);
int wp_clock(uint64_t *now,uint64_t *epoch);
static inline int wp_missing(int rc){return (uint32_t)rc==UINT32_C(0x80010002);}
#endif
