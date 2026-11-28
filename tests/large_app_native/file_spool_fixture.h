#ifndef WB_TEST_FILE_SPOOL_H
#define WB_TEST_FILE_SPOOL_H
/* Host-only temporary-file adapter for the production protected spool. Does
 * not call Vita FS/stage mocks or count as an installation-side effect. */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include "wb_app_spool.h"
static FILE *test_spool_file;
static uint64_t test_spool_size;
static unsigned test_spool_opens,test_spool_closes;
static bool test_spool_begin_fail,test_spool_write_fail,test_spool_finish_fail,test_spool_dispose_fail;
static int test_seek(FILE *file,uint64_t off) {
#ifdef _WIN32
    return _fseeki64(file,(__int64)off,SEEK_SET);
#else
    if(off>(uint64_t)LONG_MAX)return -1;
    return fseek(file,(long)off,SEEK_SET);
#endif
}
static int test_spool_read(const void *ctx,uint64_t off,void *data,size_t n) {
    FILE *file=(FILE *)ctx;
    if(test_seek(file,off) || fread(data,1,n,file)!=n)return WB_E_IO;
    return WB_OK;
}
static int test_spool_begin(void *ctx,uint64_t size,void **handle) {
    (void)ctx;*handle=NULL;
    if(test_spool_begin_fail)return WB_E_IO;
    FILE *file=tmpfile();if(!file)return WB_E_IO;
    test_spool_file=file;test_spool_size=size;test_spool_opens++;*handle=file;
    return WB_OK;
}
static int test_spool_write(void *handle,const void *data,size_t n) {
    return test_spool_write_fail || fwrite(data,1,n,(FILE *)handle)!=n?WB_E_IO:WB_OK;
}
static int test_spool_finish(void *handle,wb_reader *reader) {
    if(test_spool_finish_fail || fflush((FILE *)handle))return WB_E_IO;
    *reader=(wb_reader){.ctx=handle,.size=test_spool_size,.read_at=test_spool_read};
    return WB_OK;
}
static int test_spool_dispose(void *handle) {
    test_spool_closes++;test_spool_file=NULL;
    int rc=fclose((FILE *)handle);
    return rc || test_spool_dispose_fail?WB_E_IO:WB_OK;
}
static const wb_app_spool_ops test_spool_ops={NULL,test_spool_begin,test_spool_write,test_spool_finish,test_spool_dispose};
#define WB_APP_IO_OPS (&test_spool_ops)
#endif
