#ifndef WB_VITA_INSTALL_H
#define WB_VITA_INSTALL_H

#include <stdbool.h>
#include <stddef.h>

#include "wb_install.h"
#include "wb_vita_io.h"
#include "wb_out.h"
void wb_vita_forget_remove_plan(void);
int wb_vita_managed_app_command(const char *title,int action,const char *token,const char *run,wb_out *out,int *status);
int wb_vita_ssh_vita_command(const char *title,bool uninstall,wb_out *out,int *status);

typedef struct {
    wb_vwriter writer;
    wb_vfile   vfile;
    bool       vfile_open;
    int        promote_detail;
    int        period_rc;
    char       last_error[96];
} wb_vita_install;

/* Fills a backend whose ctx is the wb_vita_install instance. */
const wb_inst_backend *wb_vita_install_backend(wb_vita_install *vi);

/* Promotes an already populated package directory. detail receives the last
 * promoter/appmgr return code for the log. */
/* Read-only, calibrated registration result for INAP00019 only. */
int wb_vita_updater_registered(int *registered,int *detail);

int wb_vita_promote_stage(const char *stage, bool skip_period, int *detail);

#endif
