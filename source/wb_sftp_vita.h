#ifndef WB_SFTP_VITA_H
#define WB_SFTP_VITA_H

#include "wb_sftp_ro.h"

/* Incoming-only virtual root. No native mount or Workbench-private directory is
 * addressable through this interface. Caller owns each returned descriptor. */
extern const wb_sftp_ops wb_sftp_vita_ops;
#ifdef WB_TTY_FILE
extern const wb_sftp_write_ops wb_sftp_vita_write_ops;
#endif

#endif
