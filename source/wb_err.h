#ifndef WB_ERR_H
#define WB_ERR_H

enum {
    WB_OK            =   0,
    WB_E_ARG         =  -1,
    WB_E_IO          =  -2,
    WB_E_FORMAT      =  -3,
    WB_E_UNSUPPORTED =  -4,
    WB_E_LIMIT       =  -5,
    WB_E_VERSION     =  -6,
    WB_E_TITLE       =  -7,
    WB_E_SHA         =  -8,
    WB_E_STAGE       =  -9,
    WB_E_PROMOTE     = -10,
    WB_E_ABI         = -11,
    WB_E_BUSY        = -12,
    WB_E_PATH        = -13,
    WB_E_STATE       = -14,
    WB_E_NOMEM       = -15,
    WB_E_TIMEOUT     = -16,
    WB_E_PARTIAL     = -17
};

const char *wb_err_name(int code);

#endif
