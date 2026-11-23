#include "wb_err.h"

const char *wb_err_name(int code) {
    switch (code) {
        case WB_OK:            return "OK";
        case WB_E_ARG:         return "bad-argument";
        case WB_E_IO:          return "io-error";
        case WB_E_FORMAT:      return "bad-format";
        case WB_E_UNSUPPORTED: return "unsupported";
        case WB_E_LIMIT:       return "limit-exceeded";
        case WB_E_VERSION:     return "version-not-newer";
        case WB_E_TITLE:       return "foreign-title-id";
        case WB_E_SHA:         return "sha256-mismatch";
        case WB_E_STAGE:       return "stage-failed";
        case WB_E_PROMOTE:     return "promote-failed";
        case WB_E_ABI:         return "payload-abi-mismatch";
        case WB_E_BUSY:        return "busy";
        case WB_E_PATH:        return "path-denied";
        case WB_E_STATE:       return "bad-state";
        case WB_E_NOMEM:       return "out-of-memory";
        case WB_E_TIMEOUT:     return "timeout";
        case WB_E_PARTIAL:     return "short-io";
        default:               return "unknown-error";
    }
}
