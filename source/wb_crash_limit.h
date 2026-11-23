#ifndef WB_CRASH_LIMIT_H
#define WB_CRASH_LIMIT_H
enum { WB_CRASH_DEFAULT=10, WB_CRASH_MAX=32, WB_CRASH_SCAN_MAX=1024 };
/* Canonical decimal: no leading zero, signs, path, suffix or overflow. */
static inline unsigned wb_crash_limit(const char *s) {
    if(!s||s[0]<'1'||s[0]>'9')return 0;
    unsigned n=(unsigned)(s[0]-'0');
    if(!s[1])return n;
    if(s[1]<'0'||s[1]>'9'||s[2])return 0;
    n=n*10+(unsigned)(s[1]-'0');
    return n<=WB_CRASH_MAX?n:0;
}
#endif
