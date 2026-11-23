/* Vita newlib's generic fd/stdio layer otherwise links socket read/write/close
 * even without a socket in our program. Fail closed for all three operations. */
#include <psp2/net/net.h>
int __wrap_sceNetRecv(int s,void *b,unsigned int n,int flags){(void)s;(void)b;(void)n;(void)flags;return -1;}
int __wrap_sceNetSend(int s,const void *b,unsigned int n,int flags){(void)s;(void)b;(void)n;(void)flags;return -1;}
int __wrap_sceNetSocketClose(int s){(void)s;return -1;}
