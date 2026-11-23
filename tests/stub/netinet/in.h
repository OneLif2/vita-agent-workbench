#ifndef WB_STUB_NETINET_IN_H
#define WB_STUB_NETINET_IN_H
#include <sys/socket.h>
struct in_addr { in_addr_t s_addr; };
struct sockaddr_in {
    unsigned char sin_len;
    sa_family_t sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};
unsigned short htons(unsigned short v);
#endif
