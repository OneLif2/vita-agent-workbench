#ifndef WB_STUB_SYS_SOCKET_H
#define WB_STUB_SYS_SOCKET_H
#include <stdint.h>
#include <stddef.h>
typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;
typedef unsigned int in_addr_t;
enum { AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6, SOL_SOCKET = 1, SO_REUSEADDR = 2 };
struct sockaddr { unsigned char sa_len; sa_family_t sa_family; char sa_data[14]; };
int socket(int domain, int type, int protocol);
int bind(int fd, const struct sockaddr *addr, socklen_t len);
int listen(int fd, int backlog);
int accept(int fd, struct sockaddr *addr, socklen_t *len);
int close(int fd);
#endif
