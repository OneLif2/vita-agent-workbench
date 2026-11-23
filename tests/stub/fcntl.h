#ifndef WB_STUB_FCNTL_H
#define WB_STUB_FCNTL_H
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 0x0004
int fcntl(int fd, int cmd, ...);
#endif
