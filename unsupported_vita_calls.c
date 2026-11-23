#include <sys/types.h>
#include <errno.h>
#include <stddef.h>
#include <pwd.h>
int dup2(int oldfd,int newfd) {
    (void)oldfd;(void)newfd;
    errno=ENOSYS; return -1;
}
pid_t waitpid(pid_t pid,int *status,int options) {
    (void)pid;(void)status;(void)options;
    errno=ENOSYS; return -1;
}
int execv(const char *path,char *const argv[]) {
    (void)path;(void)argv;
    errno=ENOSYS; return -1;
}
int getpwuid_r(uid_t uid,struct passwd *pw,char *buf,size_t buflen,struct passwd **result) {
    (void)uid;(void)pw;(void)buf;(void)buflen;
    if(result)*result=NULL;
    return ENOSYS;
}
struct passwd *getpwnam(const char *name) {
    (void)name; errno=ENOSYS; return NULL;
}
