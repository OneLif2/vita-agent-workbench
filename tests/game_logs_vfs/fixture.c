/* SDK mock. The shell implementation and actual byte-level text checks are
 * compiled unmodified. No device or external filesystem is used. */
#include "wb_shell_vfs.h"
#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {DIR=0x1000,REG=0x2000,LINK=0x4000};
enum {ROOT,DATA,IN,PRIVATE,APP,SENSITIVE,WK,DIAG,SUB,TEXT,LINKED,DOT,CTRL,
      UPPER,TMP,SPACE,BADDATE,NEG,WRONG,WEIRD,EXTRA,GAME,GLOG,GSUB,GTEXT,GEMPTY,GBIN,GSECRET,GLINK,GPREFIX,
      PERF,PLOG,PTEXT,PSECRET,PPREFIX,NODE_COUNT};
typedef struct{const char *name;int parent,type;} node;
static const node n[NODE_COUNT]={
    {"",-1,DIR},{"data",ROOT,DIR},{"VITA-POC",ROOT,DIR},{"tai",ROOT,DIR},{"app",ROOT,DIR},
    {"account",DATA,DIR},{"INAP00018",DATA,DIR},{"run.log",WK,REG},
    {"sub",IN,DIR},{"plain.txt",SUB,REG},{"link",IN,LINK},{".hidden",IN,REG},
    {"bad\033name",IN,REG},{"HOST.PRIVATE",WK,REG},{"peer.txt",WK,REG},
    {"two words.txt",IN,REG},{"unknown-time",IN,REG},{"negative",IN,REG},
    {"timeline.txt",WK,DIR},{"sub.link",SUB,LINK},{"secret-dir",WK,DIR},
    {"RJGM52237",DATA,DIR},{"Logs",GAME,DIR},{"nested",GLOG,DIR},{"frame.log",GLOG,REG},
    {"empty.log",GLOG,REG},{"audio.bin",GSUB,REG},{"save.dat",GAME,REG},{"link",GLOG,LINK},{"LogsX",GAME,DIR},
    {"RJGP52237",DATA,DIR},{"Logs",PERF,DIR},{"bench.log",PLOG,REG},{"save.dat",PERF,REG},{"LogsX",PERF,DIR}};
typedef struct{int used,id,pos;} fdstate;
static fdstate f[16];
static int fileopens,diropens,dreads,forceclose,readfail,dirfail,huge,shortreads,
           symlink_root,zerotested,rawcat,grow,toolong,fullscan;
static int game_symlink=-1;
static unsigned char content[5000]="hello\n";static int content_n=6;
static size_t matches=0;static char last[12300];static int outfail;
static int emit(void *ctx,const char *b,size_t z){
    (void)ctx;if(outfail)return -2;
    assert(z<sizeof last);memcpy(last,b,z);last[z]=0;return 0;
}
static wb_out out={NULL,emit};
static void reset(void){last[0]=0;outfail=0;}
static int findpath(const char *path){
    assert(!strncmp(path,"ux0:/",5));int id=ROOT;const char *p=path+5;
    while(*p){const char *slash=strchr(p,'/');size_t z=slash?(size_t)(slash-p):strlen(p);
        int next=-1;for(int i=1;i<NODE_COUNT;++i)if(n[i].parent==id&&strlen(n[i].name)==z&&!memcmp(n[i].name,p,z)){next=i;break;}
        if(next<0)return -1;
        id=next;if(!slash)break;p=slash+1;}
    return id;
}
static int fdnew(int id){for(int i=0;i<16;++i)if(!f[i].used){f[i]=(fdstate){1,id,0};return i;}abort();}
static int drop(int fd){assert(fd>=0&&fd<16&&f[fd].used);f[fd].used=0;return forceclose?-1:0;}
int sceIoDclose(int fd){return drop(fd);}
int sceIoClose(int fd){return drop(fd);}
int sceIoDopen(const char *path){
    ++diropens;int id=findpath(path);assert(id==ROOT||id==DATA||id==IN||id==WK||id==SUB||id==GAME||id==GLOG||id==GSUB||id==PERF||id==PLOG);
    return fdnew(id);
}
int sceIoOpen(const char *path,int flags,SceMode mode){
    ++fileopens;assert(flags==SCE_O_RDONLY&&mode==0);int id=findpath(path);
    assert(id==TEXT||id==DIAG||id==SPACE||id==BADDATE||id==GTEXT||id==GEMPTY||id==GBIN||id==PTEXT);return fdnew(id);
}
int sceIoRead(int fd,void *dst,SceSize limit){
    assert(f[fd].used);rawcat++;if(readfail)return -1;
    int left=content_n-f[fd].pos;
    if(left<=0){if(grow){*(char*)dst='X';return 1;}return 0;}
    int take=left>(int)limit?(int)limit:left;if(shortreads&&take>3)take=3;
    memcpy(dst,content+f[fd].pos,(size_t)take);f[fd].pos+=take;return take;
}
int sceIoDread(int fd,SceIoDirent *e){
    assert(f[fd].used);++dreads;
    for(size_t k=0;k<sizeof *e;k++)assert(!((unsigned char*)e)[k]);
    ++zerotested;if(dirfail)return -1;
    int parent=f[fd].id;
    if(fullscan&&parent==SUB){strcpy(e->d_name,".excluded");e->d_stat.st_mode=REG;return 1;}
    if(toolong&&parent==SUB){memset(e->d_name,'x',sizeof e->d_name);return 1;}
    if(huge&&parent==IN){strcpy(e->d_name,"abc012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");e->d_stat.st_mode=REG;return 1;}
    while(++f[fd].pos<NODE_COUNT){
        int i=f[fd].pos;if(n[i].parent!=parent)continue;strcpy(e->d_name,n[i].name);
        e->d_stat.st_mode=((symlink_root&&i==IN)||i==game_symlink?LINK:n[i].type)|0644;
        e->d_stat.st_size=i==NEG?-1:content_n;
        if(i!=BADDATE){
            e->d_stat.st_mtime.year=2026;e->d_stat.st_mtime.month=11;e->d_stat.st_mtime.day=22;
            e->d_stat.st_mtime.hour=4;e->d_stat.st_mtime.minute=1;
        }return 1;
    }
    return 0;
}
static void done(void){for(size_t i=0;i<16;i++)assert(!f[i].used);++matches;}
static void settext(const unsigned char *s,int length){memcpy(content,s,(size_t)length);content_n=length;}
#define ROOTSTR "ux0:/"
#define WBSTR "ux0:/data/INAP00018"
#define INSTR "ux0:/VITA-POC"
#define FILESTR INSTR "/sub/plain.txt"
#define LIST(p,lf) wb_vita_shell_list(NULL,p,lf,&out)
#define CAT(p) wb_vita_shell_cat(NULL,p,&out)
#define CD(p) wb_vita_shell_isdir(NULL,p,&out)
static void denycat(const char *s){reset();assert(CAT(s)==1&&!strncmp(last,"ERR ",4));done();}
int main(int argc,char **argv){
    if(argc>1&&!strcmp(argv[1],"--probe")){reset();int rc=LIST("ux0:/data/RJGM52237/Logs",0);printf("logs_list_rc=%d\n%s",rc,last);done();return 0;}
    assert(CD(ROOTSTR)==0);done();assert(CD(INSTR)==0);done();assert(CD(WBSTR)==0);done();
    reset();assert(!LIST(ROOTSTR,0)&&!strcmp(last,"data/\nVITA-POC/\n"));done();
    reset();assert(!LIST(ROOTSTR,1)&&strstr(last,"2026-11-22 04:01")&&!strstr(last,"tai/"));done();
    reset();assert(!LIST(ROOTSTR "data",0)&&!strcmp(last,"INAP00018/\nRJGM52237/\nRJGP52237/\n"));done();
    reset();assert(!LIST(WBSTR,0)&&!strcmp(last,"run.log\n"));done();
    reset();assert(!LIST(INSTR,0)&&strstr(last,"two words.txt\n")&&strstr(last,"sub/\n")&&
                   !strstr(last,".hidden")&&!strstr(last,"bad")&&!strstr(last,"link")&&!strstr(last,"negative"));done();
    reset();assert(!LIST(INSTR "/two words.txt",1)&&strstr(last,"-rw-r--r--")&&strstr(last,"6 2026-11-22")&&strstr(last,"two words.txt"));done();
    reset();assert(!LIST(INSTR "/unknown-time",1)&&strstr(last,"6 ?"));done();
    reset();assert(CD(FILESTR)==1&&strstr(last,"not a directory"));done();
    reset();assert(CAT(ROOTSTR)==1&&!strncmp(last,"ERR",3));done();
    const char *bad[]={NULL,"","/","ux0:","ux0:data","ur0:/tai","ux0:/data/../tai","ux0://data",
        "ux0:/app","ux0:/data/private","ux0:/data/INAP00018/host.private",
        WBSTR "/peer.txt",WBSTR "/mac-public-pin.txt",WBSTR "/stage/private",INSTR "/../data",
        INSTR "/.hidden",INSTR "/plain. ","ux0:/vita-poc",INSTR "/.\n",INSTR "/abc\\def",
        INSTR "/sub/tai:config","ux0:/VITA-POCX/name",INSTR "/",WBSTR "/run.log/"};
    for(size_t i=0;i<sizeof bad/sizeof bad[0];i++){int a=diropens,b=fileopens;denycat(bad[i]);assert(a==diropens&&b==fileopens);}
    int a=fileopens;denycat(INSTR "/MISSING");denycat(INSTR "/link");denycat(INSTR "/link/f");
    denycat(INSTR "/sub/sub.link/pwd");denycat(WBSTR "/timeline.txt");assert(fileopens==a);
    symlink_root=1;denycat(FILESTR);symlink_root=0;assert(fileopens==a);
    unsigned char cn[]={0xe4,0xbd,0xa0,0xe5,0xa5,0xbd,'\r','\n','a','\t','b'};settext(cn,sizeof cn);
    shortreads=1;reset();assert(!CAT(FILESTR)&&!strcmp(last,"\xe4\xbd\xa0\xe5\xa5\xbd\na b\n"));shortreads=0;done();
    const unsigned char bytes[][6]={{'a','b',0,1},{'a',27,'[','H'},{'a',127},{'a',13,'b'},
        {0xc0,0xaf},{0xc2,0x9b},{0xe2,0x80,0xae},{0xed,0xa0,0x80},{0xf4,0x90,0x80,0x80},{0xe3,0x80}};
    const int len[]={4,4,2,3,2,2,3,3,4,2};for(unsigned i=0;i<sizeof len/sizeof len[0];i++){settext(bytes[i],len[i]);denycat(FILESTR);assert(strstr(last,"safe UTF-8 text"));}
    content_n=4097;a=fileopens;denycat(FILESTR);assert(fileopens==a&&strstr(last,"4096"));
    memset(content,'a',4096);content_n=4096;reset();assert(!CAT(FILESTR)&&strlen(last)==4097);done();
    content_n=0;reset();assert(!CAT(FILESTR)&&!*last);done();
    settext((unsigned char*)"ok",2);reset();assert(!CAT(WBSTR "/run.log")&&!strcmp(last,"ok\n"));done();
    grow=1;denycat(FILESTR);grow=0;readfail=1;denycat(FILESTR);readfail=0;
    forceclose=1;denycat(FILESTR);forceclose=0;dirfail=1;denycat(FILESTR);dirfail=0;
    int old=dreads;fullscan=1;reset();assert(LIST(INSTR "/sub",0)==1&&strstr(last,"limit"));assert(dreads-old<530);fullscan=0;done();
    huge=1;reset();assert(LIST(INSTR,1)==1&&!strncmp(last,"ERR directory limit",19));huge=0;done();
    toolong=1;reset();assert(LIST(INSTR "/sub",1)==1&&!strncmp(last,"ERR",3));toolong=0;done();
    outfail=1;assert(LIST(ROOTSTR,1)<0&&CAT(FILESTR)<0&&CAT(WBSTR "/peer.txt")<0);done();
    /* New exact, read-only namespace; other game data remain hidden. */
    settext((unsigned char*)"frame_ms=16\n",12);
    reset();assert(!CD("ux0:/data/RJGM52237"));done();
    reset();assert(!LIST("ux0:/data/RJGM52237",0)&&!strcmp(last,"Logs/\n"));done();
    reset();assert(!LIST("ux0:/data/RJGM52237/Logs",0)&&strstr(last,"nested/")&&strstr(last,"frame.log")&&!strstr(last,"link"));done();
    reset();assert(!CAT("ux0:/data/RJGM52237/Logs/frame.log")&&!strcmp(last,"frame_ms=16\n"));done();
    const char *private_paths[]={"ux0:/data/RJGM52237/save.dat","ux0:/data/RJGM52237/LogsX",
      "ux0:/data/RJGM52237/logs/frame.log","ux0:/data/RJGM52238/Logs/frame.log",
      "ux0:/data/RJGM52237/Logs/../save.dat","ux0:/data/RJGM52237/Logs//frame.log",
      "ux0:/data/RJGM52237/Logs/.hidden","ux0:/data/RJGM52237/Logs/link",
      "ux0:/data/RJGM52237/Logs/frame.log/child"};
    for(unsigned k=0;k<sizeof private_paths/sizeof private_paths[0];k++)denycat(private_paths[k]);
    reset();assert(!CD("ux0:/data/RJGP52237"));done();
    reset();assert(!LIST("ux0:/data/RJGP52237",0)&&!strcmp(last,"Logs/\n"));done();
    reset();assert(!CAT("ux0:/data/RJGP52237/Logs/bench.log")&&!strcmp(last,"frame_ms=16\n"));done();
    const char *perf_private[]={"ux0:/data/RJGP52237/save.dat","ux0:/data/RJGP52237/LogsX",
      "ux0:/data/RJGP52237/logs/bench.log","ux0:/data/RJGP52238/Logs/bench.log",
      "ux0:/data/RJGP52237/Logs/../save.dat","ux0:/data/RJGP52237"};
    for(unsigned k=0;k<sizeof perf_private/sizeof perf_private[0];k++)denycat(perf_private[k]);
    const int links[]={GAME,GLOG,GSUB,GTEXT};
    for(unsigned k=0;k<sizeof links/sizeof links[0];k++){
      game_symlink=links[k];int opens=fileopens;
      denycat(k==2?"ux0:/data/RJGM52237/Logs/nested/audio.bin":"ux0:/data/RJGM52237/Logs/frame.log");
      assert(fileopens==opens);game_symlink=-1;
    }
#ifdef WB_TEST_GAME_READ_API
    int fd=-1;assert(!wb_vita_shell_open_game_log("ux0:/data/RJGM52237/Logs/nested/audio.bin",&fd)&&fd>=0);
    unsigned char buf[32]={0};assert(sceIoRead(fd,buf,sizeof buf)==12&&!memcmp(buf,"frame_ms=16\n",12));assert(!sceIoClose(fd));done();
    assert(wb_vita_shell_open_game_log("ux0:/data/RJGM52237/Logs",&fd)<0&&fd==-1);done();
    for(unsigned k=0;k<sizeof private_paths/sizeof private_paths[0];k++){
      int opens=fileopens;assert(wb_vita_shell_open_game_log(private_paths[k],&fd)<0&&fd==-1);assert(fileopens==opens);done();
    }
    memset(buf,0,sizeof buf);
    assert(!wb_vita_shell_open_game_log("ux0:/data/RJGP52237/Logs/bench.log",&fd)&&fd>=0);
    assert(sceIoRead(fd,buf,sizeof buf)==12&&!memcmp(buf,"frame_ms=16\n",12));assert(!sceIoClose(fd));done();
    assert(wb_vita_shell_open_game_log("ux0:/data/RJGP52237/Logs",&fd)<0&&fd==-1);done();
    for(unsigned k=0;k<sizeof perf_private/sizeof perf_private[0];k++){
      int opens=fileopens;assert(wb_vita_shell_open_game_log(perf_private[k],&fd)<0&&fd==-1);assert(fileopens==opens);done();
    }
    assert(wb_vita_shell_open_game_log("ux0:/VITA-POC/sub/plain.txt",&fd)<0&&fd==-1);done();
    assert(wb_vita_shell_open_game_log("ux0:/data/INAP00018/run.log",&fd)<0&&fd==-1);done();
    assert(wb_vita_shell_open_game_log(NULL,&fd)<0&&fd==-1);done();
    assert(wb_vita_shell_open_game_log("ux0:/data/RJGM52237/Logs/frame.log",NULL)<0);done();
#endif
    assert(zerotested&&rawcat);
    printf("PASS %u native VFS case groups: root projection, exact paths/types, cwd verification, ls details, bounded UTF-8 cat, no ANSI or metadata leaks, I/O and output errors, all handles closed\n",(unsigned)matches);
    return 0;
}
