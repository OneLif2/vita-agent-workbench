/* Production TTY storage + TTY1 protocol, with the existing simulated Vita FS.
 * The VFS API is a strict fixture contract here; game_logs_vfs independently
 * tests the production exact-component/regular-file/read-only implementation. */
#include "wb_game_logs_path.h"
#define WB_TEST_GAME_LOG_API_CUSTOM 1
#define main legacy_tty_fixture_main
#include "../tty_vita/probe.c"
#undef main

static unsigned api_calls,api_opens;
static const char *const text_path=WB_GAME_LOG_ROOT "/run.log";
static const char *const binary_path=WB_GAME_LOG_ROOT "/nested/two words.bin";
static const char *const empty_path=WB_GAME_LOG_ROOT "/empty.log";
static const char *const large_path=WB_GAME_LOG_ROOT "/metadata-large.log";
static const char *const perf_text_path=WB_PERFLAB_LOG_ROOT "/bench.log";
static const char *const perf_binary_path=WB_PERFLAB_LOG_ROOT "/nested/audio.bin";
static const char *const perf_empty_path=WB_PERFLAB_LOG_ROOT "/empty.log";
int wb_vita_shell_open_game_log(const char *path,int *fd){
    api_calls++;assert(path&&fd);*fd=-1;
    /* Namespace membership is not validation: only these exact, modeled REG
     * entries pass, never directory, missing, alias, traversal or link input. */
    if(strcmp(path,text_path)&&strcmp(path,binary_path)&&strcmp(path,empty_path)&&strcmp(path,large_path)&&
       strcmp(path,perf_text_path)&&strcmp(path,perf_binary_path)&&strcmp(path,perf_empty_path))return -1;
    *fd=sceIoOpen(path,SCE_O_RDONLY,0);if(*fd<0)return -1;
    api_opens++;return 0;
}
static void setup(void){
    memset(fs,0,sizeof fs);api_calls=api_opens=0;io_writes=io_removes=0;
    int id=make(text_path);memcpy(fs[id].b,"hello\n",6);fs[id].n=6;
    id=make(binary_path);for(unsigned i=0;i<256;i++)fs[id].b[i]=(uint8_t)i;fs[id].n=256;
    (void)make(empty_path);
    id=make(large_path);fs[id].n=(size_t)WB_TRANSFER_MAX+1u;
    id=make(perf_text_path);memcpy(fs[id].b,"perf\n",5);fs[id].n=5;
    id=make(perf_binary_path);for(unsigned i=0;i<32;i++)fs[id].b[i]=(uint8_t)i;fs[id].n=32;
    (void)make(perf_empty_path);
}
static void filesystem_hash(char hex[65]){
    wb_sha256 h;uint8_t raw[32];wb_sha256_init(&h);
    for(unsigned i=0;i<24;i++){
        wb_sha256_update(&h,fs[i].name,sizeof fs[i].name);
        wb_sha256_update(&h,fs[i].b,sizeof fs[i].b);
        wb_sha256_update(&h,&fs[i].n,sizeof fs[i].n);
        wb_sha256_update(&h,&fs[i].isdir,sizeof fs[i].isdir);
    }
    wb_sha256_final(&h,raw);wb_sha_hex(raw,sizeof raw,hex);
}
static void readonly(const char before[65]){
    char after[65];filesystem_hash(after);assert(!strcmp(before,after));
    assert(!io_writes&&!io_removes&&!private_count());
}
static void protocol_get(const char *path,const uint8_t *want,size_t size){
    char before[65];filesystem_hash(before);
    wb_tty_file file;char command[WB_CMD_ARG_MAX+20];
    snprintf(command,sizeof command,"get \"%s\"",path);
    const char *error=wb_tty_begin(&file,command);assert(!error);
    char ready[128];snprintf(ready,sizeof ready,"TTY1 READY GET %zu 2048\r\n",size);assert(!strcmp(file.reply,ready));
    bool private_reply=false;char hash[65];uint8_t digest[32];wb_sha256 sha;wb_sha256_init(&sha);
    if(size){
        strcpy(file.line,"NEXT 0");file.n=6;assert(wb_tty_frame(&file,&private_reply)==1);
        char expected[640];size_t at=(size_t)snprintf(expected,sizeof expected,"TTY1 DATA 0 ");
        for(size_t i=0;i<size;i++)at+=(size_t)snprintf(expected+at,sizeof expected-at,"%02x",want[i]);
        strcpy(expected+at,"\r\n");assert(!strcmp(file.reply,expected));
        wb_sha256_update(&sha,want,size);
    }
    wb_sha256_final(&sha,digest);wb_sha_hex(digest,sizeof digest,hash);
    strcpy(file.line,"END");file.n=3;assert(wb_tty_frame(&file,&private_reply)==0&&!file.handle);
    char receipt[160];snprintf(receipt,sizeof receipt,"TTY1 OK GET %zu %s\r\n",size,hash);assert(!strcmp(file.reply,receipt));
    readonly(before);
}
static int one_probe(void){
    int id=find(binary_path);void *handle=NULL;uint64_t size=0;
    const char *error=wb_tty_vopen(false,binary_path,0,&handle,&size);
    if(error){printf("DENIED error=%s writes=%d removes=%d\n",error,io_writes,io_removes);return 0;}
    uint8_t bytes[256],raw[32];size_t got=0;assert(size==256);
    assert(!wb_tty_vread(handle,bytes,sizeof bytes,&got)&&got==256&&!memcmp(bytes,fs[id].b,256));
    assert(!wb_tty_vfinish(handle,true,NULL));
    wb_sha256 sha;wb_sha256_init(&sha);wb_sha256_update(&sha,bytes,got);wb_sha256_final(&sha,raw);
    char digest[65];wb_sha_hex(raw,sizeof raw,digest);
    printf("GET bytes=%llu sha256=%s api_checked=%u readonly=1 writes=%d removes=%d\n",(unsigned long long)size,digest,api_opens,io_writes,io_removes);
    return 0;
}
int main(int argc,char **argv){
    (void)&wb_s2_selftest;setup();
    if(argc==2&&!strcmp(argv[1],"--probe"))return one_probe();
    assert(wb_game_logs_path(WB_GAME_LOG_ROOT)&&wb_game_logs_path(text_path));
    assert(wb_game_logs_path(WB_PERFLAB_LOG_ROOT)&&wb_game_logs_path(WB_PERFLAB_LOG_ROOT "/bench.log"));
    assert(wb_game_logs_exact(WB_GAME_LOG_ROOT)&&wb_game_logs_exact(WB_PERFLAB_LOG_ROOT));
    assert(!wb_game_logs_exact(text_path)&&!wb_game_logs_exact(WB_PERFLAB_LOG_ROOT "/bench.log"));
    assert(wb_game_data_parent(WB_GAME_DATA_ROOT)&&wb_game_data_parent(WB_PERFLAB_DATA_ROOT));
    assert(!wb_game_data_parent(WB_GAME_LOG_ROOT)&&!wb_game_logs_path(WB_PERFLAB_DATA_ROOT));
    assert(wb_game_logs_path(WB_GAME_LOG_ROOT "/../SaveData/private.bin")); /* predicate != validation */
    const char *not_namespace[]={NULL,"",WB_GAME_DATA_ROOT,WB_PERFLAB_DATA_ROOT,WB_GAME_LOG_ROOT "X/run.log",
        WB_PERFLAB_LOG_ROOT "X/bench.log","ux0:/data/RJGP52237/save.dat","ux0:/data/RJGP52237/logs/bench.log",
        "ux0:/data/RJGP52238/Logs/bench.log",
        "ux0:data/RJGM52237/Logs/run.log","ux0:/data/RJGM52237/logs/run.log","ux0:/data/RJGM52238/Logs/run.log"};
    for(unsigned i=0;i<sizeof not_namespace/sizeof *not_namespace;i++)assert(!wb_game_logs_path(not_namespace[i]));
    puts("PASS shared namespace predicate selects exact root or slash descendants only; matching traversal suffix is NOT validation or an access grant");
    uint8_t bytes[256];for(unsigned i=0;i<256;i++)bytes[i]=(uint8_t)i;
    protocol_get(text_path,(const uint8_t *)"hello\n",6);protocol_get(binary_path,bytes,256);protocol_get(empty_path,NULL,0);
    assert(api_calls==3 && api_opens==3);
    protocol_get(perf_text_path,(const uint8_t *)"perf\n",5);
    protocol_get(perf_binary_path,bytes,32);protocol_get(perf_empty_path,NULL,0);
    assert(api_calls==6 && api_opens==6);
    puts("PASS actual TTY1 GET: checked VFS API used for text, nested space-name binary and empty log; exact READY/DATA/END SHA receipts; no remote mutation");
    puts("PASS separate RJGP52237 PerfLab TTY1 GET: exact text/binary/empty bytes+SHA, checked API, no alias to RJGM52237 and no writes/removes");
    const char *denied[]={WB_GAME_DATA_ROOT,WB_GAME_LOG_ROOT,WB_GAME_LOG_ROOT "/missing.log",
        WB_GAME_LOG_ROOT "/run.log/child",WB_GAME_LOG_ROOT "/../SaveData/private.bin",
        WB_GAME_LOG_ROOT "/./run.log",WB_GAME_LOG_ROOT "//run.log",WB_GAME_LOG_ROOT "/.hidden",
        WB_GAME_LOG_ROOT "/nested/link/private.bin",WB_GAME_LOG_ROOT "/RUN.log",WB_GAME_LOG_ROOT "X/run.log",
        "ux0:/data/RJGM52238/Logs/run.log","ux0:data/RJGM52237/Logs/run.log",
        "ux0:/data/RJGM52237/logs/run.log","ux0:/data/INAP00018/mac-public-pin.txt",
        WB_PERFLAB_DATA_ROOT,WB_PERFLAB_LOG_ROOT,WB_PERFLAB_LOG_ROOT "/missing.log",
        WB_PERFLAB_LOG_ROOT "/../save.dat","ux0:/data/RJGP52237/save.dat",
        "ux0:/data/RJGP52237/logs/bench.log","ux0:/data/RJGP52238/Logs/bench.log"};
    char before[65];filesystem_hash(before);
    for(unsigned i=0;i<sizeof denied/sizeof *denied;i++){
        unsigned opened=api_opens;void *handle=NULL;uint64_t size=99;
        assert(wb_tty_vopen(false,denied[i],0,&handle,&size)&&!handle&&!size&&api_opens==opened);
    }
    void *handle=NULL;uint64_t size=0;
    assert(!strcmp(wb_tty_vopen(false,large_path,0,&handle,&size),"bad-size")&&!handle);
    char long_path[WB_CMD_ARG_MAX+1];memset(long_path,'a',sizeof long_path-1);long_path[sizeof long_path-1]=0;
    assert(wb_tty_vopen(false,long_path,0,&handle,&size)&&!handle);
    readonly(before);
    puts("PASS GET refuses root/directory/missing/alias/traversal/link/private/overlength paths and uint32+1 metadata; namespace membership never bypasses checked API");
    const char *write_paths[]={WB_GAME_LOG_ROOT,text_path,binary_path,empty_path,
        WB_GAME_LOG_ROOT "/new.log",WB_GAME_LOG_ROOT "/../SaveData/private.bin",WB_GAME_DATA_ROOT,
        WB_PERFLAB_LOG_ROOT,perf_text_path,perf_binary_path,perf_empty_path,WB_PERFLAB_DATA_ROOT};
    filesystem_hash(before);unsigned calls_before=api_calls;
    for(unsigned i=0;i<sizeof write_paths/sizeof *write_paths;i++){
        const char *kind=NULL;
        assert(wb_tty_vopen(true,write_paths[i],3,&handle,&size)&&!handle);
        assert(wb_tty_vopen_stream(write_paths[i],&handle)&&!handle);
        assert(wb_tty_vmkdir(write_paths[i]));assert(wb_tty_vprobe(write_paths[i],&kind));
    }
    assert(api_calls==calls_before);readonly(before);
    assert(!wb_tty_vopen(false,text_path,0,&handle,&size));
    assert(wb_tty_vwrite(handle,(const uint8_t *)"NO",2));assert(!wb_tty_vfinish(handle,false,NULL));readonly(before);
    puts("PASS game Logs grants no PUT, stream, mkdir, tree probe or read-handle write; writes/removes/private-stage creation remain zero");
    /* Same original incoming and public diagnostics remain readable. */
    int id=make(WB_INCOMING "/original.bin");memcpy(fs[id].b,"old",3);fs[id].n=3;
    id=make(WB_ROOT "/run.log");memcpy(fs[id].b,"diag",4);fs[id].n=4;
    protocol_get(WB_INCOMING "/original.bin",(const uint8_t *)"old",3);
    protocol_get("ux0:/data/INAP00018/run.log",(const uint8_t *)"diag",4);
    puts("PASS existing incoming and INAP00018 diagnostic GET routes retain exact binary/SHA behavior");
    return 0;
}
