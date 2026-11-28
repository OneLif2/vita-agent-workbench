/* Production PTY packet engine and Vita adapter. Only the storage syscalls
 * are fakes, shared with the existing fault/no-clobber/readback tests. */
#define WB_TEST_FS_CAP (4u*1024u*1024u+11u)
#define main tiny_adapter_fixture
#include "../tty_vita/probe.c"
#undef main
#include <inttypes.h>
enum {F=2048,G=8};
static uint8_t data[WB_TEST_FS_CAP];
static wb_tty_file f;
static const char *dest=WB_INCOMING "/batch.bin";
static char sha[65];
static void bytes(size_t n){
    wb_sha256 s;uint8_t hash[32];
    for(size_t i=0;i<n;i++)data[i]=(uint8_t)((i*29u)^(i>>8));
    wb_sha256_init(&s);wb_sha256_update(&s,data,n);wb_sha256_final(&s,hash);wb_sha_hex(hash,sizeof hash,sha);
}
static void begin(size_t n,bool batch){
    char cmd[220],expect[155];bytes(n);
    snprintf(cmd,sizeof cmd,"%s \"%s\" %zu sha256=%s",batch?"put-batch":"put",dest,n,sha);
    assert(wb_tty_recognizes(cmd));assert(!wb_tty_begin(&f,cmd));
    snprintf(expect,sizeof expect,"TTY1 READY %s %zu 2048%s\r\n",batch?"BATCH":"PUT",n,batch?" 8":"");
    assert(!strcmp(f.reply,expect));io_writes=0;
}
static int frame(const char *s,bool *priv){
    if(s!=f.line){assert(strlen(s)<sizeof f.line);strcpy(f.line,s);}
    f.n=strlen(f.line);return wb_tty_frame(&f,priv);
}
static int send_data(size_t off,size_t z,bool *priv){
    const char *hex="0123456789abcdef";int j=snprintf(f.line,sizeof f.line,"D %zu ",off);
    assert(z<=F && off+z<=sizeof data);
    for(size_t i=0;i<z;i++){unsigned c=data[off+i];f.line[j++]=hex[c>>4];f.line[j++]=hex[c&15];}
    f.line[j]=0;return frame(f.line,priv);
}
static void upload(size_t n,bool batch){
    begin(n,batch);size_t written=0;int acks=0;bool priv=false;
    for(size_t off=0;off<n;){
        const size_t z=n-off<F?n-off:F;assert(send_data(off,z,&priv)==1);off+=z;
        if(!batch || off%(F*G)==0 || off==n){
            written=off;acks++;
            char reply[80];snprintf(reply,sizeof reply,"TTY1 ACK %zu\r\n",off);
            assert(priv && !strcmp(f.reply,reply));
        }else assert(!priv && !f.reply[0]);
        assert(f.offset==written&&io_writes==acks&&find(dest)<0);
    }
    assert(!frame("END",&priv)&&!priv);
    char final[200];snprintf(final,sizeof final,"TTY1 OK PUT %zu %s\r\n",n,sha);
    assert(!strcmp(f.reply,final)&&!private_count());
    int idx=find(dest);assert(idx>0&&fs[idx].n==n&&!memcmp(fs[idx].b,data,n));
    printf("%s bytes=%zu data_frames=%zu sceIoWrite=%d cumulative_ACK=%d sha256=%s published=1\n",
           batch?"batch":"legacy",n,(n+F-1)/F,io_writes,acks,sha);
}
static void bad(const char *which){
    const size_t n=8*F+17;begin(n,true);bool priv=false;
    assert(send_data(0,F,&priv)==1 && !f.reply[0]&&!priv&&f.offset==0&&io_writes==0);
    int rc=-99;
    if(!strcmp(which,"abort")){
        wb_tty_abort(&f);wb_tty_abort(&f);assert(!private_count()&&find(dest)<0&&!io_writes);return;
    }
    if(!strcmp(which,"cancel"))rc=frame("CANCEL",&priv);
    else if(!strcmp(which,"end"))rc=frame("END",&priv);
    else if(!strcmp(which,"dup"))rc=send_data(0,F,&priv);
    else if(!strcmp(which,"skip"))rc=send_data(2*F,F,&priv);
    else if(!strcmp(which,"overflow"))rc=frame("D 18446744073709551616 00",&priv);
    else if(!strcmp(which,"short"))rc=send_data(F,4,&priv);
    else if(!strcmp(which,"hex")){
        int j=snprintf(f.line,sizeof f.line,"D %u ",F);memset(f.line+j,'a',2*F);f.line[j+2*F-1]='G';f.line[j+2*F]=0;
        rc=frame(f.line,&priv);
    }else{
        for(int i=1;i<G-1;i++)assert(send_data(i*F,F,&priv)==1&&!f.reply[0]&&f.offset==0);
        assert(!io_writes);
        if(!strcmp(which,"write"))inject_write=1;
        if(!strcmp(which,"write-cleanup")){inject_write=1;inject_remove=(int)0x80010013u;}
        rc=send_data((G-1)*F,F,&priv);
        if(rc<0)assert(strstr(f.reply,"write-error rc=0x80010005 offset=2 requested=16382")&&f.offset==0);
        else{
            assert(priv&&!strcmp(f.reply,"TTY1 ACK 16384\r\n"));
            if(!strcmp(which,"latefail")){
                inject_write=2;rc=send_data(G*F,17,&priv);
                assert(rc<0&&strstr(f.reply,"offset=16384 requested=17"));
            }else{
                assert(send_data(G*F,17,&priv)==1&&!strcmp(f.reply,"TTY1 ACK 16401\r\n"));
                if(!strcmp(which,"digest"))f.expected[0]=(f.expected[0]=='a'?'b':'a');
                else if(!strcmp(which,"readback"))damage=1;
                else if(!strcmp(which,"sync"))inject_sync=-5;
                else if(!strcmp(which,"collision")){int other=make(dest);assert(sceIoWrite(other,"SAFE",4)==4);}
                else assert(!"unknown scenario");
                rc=frame("END",&priv);
            }
        }
    }
    assert(rc==(!strcmp(which,"cancel")?0:-1)&&!priv&&strstr(f.reply,"TTY1 ERR ")==f.reply&&!f.handle);
    if(!strcmp(which,"write-cleanup"))assert(private_count()==1&&strstr(f.reply,"cleanup-error rc=0x80010013"));
    else assert(!private_count());
    if(!strcmp(which,"collision")){int other=find(dest);assert(other>0&&fs[other].n==4&&!memcmp(fs[other].b,"SAFE",4));}
    else assert(find(dest)<0);
    printf("denied case=%s %s",which,f.reply);
}
int main(int argc,char**argv){
    assert(argc>=2);
    if(!strcmp(argv[1],"auto")||!strcmp(argv[1],"legacy")||!strcmp(argv[1],"batch")){
        size_t n=argc==3?(size_t)strtoull(argv[2],NULL,10):sizeof data;assert(n<=sizeof data);
        const bool batch=!strcmp(argv[1],"batch")||(!strcmp(argv[1],"auto")&&wb_tty_recognizes("put-batch probe"));
        upload(n,batch);return 0;
    }
    assert(wb_tty_recognizes("put-batch ")&&!wb_tty_recognizes("put-batched "));
    if(!strcmp(argv[1],"gates")){
        bytes(0);char cmd[240];
        for(int i=0;i<4;i++){
            strcpy(cmd,i==0?"put-batch \"ux0:/data/unrelated.bin\" 0 sha256=":i==1?"put-batch \"ux0:/VITA-POC/../other\" 0 sha256=":
                 i==2?"put-batch \"ux0:/VITA-POC/batch.bin\" 4294967296 sha256=":"put-batch \"ux0:/VITA-POC/batch.bin\" 0 sha256=");
            strcat(cmd,i==3?"zzz":sha);assert(wb_tty_begin(&f,cmd));assert(!f.handle&&!private_count());wb_tty_abort(&f);
        }return 0;
    }
    bad(argv[1]);return 0;
}
