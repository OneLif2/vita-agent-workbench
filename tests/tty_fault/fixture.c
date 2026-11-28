/* Same native reader, gate, protocol and hashing as in tty_vita; only the
 * filesystem syscalls are doubles. Independent process for each scenario. */
#define main unused_tty_vita_fixture
#include "../tty_vita/probe.c"
#undef main
static int frame(wb_tty_file *f,const char *line){
    bool priv=false;strcpy(f->line,line);f->n=strlen(line);
    int r=wb_tty_frame(f,&priv);f->reply[strcspn(f->reply,"\r\n")]=0;
    printf("%s\n",f->reply);return r;
}
int main(int argc,char **argv){
    assert(argc==2);const char *mode=argv[1];
    const char *dest=WB_INCOMING "/tiny";
    wb_tty_file f={0};
    assert(!wb_tty_begin(&f,"put \"ux0:/VITA-POC/tiny\" 3 sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    if(!strcmp(mode,"combo")){inject_write=1;inject_remove=(int)0x80010013u;}
    else if(!strcmp(mode,"zero"))inject_write=2;
    else if(!strcmp(mode,"oversize"))inject_write=3;
    else if(!strcmp(mode,"short"))inject_write=4;
    else if(!strcmp(mode,"tail")){assert(frame(&f,"D 0 61")==1);inject_write=2;}
    else if(!strcmp(mode,"cancel"))inject_remove=(int)0x80010013u;
    else assert(!strcmp(mode,"finish"));
    int r=frame(&f,!strcmp(mode,"cancel")?"CANCEL":!strcmp(mode,"tail")?"D 1 6263":"D 0 616263");
    if(r==1){
        if(!strcmp(mode,"finish")){
            inject_sync=(int)0x80010005u;inject_close=(int)0x80010009u;inject_remove=(int)0x80010013u;
        }r=frame(&f,"END");
    }
    printf("terminal_rc=%d published=%d private=%d\n",r,find(dest)>0,private_count());
    return 0;
}
