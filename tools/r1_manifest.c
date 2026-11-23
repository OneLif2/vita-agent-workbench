/* Host-only: emit the actual core's WBQ2 for three approved local inputs. No device I/O. */
#include "wb_queued.h"
#include "wb_head.h"
#include <stdlib.h>
int main(int ac,char **av) {
    if(ac!=4)return 2;
    wbq_manifest m={0};char ver[6]={0},cid[64]={0};unsigned char head[WB_HEAD_SIZE];
    for(unsigned i=0,j=1;i<4;i++){
        if(i==2)continue;
        FILE *f=fopen(av[j++],"rb");if(!f || fseek(f,0,SEEK_END))return 3;
        long n=ftell(f);if(n<=0 || (unsigned long)n>WBQ_FILE_MAX || fseek(f,0,SEEK_SET))return 3;
        unsigned char *b=malloc((size_t)n);if(!b || fread(b,1,(size_t)n,f)!=(size_t)n)return 3;
        fclose(f);if(wbq_bytes(&m,i,b,(size_t)n))return 4;
        if(i==1){
            wb_sfo s;if(wbq_identity(b,(size_t)n,ver) || wb_sfo_parse(&s,b,(size_t)n))return 5;
            (void)wb_sfo_get(&s,"CONTENT_ID",cid,sizeof cid);
        }
        free(b);
    }
    char receipt[WBQ_CAP];
    if(wb_head_build(head,sizeof head,WB_TITLE_ID,cid) || wbq_bytes(&m,2,head,sizeof head) || wbq_format(&m,ver,receipt))return 6;
    fputs(receipt,stdout);return 0;
}
