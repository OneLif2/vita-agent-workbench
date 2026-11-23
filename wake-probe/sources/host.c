#include "life.h"
#include <stdio.h>
#include <string.h>
static unsigned n;
#define EXPECT(label,val) do{++n;if(!(val)){printf("FAIL %s\n",label);return 1;}printf("PASS %s\n",label);}while(0)
int main(void){
    lc_arm a={LC_MAGIC,1,300};lc_trace t={.magic=LC_TRACE,.start=300},copy;
    EXPECT("armed exact start",lc_live(&a,300));
    EXPECT("null denied",!lc_live(NULL,300));
    EXPECT("before issue denied",!lc_live(&a,299));
    EXPECT("expiry exclusive",!lc_live(&a,300+LC_SPAN));
    EXPECT("valid empty trace",lc_valid(&t));
    EXPECT("first heartbeat",lc_tick(&a,&t,301)&&t.count==1&&t.us[0]==301);
    copy=t;EXPECT("same instant cannot fabricate another heartbeat",!lc_tick(&a,&t,301)&&!memcmp(&t,&copy,sizeof t));
    EXPECT("no catch-up on early wake",!lc_tick(&a,&t,301+LC_STEP-1));
    EXPECT("suspended interval preserved not backfilled",lc_tick(&a,&t,301+3*LC_STEP)&&t.count==2&&t.us[1]-t.us[0]==3*LC_STEP);
    a.enabled=0;EXPECT("local revocation rejects next write",!lc_tick(&a,&t,301+4*LC_STEP));
    a.enabled=1;a.start=301;EXPECT("other generation denied",!lc_tick(&a,&t,301+4*LC_STEP));
    a.start=300;a.magic=0;EXPECT("corrupt grant denied",!lc_tick(&a,&t,301+4*LC_STEP));
    a.magic=LC_MAGIC;a.enabled=2;EXPECT("unknown control denied",!lc_live(&a,301));
    a.enabled=1;t=(lc_trace){.magic=LC_TRACE,.start=300};
    for(unsigned i=0;i<LC_CAP;i++)if(!lc_tick(&a,&t,300+i*LC_STEP))return 2;
    EXPECT("hard 24 record cap",t.count==LC_CAP&&!lc_tick(&a,&t,300+LC_SPAN-1));
    t.us[2]=t.us[1]-1;EXPECT("corrupt chronological order",!lc_valid(&t));
    t.count=LC_CAP+1;EXPECT("bad count before array access",!lc_valid(&t));
    int p=0;EXPECT("held button no grant",!lc_gesture(&p,8,8)&&!lc_gesture(&p,0,8));
    EXPECT("button chord no grant",!lc_gesture(&p,12,8)&&!lc_gesture(&p,0,8));
    EXPECT("neutral press release",!lc_gesture(&p,8,8)&&lc_gesture(&p,0,8));
    EXPECT("no autorepeat on released",!lc_gesture(&p,0,8));printf("%u checks\n",n);return 0;
}
