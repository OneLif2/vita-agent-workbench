#ifndef WB_AUTOARM_H
#define WB_AUTOARM_H
/* INAP00018 owns the intent in its private title save. Public job/marker files
 * are not authorities. Only an already authorized launch can mint an intent;
 * its fresh per-launch ticket distinguishes reruns of a reused job ID. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint64_t issued; char job[64], cse[32],ticket[17]; } wb_arm_intent;
static bool wb_arm_id(const char *s,size_t cap) {
    const char *end=memchr(s,0,cap);
    return end && end>s && strspn(s,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")==(size_t)(end-s);
}
static bool wb_arm_text(const wb_arm_intent *i,char job[160],char marker[144]) {
    if(!i || !i->issued || !wb_arm_id(i->job,sizeof i->job) || !wb_arm_id(i->cse,sizeof i->cse) ||
       i->ticket[16]!=0 || strspn(i->ticket,"0123456789ABCDEF")!=16) return false;
    int j=snprintf(job,160,"job=%s\ncase=%s\nreturn=%s\n",i->job,i->cse,i->ticket);
    int m=snprintf(marker,144,"job=%s\nreturn=%s\n",i->job,i->ticket);
    return j>0 && j<160 && m>0 && m<144;
}
static bool wb_arm_match(const wb_arm_intent *i,uint64_t now,const void *job,size_t jn,const void *marker,size_t mn) {
    char j[160],m[144];
    return wb_arm_text(i,j,m) && now>=i->issued && now-i->issued<UINT64_C(120000000)
         && job && jn==strlen(j) && !memcmp(j,job,jn) && marker && mn==strlen(m) && !memcmp(m,marker,mn);
}
/* Pure, fixed probes: no path, mutation, configuration or issuance capability. */
static unsigned wb_arm_selftest(void) {
    wb_arm_intent i={100,"job-1","fs-smoke","0123456789ABCDEF"},spent={0};
    char j[160],m[144],j2[160],m2[144];unsigned count=0;
    if(!wb_arm_text(&i,j,m)) return 0;
    count+=wb_arm_match(&i,100,j,strlen(j),m,strlen(m));
    count+=!wb_arm_match(&i,100,j,strlen(j),"autoarm\n",8);
    strcpy(j2,j);j2[4]='Z';count+=!wb_arm_match(&i,100,j2,strlen(j2),m,strlen(m));
    strcpy(m2,m);m2[4]='Z';count+=!wb_arm_match(&i,100,j,strlen(j),m2,strlen(m2));
    strcpy(m2,m);m2[strlen(m2)-2]='0';count+=!wb_arm_match(&i,100,j,strlen(j),m2,strlen(m2));
    count+=!wb_arm_match(&i,UINT64_C(120000100),j,strlen(j),m,strlen(m));
    count+=!wb_arm_match(&i,99,j,strlen(j),m,strlen(m));
    count+=!wb_arm_match(&spent,100,j,strlen(j),m,strlen(m));
    return count;
}
#endif
