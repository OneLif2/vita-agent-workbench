/* The exact product header, no sockets, I/O or device dependencies. */
#include "wb_return_policy.h"
#include <stdlib.h>
#include <stdio.h>

static const char oldrun[]="1111111111111111", newrun[]="2222222222222222";
static const char nonce[]="112233445566778899AABBCCDDEEFF00";
static const char owner[]="AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111";
static const char host[]="BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111";
static const char host_lc[]="bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111";
static const char r[]="WBQ2 01.34 aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11111111 2397415\n";
static const char changed[]="WBQ2 01.34 abaaaaaa11111111aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11111111 2397415\n";
static wb_r1_ticket priv, proof, scratch;
static unsigned n,fail;
static void check(const char *name,bool x){++n;if(!x)++fail; printf("%s %s\n",x?"PASS":"FAIL",name);}
static bool grant(void){
    return wb_r1_return(&priv,&proof,105,"01.34",newrun,owner,host_lc,r);
}
static bool mint(const char *rcpt) {
    return wb_r1_make(&priv,100,"01.33",oldrun,nonce,owner,host_lc,rcpt);
}
static void reset(void) {
    if(!mint(r)) { puts("fatal: could not make positive case");exit(2); }
    proof=priv;
}
static int wipes;
static int wipe(void *ctx) { ++wipes;memset(ctx,0,sizeof priv);return 0; }
static int fail_wipe(void *ctx) { (void)ctx;++wipes;return -1; }
int main(void){
    reset();check("known-local-intent, matched-promote, fresh-run, canonical-pin",grant());
    check("same installed source accepted by updater",wb_r1_handoff(&priv,104,"01.33",r));
    check("updater rejects changed WBQ2",!wb_r1_handoff(&priv,104,"01.33",changed));
    check("updater rejects another source",!wb_r1_handoff(&priv,104,"01.32",r));
    check("updater rejects expired handoff",!wb_r1_handoff(&priv,priv.expires,"01.33",r));
    check("expiry boundary exclusive",!wb_r1_valid(&priv,priv.expires));
    check("last in-window tick",wb_r1_valid(&priv,priv.expires-1));
    check("backwards RTC",!wb_r1_valid(&priv,priv.issued-1));
    check("zero RTC",!wb_r1_valid(&priv,0));
    check("no durable private/local intent",!wb_r1_return(NULL,&proof,101,"01.34",newrun,owner,host,r));
    check("no success proof on failed promote",!wb_r1_return(&priv,NULL,101,"01.34",newrun,owner,host,r));
    proof.nonce[0]='A';check("success from different transaction",!grant());reset();
    proof.source_run[0]='A';check("success from other source run",!grant());reset();
    strcpy(priv.title,"INAP00020");proof=priv;check("TestApp is not Workbench",!grant());reset();
    strcpy(priv.magic,"AUTOARM");proof=priv;check("S4 cannot act as R1",!grant());reset();
    check("wrong running target",!wb_r1_return(&priv,&proof,101,"01.33",newrun,owner,host,r));
    check("changed host",!wb_r1_return(&priv,&proof,101,"01.34",newrun,owner,owner,r));
    check("changed owner",!wb_r1_return(&priv,&proof,101,"01.34",newrun,host,host,r));
    check("reused run",!wb_r1_return(&priv,&proof,101,"01.34",oldrun,owner,host,r));
    check("bad new run",!wb_r1_return(&priv,&proof,101,"01.34","",owner,host,r));
    check("installed content differs",!wb_r1_return(&priv,&proof,101,"01.34",newrun,owner,host,changed));
    check("missing measured content",!wb_r1_return(&priv,&proof,101,"01.34",newrun,owner,host,NULL));
    proof=priv;scratch=priv;priv.reserved[0]=1;proof=priv;check("noncanonical fixed record",!grant());reset();
    memset(priv.receipt,'x',sizeof priv.receipt);proof=priv;check("unterminated fixed field",!grant());reset();
    priv.receipt[sizeof priv.receipt-1]='x';proof=priv;check("trailing data denied",!grant());reset();
    priv.expires++;proof=priv;check("extended expiry denied",!grant());reset();
    priv.target_ver[4]='5';proof=priv;check("receipt version mismatch denied",!grant());reset();
    check("all-zero nonce",!wb_r1_make(&scratch,100,"01.33",oldrun,"00000000000000000000000000000000",owner,host,r));
    check("overflowing clock",!wb_r1_make(&scratch,UINT64_MAX-2,"01.33",oldrun,nonce,owner,host,r));
    check("same-version update not eligible",!wb_r1_make(&scratch,100,"01.34",oldrun,nonce,owner,host,r));
    check("downgrade not eligible",!wb_r1_make(&scratch,100,"01.35",oldrun,nonce,owner,host,r));
    check("missing receipt denied",!mint(NULL));reset();
    check("legacy receipt denied",!mint("WBQ1 01.34\n"));reset();
    char buf[160];strcpy(buf,r);buf[11]='A';check("canonical lowercase hash only",!mint(buf));reset();
    strcpy(buf,r);buf[strlen(buf)-1]=0;check("newline is part of binding",!mint(buf));reset();
    strcpy(buf,r);strcpy(buf+76,"00020\n");check("noncanonical size denied",!mint(buf));reset();
    strcpy(buf,r);strcpy(buf+76,"99999999999999999999999999\n");check("oversized tree denied",!mint(buf));reset();
    strcpy(buf,r);strcat(buf,"a");check("trailing text denied",!mint(buf));reset();
    check("invalidation storage failure denies",!wb_r1_consume(grant(),fail_wipe,&priv));
    check("missing invalidation denies",!wb_r1_consume(grant(),NULL,&priv));
    check("invalid intent is retired",!wb_r1_consume(false,wipe,&priv) && !grant());reset();
    wipe(&priv);check("local revoke denies even with a real old proof",!grant());reset();
    check("accept once after durable tombstone",wb_r1_consume(grant(),wipe,&priv));
    check("proof replay/second boot fails after one-use",!grant()&&!wb_r1_consume(grant(),wipe,&priv));
    printf("RESULT %u/%u; host simulation, production policy, no Vita contact\n",n-fail,n);
    return fail?1:0;
}
