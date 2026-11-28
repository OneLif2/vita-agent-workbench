#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wb_xfer_ui.h"
static struct{bool off;} idle_screen;
typedef struct {uint64_t offset,size;bool put;size_t buffered,n;} wb_tty_file;
typedef struct {wb_tty_file *file;size_t queued,sent;} channel;
typedef struct {channel *shell;bool authenticated;} wb_ssh;
typedef struct {int unused;} wb_core;
static wb_ssh g_ssh;static const wb_core g_core={0};
static struct {char pin[65],ui_line2[64];} a;
static wb_tty_file file;static channel ch;
static uint64_t clock_ms;
static unsigned calls,delay_us,draws,notes,phases,unexpected_dispatch;
enum {OFFSET,PARTIAL,IDLE,END_FILE,CLOSE_SHELL,SERVICE_FAIL,PARTIAL_LINE,BATCH_INPUT};
static int behavior,draw_ok;
static uint64_t now_ms(void){return clock_ms;}
static void wb_strcpy(char *dst,size_t cap,const char *src){snprintf(dst,cap,"%s",src);}
static int wb_ssh_service(wb_ssh *s,wb_core *core){
    (void)core;assert(++calls<1000);clock_ms++;
    if(!s->shell||!s->shell->file){unexpected_dispatch++;return 1;}
    switch(behavior){
    case OFFSET:s->shell->file->offset++;break;
    case PARTIAL:s->shell->sent++;break;
    case PARTIAL_LINE:s->shell->file->n++;break;
    case BATCH_INPUT:s->shell->file->buffered+=64;break;
    case IDLE:break;
    case END_FILE:s->shell->file=NULL;s->shell->queued=20;break;
    case CLOSE_SHELL:s->shell=NULL;break;
    case SERVICE_FAIL:return 0;
    }
    return 1;
}
static bool wb_ssh_connected(wb_ssh *s){return s->authenticated;}
static void phase_begin(const char *s){(void)s;phases++;}
static void phase_end(int rc){(void)rc;}
static bool display_terminal_transfer(const char *pin,const char *line,bool online,const wb_xfer_ui *meter,uint64_t now){
    (void)now;(void)meter;
    (void)pin;(void)line;(void)online;draws++;return draw_ok;
}
static int log_event(const char *s){(void)s;notes++;return 0;}
static int sceKernelDelayThread(unsigned usec){delay_us=usec;return 0;}
#include "pace.inc"
static void reset(void){
    clock_ms=100;calls=delay_us=draws=notes=phases=unexpected_dispatch=0;
    behavior=OFFSET;draw_ok=1;file=(wb_tty_file){.size=100000,.put=true};ch=(channel){&file,0,0};
    g_ssh=(wb_ssh){&ch,true};strcpy(a.ui_line2,"SSH LISTENING");
    xfer_t0=xfer_b0=xfer_note_ms=xfer_present_ms=0;xfer_tracking=xfer_status_override=false;
    xfer_saved[0]=xfer_meter.text[0]=0;idle_screen.off=false;
}
int main(void){
    const char *reason="unchanged";unsigned ui=0;
    reset();assert(wb_transfer_pace(&reason,&ui)==1&&calls==30&&clock_ms==130&&delay_us==200);
    assert(draws==1&&notes==1&&ui==2&&strstr(xfer_meter.text,"PUT") && !strcmp(a.ui_line2,"SSH LISTENING"));
    assert(wb_transfer_pace(&reason,&ui)==1&&calls==60&&draws==1&&notes==1);
    reset();behavior=PARTIAL;ch.queued=100;
    assert(wb_transfer_pace(&reason,&ui)==1&&calls==30&&ch.sent==30&&delay_us==200);
    reset();behavior=PARTIAL_LINE;
    assert(wb_transfer_pace(&reason,&ui)==1&&calls==30&&delay_us==200&&file.offset==0&&file.n==30);
    reset();behavior=BATCH_INPUT;
    assert(wb_transfer_pace(&reason,&ui)==1&&calls==30&&delay_us==200&&file.offset==0&&file.buffered==1920);
    assert(strstr(xfer_meter.text,"PUT 0%")&&!strstr(xfer_meter.text,"WAIT RECEIPT"));
    reset();behavior=IDLE;
    assert(wb_transfer_pace(&reason,&ui)==1&&calls==1&&delay_us==1000);
    reset();behavior=END_FILE;xfer_note(&file);
    assert(wb_transfer_pace(&reason,&ui)==0&&calls==1&&unexpected_dispatch==0&&ch.queued==20);
    assert(!strcmp(a.ui_line2,"SSH LISTENING")&&!xfer_tracking&&draws==0);
    reset();behavior=CLOSE_SHELL;
    assert(wb_transfer_pace(&reason,&ui)==0&&calls==1&&unexpected_dispatch==0);
    reset();behavior=SERVICE_FAIL;reason="unchanged";
    assert(wb_transfer_pace(&reason,&ui)==-1&&calls==1&&!strcmp(reason,"SSH ERROR")&&delay_us==0);
    reset();draw_ok=0;reason="unchanged";
    assert(wb_transfer_pace(&reason,&ui)==-1&&!strcmp(reason,"DISPLAY ERROR")&&delay_us==0);
    reset();g_ssh.shell=NULL;
    assert(wb_transfer_pace(&reason,&ui)==0&&calls==0&&delay_us==0);
    reset();xfer_note(&file);assert(strstr(xfer_meter.text,"PUT") && !strcmp(a.ui_line2,"SSH LISTENING"));
    strcpy(a.ui_line2,"R1 AUTHORIZATION REVOKED");clock_ms+=250;file.offset+=2048;xfer_note(&file);
    assert(!strcmp(a.ui_line2,"R1 AUTHORIZATION REVOKED")&&xfer_status_override);
    xfer_restore();assert(!strcmp(a.ui_line2,"R1 AUTHORIZATION REVOKED")&&!xfer_tracking);
    reset();xfer_note(&file);strcpy(a.ui_line2,"R1 REVOKE ERROR");xfer_restore();
    assert(!strcmp(a.ui_line2,"R1 REVOKE ERROR"));
    reset();file.put=false;file.offset=file.size;xfer_note(&file);
    assert(strstr(xfer_meter.text,"GET 100%")&&strstr(xfer_meter.text,"WAIT RECEIPT"));xfer_restore();assert(!strcmp(a.ui_line2,"SSH LISTENING"));
    reset();g_ssh.authenticated=false;ui=0;assert(wb_transfer_pace(&reason,&ui)==1&&ui==1);
    reset();idle_screen.off=true;assert(wb_transfer_pace(&reason,&ui)==1 && draws==0);
    printf("PASS13 native transfer pace/UI groups: 30ms bursts, partial/zero writes, END/no-next-dispatch, errors, idle, critical-status preservation, PUT/GET bar, throttled mirror presentation\n");
    return 0;
}
