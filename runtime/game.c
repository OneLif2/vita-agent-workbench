#include "wb_game.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "py/compile.h"
#include "py/gc.h"
#include "py/runtime.h"
#include "py/stackctrl.h"
#include "shared/runtime/gchelper.h"
static const char game[] = {
#include "game_blob.inc"
0 };
static struct wb_io {void *ctx; wb_game_readline_fn r; wb_game_write_fn w; wb_game_delay_fn d; int cancelled,reporting; unsigned poll;} io;
static unsigned busy; /* Cortex-A9 / desktop atomic exchange. */
static uint32_t seed=0xb00bb135u;
static void stop_game(void){io.cancelled=1;mp_raise_type(&mp_type_SystemExit);}
void wb_game_poll(void){if((++io.poll&63u)==0 && io.d(io.ctx,0)<0)stop_game();}
void mp_hal_stdout_tx_strn_cooked(const char *s,size_t n){
    if(n && io.w(io.ctx,s,n)<0 && !io.reporting)stop_game();
}
static void set(mp_obj_dict_t *dict,const char *key,mp_obj_t value){mp_obj_dict_store(MP_OBJ_FROM_PTR(dict),MP_OBJ_NEW_QSTR(qstr_from_str(key)),value);}
static mp_obj_t input_(mp_obj_t prompt){
    size_t n;const char *p=(const char*)mp_obj_str_get_data(prompt,&n);mp_hal_stdout_tx_strn_cooked(p,n);
    char buf[64];int z=io.r(io.ctx,buf,sizeof buf);if(z<0 || z>(int)sizeof buf)stop_game();
    return mp_obj_new_str(buf,(size_t)z);
}
static MP_DEFINE_CONST_FUN_OBJ_1(input_obj,input_);
static mp_obj_t exit_(void){mp_raise_type(&mp_type_SystemExit);}
static MP_DEFINE_CONST_FUN_OBJ_0(exit_obj,exit_);
static mp_obj_t delay_(mp_obj_t o){double n=mp_obj_get_float(o);if(!(n>=0 && n<=5))mp_raise_ValueError(MP_ERROR_TEXT("delay"));if(io.d(io.ctx,(unsigned)(n*1000+0.5))<0)stop_game();return mp_const_none;}
static MP_DEFINE_CONST_FUN_OBJ_1(delay_obj,delay_);
static mp_obj_t floor_(mp_obj_t o){return mp_obj_new_int((mp_int_t)floor(mp_obj_get_float(o)));}
static MP_DEFINE_CONST_FUN_OBJ_1(floor_obj,floor_);
static mp_obj_t choice_(mp_obj_t o){size_t n;mp_obj_t *items;mp_obj_list_get(o,&n,&items);if(!n)mp_raise_ValueError(MP_ERROR_TEXT("empty choice"));seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return items[seed%n];}
static MP_DEFINE_CONST_FUN_OBJ_1(choice_obj,choice_);
static mp_obj_dict_t *mod(const char *name){return mp_obj_module_get_globals(mp_obj_new_module(qstr_from_str(name)));}
void gc_collect(void){gc_collect_start();gc_helper_collect_regs_and_stack();gc_collect_end();}
void nlr_jump_fail(void *unused){(void)unused;abort();}
int wb_game_run(void *ctx,wb_game_readline_fn r,wb_game_write_fn w,wb_game_delay_fn d){
    if(!r || !w || !d)return -4;
    if(__atomic_exchange_n(&busy,1,__ATOMIC_ACQUIRE))return -3;
    unsigned char *heap=malloc(512*1024);if(!heap){__atomic_store_n(&busy,0,__ATOMIC_RELEASE);return -4;}
    io=(struct wb_io){.ctx=ctx,.r=r,.w=w,.d=d};
    mp_stack_ctrl_init();mp_stack_set_limit(192*1024);gc_init(heap,heap+512*1024);mp_init();
    nlr_buf_t frame; int result=0;
    if(nlr_push(&frame)==0){
        mp_obj_dict_t *m=mod("math");set(m,"floor",MP_OBJ_FROM_PTR(&floor_obj));set(m,"inf",mp_obj_new_float(INFINITY));
        set(mod("time"),"sleep",MP_OBJ_FROM_PTR(&delay_obj));set(mod("random"),"choice",MP_OBJ_FROM_PTR(&choice_obj));
        set(mp_globals_get(),"input",MP_OBJ_FROM_PTR(&input_obj));set(mp_globals_get(),"exit",MP_OBJ_FROM_PTR(&exit_obj));
        qstr filename=qstr_from_str("tictactoe_ai.py");
        mp_lexer_t *l=mp_lexer_new_from_str_len(filename,game,sizeof(game)-1,0);
        mp_parse_tree_t tree=mp_parse(l,MP_PARSE_FILE_INPUT);mp_obj_t f=mp_compile(&tree,filename,true);mp_call_function_0(f);
        nlr_pop();
    } else {
        mp_obj_t e=MP_OBJ_FROM_PTR(frame.ret_val);
        if(io.cancelled){result=-2;}else if(!mp_obj_is_type(e,&mp_type_SystemExit)){
            result=-1;io.reporting=1;mp_obj_print_exception(&mp_plat_print,e);
        }
    }
    mp_deinit();free(heap);memset(&io,0,sizeof io);__atomic_store_n(&busy,0,__ATOMIC_RELEASE);return result;
}
