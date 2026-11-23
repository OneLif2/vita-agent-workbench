"""Same-input before/after host probe: run the extracted production listener branch
and renderer selection. Actual auth, framebuffer pixels and shell callbacks are
tested separately; this probe only labels which panel received each state.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def block(text, opening):
    depth = 0
    for i in range(opening, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if not depth:
                return text[opening + 1:i]
    raise ValueError('incomplete block')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', type=Path, required=True)
    ap.add_argument('--input', type=Path, required=True)
    opts = ap.parse_args()
    renderer = (opts.source/'display.c').read_text(encoding='utf8')
    m = re.search(r'if\s*\(\s*terminal\s*\)\s*\{', renderer)
    assert m is not None, 'production terminal renderer not found'
    panel = block(renderer, m.end() - 1)
    code = (opts.source/'vita_ssh_status.c').read_text(encoding='utf8')
    i = code.index('if (!g_ssh.listening) { reason = "LISTENER CLOSED"; break; }')
    j = code.index('sceKernelDelayThread(16000);', i)
    loop = code[i:j]
    harness = r'''
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "wb_ver.h"
static struct {bool listening,authenticated,terminal_latched;} g_ssh;
static int connected,active,ui_seen;
static const char *selected;
#define wb_ssh_connected(...) (connected)
#define wb_mirror_active() (active)
#define phase_begin(...) ((void)0)
#define phase_end(...) ((void)0)
#define log_event(...) (0)
#define draw_mirror(...) (selected=agent_online?"SHARED-ONLINE":"SHARED-IDLE")
#define draw_connected(...) (selected=agent_online?"LEGACY-ONLINE":"LEGACY-IDLE")
#define display_frame_prompt(...) (selected="LISTENING-PAGE",1)
#define term2(e,o) present(o)
#define term3(p,e,o) present(o)
#define term_select(_1,_2,_3,f,...) f
#define display_terminal(...) term_select(__VA_ARGS__,term3,term2)(__VA_ARGS__)
static int present(bool agent_online) {
#include "route.inc"
    return 1;
}
int main(void) {
    int l,h,a,c,m,errors=0,count=0;
    char name[64],want[64];
    while(scanf("%63s %d %d %d %d %d %63s",name,&l,&h,&a,&c,&m,want)==7) {
        g_ssh.listening=l;g_ssh.terminal_latched=h;g_ssh.authenticated=a;connected=c;active=m;
        const char *reason=NULL;selected=NULL;
        do{
#include "listen.inc"
        }while(0);
        if(reason && !strcmp(reason,"LISTENER CLOSED"))selected="CLOSED";
        if(!selected)selected="NONE";
        printf("%s: %s\n",name,selected);
        errors+=strcmp(want,selected)!=0;
        ++count;
    }
    printf("states=%d mismatches=%d\n",count,errors);
    return errors || count!=9;
}
'''
    with tempfile.TemporaryDirectory(prefix='wb-ready-route-') as tmp:
        d = Path(tmp)
        (d/'route.inc').write_text(panel, encoding='utf8')
        (d/'listen.inc').write_text(loop, encoding='utf8')
        (d/'probe.c').write_text(harness, encoding='utf8')
        exe = d/('probe.exe' if os.name=='nt' else 'probe')
        subprocess.run(['gcc', '-std=c11', '-I', str(opts.source.resolve()), str(d/'probe.c'), '-o', str(exe)], check=True)
        return subprocess.run([str(exe)], input=opts.input.read_bytes()).returncode


if __name__ == '__main__':
    raise SystemExit(main())
