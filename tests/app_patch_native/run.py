"""Run the production native adapter and real SFO/SHA/head/shape logic against an
isolated Vita syscall filesystem double and small, exact two-version recipes."""
from pathlib import Path
import hashlib, os, shutil, struct, subprocess, tempfile
D=Path(__file__).resolve().parent
SRC=D.parents[1]/'source'
MEMBERS=('eboot.bin','sce_sys/param.sfo','strings.dat','media.rja','audio.nsa','font.ttc','sce_sys/icon0.png','sce_sys/livearea/contents/bg.png','sce_sys/livearea/contents/startup.png','sce_sys/livearea/contents/template.xml','build-manifest.json')
def sfo(ver):
    keys=b'APP_VER\0TITLE_ID\0'; vals=ver.encode()+b'\0'+b'\0\0'+b'RJGM52237\0\0\0'
    return (struct.pack('<4sIIII',b'\0PSF',0x101,52,72,2)+struct.pack('<HHIII',0,0x204,6,8,0)+struct.pack('<HHIII',8,0x204,10,12,8)+keys).ljust(72,b'\0')+vals
def test_header(path):
    text=['#pragma once','#include <stdint.h>','#include <stddef.h>','#define WB_PATCH_TITLE "RJGM52237"','#define WB_PATCH_VERSION "01.12"', '#define WB_PATCH_FILE_COUNT 11','#define WB_PATCH_BASE_COUNT 2','typedef struct {const char *path;uint64_t bytes;const char *sha;const unsigned char *embedded;}wb_patch_file;','static const char *const wb_patch_base_versions[2]={"01.09","01.10"};']
    sets=[
        [bytes(range(16))+v.encode(),sfo(v)]+[(p+'123').encode() for p in MEMBERS[2:10]]+[('manifest'+v).encode()] for v in ('01.09','01.10','01.12')]
    rows=[[],[],[]]
    for i,s in enumerate(sets):
        for j,b in enumerate(s):
            ident=f'f_{i}_{j}'
            text.append('static const unsigned char '+ident+'[]={'+','.join(map(str,b))+'};')
            embedded=ident if i==2 and j in (1,10) else 'NULL'
            rows[i].append('{"%s",%d,"%s",%s}'%(MEMBERS[j],len(b),hashlib.sha256(b).hexdigest(),embedded))
    text.append('static const wb_patch_file wb_patch_bases[2][11]={{'+','.join(rows[0])+'},{'+','.join(rows[1])+'}};')
    text.append('static const wb_patch_file wb_patch_target[11]={'+','.join(rows[2])+'};')
    (path/'wb_app_patch_recipe.h').write_text('\n'.join(text)+'\n')
    (path/'fixture_data.inc').write_text('static const unsigned char *const base_bytes[2][11]={{'+','.join('f_0_'+str(j) for j in range(11))+'},{'+','.join('f_1_'+str(j) for j in range(11))+'}};\n#define new_boot f_2_0\nenum{title_offset=80, version_offset=72};\n')
def main():
    with tempfile.TemporaryDirectory(prefix='wbpatch-native-') as td:
        path=Path(td);test_header(path)
        for p in (D/'fixture.c',SRC/'wb_app_patch_vita.inc'):shutil.copyfile(p,path/p.name)
        exe=path/('probe.exe' if os.name=='nt' else 'probe')
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(path),'-I'+str(SRC),str(path/'fixture.c'),*[str(SRC/(n+'.c')) for n in ('wb_sfo','wb_sha256','wb_head','wb_sha1','wb_out')],'-o',str(exe)],check=True)
        modes='plan apply-0109 apply-0110 head-allowed work-allowed bad-head bad-work foreign-file foreign-dir base-sha base-version wrong-title already-target input-corrupt wrong-size link-input link-base stale missing path running unknown-pid unsigned-session lost-gate no-space write-fail sync-fail stage-corrupt base-mutates extra-stage started-before-promote readdir-fail cancel-progress promote-fail post-corrupt'.split()
        for m in modes:subprocess.run([str(exe),m],check=True,timeout=15)
        print(f'PASS {len(modes)} native patch scenarios; real adapter and hashes, emulated IO/promoter; not hardware')
if __name__=='__main__':main()
