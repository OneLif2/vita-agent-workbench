"""Exact C registry compiled on the host; no Vita, network, installs or launches."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"))
import app_registry as policy
import gen_app_registry as generator

APP="INAP00020"
H="fea70dc69399200bdf00ca145044cac7725b4987d19da9d032ff2dbfd12a43e9"
SSH_VITA="e6363e629be55ab65151456989095310f9c0d2177bc4685a655041e1ea4758ce"

PROBE=r'''#include <stdio.h>
#include <string.h>
#include "wb_app_registry.h"
int main(int argc,char **argv) {
    if(argc!=5)return 2;
    wb_reg_result r;
    if(!strcmp(argv[1],"install"))r=wb_reg_install(argv[2],argv[3],argv[4]);
    else if(!strcmp(argv[1],"launch"))r=wb_reg_launch(argv[2],argv[3],argv[4]);
    else return 2;
    puts(wb_reg_reason(r));return r==WB_REG_OK?0:1;
}
'''

class RegistryTable(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.tmp=Path(self.temp.name); self.output=self.tmp/"wb_registry_data.inc"
        self.pkg=(ROOT/"tools/apps.txt").read_bytes()
        self.catalog=self.tmp/"apps.txt";self.catalog.write_bytes(self.pkg)

    def compile(self):
        source=self.tmp/"probe.c";source.write_bytes(PROBE.encode("ascii"))
        self.probe=self.tmp/("probe.exe" if sys.platform=="win32" else "probe")
        cmd=[shutil.which("gcc") or "cc","-std=c11","-pedantic","-Wall","-Wextra","-Werror",
             "-I",str(self.tmp),"-I",str(ROOT/"source"),str(source),"-o",str(self.probe)]
        p=subprocess.run(cmd,capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)

    def decision(self,action,title,ver,value,expect):
        p=subprocess.run([str(self.probe),action,title,ver,value],capture_output=True,text=True)
        self.assertEqual((p.returncode,p.stdout.strip(),p.stderr),(0 if expect=="approved" else 1,expect,""))

    def test_real_device_table_exact(self):
        p=subprocess.run([sys.executable,"-B",str(ROOT/"tools/gen_app_registry.py"),str(self.output)],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr);self.assertIn("2 approved artifact(s)",p.stdout)
        self.compile()
        self.decision("install","VSSH00001","01.42",SSH_VITA,"approved")
        for c in ("", "-", "fs-smoke"):
            self.decision("launch","VSSH00001","01.42",c,"registry-case")
        self.decision("install",APP,"01.01",H,"approved")
        for c in ("fs-smoke","power-smoke","compute-smoke"):
            self.decision("launch",APP,"01.01",c,"approved")
        for c in ("", "fs", "fs-smok", "fs-smoke1", "FS-SMOKE", "fs-smoke,power-smoke"):
            self.decision("launch",APP,"01.01",c,"registry-case")
        self.decision("install",APP,"01.02",H,"registry-version")
        self.decision("install",APP,"01.01","0"*64,"registry-sha256")
        self.decision("install",APP,"01.01",H.upper(),"registry-sha256")
        for t in ("ABCD00021","INAP00018","INAP00019",APP[:8]):
            self.decision("install",t,"01.01",H,"registry-title")
            self.decision("launch",t,"01.01","fs-smoke","registry-title")

    def test_two_versions_no_cross_grants_and_second_title(self):
        self.catalog.write_bytes(self.pkg + (f"\n{APP} 01.02 {'a'*64} only-new\nABCD00021 02.00 {'b'*64} render-smoke\n").encode())
        n,_=generator.emit(self.output,self.catalog);self.assertEqual(n,4);self.compile()
        self.decision("install",APP,"01.02","a"*64,"approved")
        self.decision("install",APP,"01.01","a"*64,"registry-sha256")
        self.decision("launch",APP,"01.02","fs-smoke","registry-case")
        self.decision("launch",APP,"01.01","only-new","registry-case")
        self.decision("launch",APP,"01.02","only-new","approved")
        self.decision("launch","ABCD00021","02.00","render-smoke","approved")
        self.decision("launch","ABCD00021","02.01","render-smoke","registry-version")
        self.decision("launch","ABCD00021","02.00","only-new","registry-case")

    def test_deterministic_semantics(self):
        one=f"{APP} 01.01 {H} z-smoke,a-smoke";two=f"ABCD00021 01.01 {'1'*64} zero"
        def gen(s):
            self.catalog.write_bytes(s.encode());meta=generator.emit(self.output,self.catalog)
            return meta,self.output.read_bytes()
        self.assertEqual(gen(one+"\n"+two+"\n"),gen("# comment\r\n"+two+"\r\n"+one.replace("z-smoke,a-smoke","a-smoke,z-smoke")+"\r\n"))

    def test_malformed_duplicate_wildcard_reserved(self):
        for title in ("INAP00018","INAP00019","INAP00012","NPXS12345","PCSG01234"):
            with self.subTest(title=title):
                self.catalog.write_bytes(self.pkg+(f"\n{title} 01.01 {'a'*64} fs-smoke\n").encode())
                with self.assertRaises(policy.Denied):generator.emit(self.output,self.catalog)
                self.assertFalse(self.output.exists())
        extras=["",f"{APP} 01.01 {H} fs-smoke\n{APP} 01.01 {'1'*64} foo",
                f"{APP} 01.01 {H} fs-smoke\nABCD00021 01.01 {H} foo",
                f"{APP} 01.01 {H} *",f"{APP} 01.01 {H} foo,foo",f"{APP} 01.01 {H} one\v"]
        for line in extras:
            with self.subTest(line=line):
                self.catalog.write_bytes(line.encode())
                with self.assertRaises(policy.Denied):generator.emit(self.output,self.catalog)
                self.assertFalse(self.output.exists())

if __name__=="__main__": unittest.main(verbosity=2)
