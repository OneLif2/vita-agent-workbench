"""Recipe release acceptance: exact archives -> C -> compile -> runtime table reader, no PS Vita or network."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1];sys.path.insert(0,str(ROOT/'tools'))
import gen_patch_recipe as g
RECIPE="f0435af90d069a22d14acf8d855561ce134e1534ceb379a6c279d608d9ef1d79"
def denies(label, action):
    try:action()
    except (ValueError,FileExistsError):print("DENIED "+label);return
    raise AssertionError(label+" unexpectedly accepted")
def main():
    obj,h=g.generate();raw=g.canonical(obj)
    assert g.hash_bytes(raw)==RECIPE and g.HEADER.read_bytes()==h
    rows=obj['bases']+[obj['target']]
    # Check C data shape and content independently, not just generated C text.
    with tempfile.TemporaryDirectory() as t:
        exe=Path(t)/('recipe.exe' if os.name=='nt' else 'recipe')
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(ROOT/'source'),str(HERE/'probe.c'),str(ROOT/'source/wb_sha256.c'),'-o',str(exe)],check=True)
        lines=subprocess.check_output([str(exe)],text=True).splitlines()
        assert lines[0]==f"recipe {g.TITLE} {g.VER} {RECIPE} {g.PACKS[-1][3]} {g.PACKS[-1][4]}"
        assert len(lines)==67
        parsed={}
        for line in lines[1:]:
            ver,path,size,digest,role=line.split();k=(ver,path);assert k not in parsed
            parsed[k]=(int(size),digest,role)
        for row in rows:
            for name,e in row['members'].items():
                assert parsed[(row['version'],name)]==(e['bytes'],e['sha256'],'embedded' if row['version']==g.VER and name in g.META else 'external')
        # Replacing proof, or supplying a different archive of the SAME length,
        # must not enable deriving approval for some other bytes.
        p=Path(t)/'fake.vpk';p.write_bytes(b'abcdef')
        r=Path(t)/'fake.json';r.write_text(json.dumps({'passed':True,'sfo_patched':{'TITLE_ID':g.TITLE,'APP_VER':'01.09'},
            'manifest':{'files':{}},'bytes':6,'sha256':'a'*64}))
        denies('same length wrong archive digest',lambda:g.inspect(('01.09',p,r,6,'a'*64)))
        denies('substituted receipt',lambda:g.inspect(('01.09',p,r,6,g.hash_bytes(p.read_bytes()))))
        out=Path(t)/'header';out.write_bytes(b'keep');denies('refuse changed generated file',lambda:g.publish(out,h));assert out.read_bytes()==b'keep'
    def mutation(label,mut):
        bad=copy.deepcopy(rows);mut(bad);denies(label,lambda:g.validate(bad))
    mutation('unavailable base asset',lambda z:z[0]['members']['audio.nsa'].update(sha256='0'*64))
    mutation('extra base member',lambda z:z[1]['members'].update({'rogue':{}}))
    mutation('wrong target eboot',lambda z:z[-1]['members'][g.EBOOT].update(sha256='0'*64))
    mutation('wrong target version',lambda z:z[-1].update(version='01.11'))
    mutation('untrusted VPK',lambda z:z[-1].update(archive_sha256='0'*64))
    denies('map attempts to embed executable',lambda:g.render(obj,{g.EBOOT:b'x',g.SFO:b'',g.MANIFEST:b''}))
    denies('bad generated embedded SFO',lambda:g.render(obj,{g.SFO:b'bad',g.MANIFEST:b'bad'}))
    print("PASS actual 3 package SHA x2; 33 members; 3 SFO identities; 2 metadata blobs; native table and negative tests; no Vita or signing.")
if __name__=='__main__':main()
