"""Read-only check for the 01.34 stable-host-identity candidate. Python 3."""
import argparse, hashlib, re, struct, sys, zipfile
from pathlib import Path
expected_core='01.34'
expected_vpk='df1acf78527b7e67066d363f04f64919d2045e50fc7adc011c68bb26445b0996'
expected_payload='0e3a633929b7069a5a194c86bd92eb770515d1766101f597139af61b0a45a66b'
def sha(b):return hashlib.sha256(b).hexdigest()
def sfo(data):
    if data[:4]!=b'\x00PSF':raise ValueError('SFO magic')
    ko,vo,count=struct.unpack_from('<III',data,8); fields={}
    if count>(len(data)-20)//16:raise ValueError('SFO field count')
    for i in range(count):
        k,fmt,n,cap,v=struct.unpack_from('<HHIII',data,20+16*i)
        if n>cap or vo+v+n>len(data):raise ValueError('SFO bounds')
        key=data[ko+k:data.index(0,ko+k)].decode('ascii')
        if fmt==0x204:fields[key]=data[vo+v:vo+v+n].rstrip(b'\0').decode('utf8')
    return fields
def check(root):
    facts=[]
    def record(label,v,expect):
        ok=v==expect
        print(('PASS' if ok else 'FAIL')+' '+label+': '+str(v))
        facts.append(ok)
    def read(name):return (root/'source'/name).read_text(encoding='utf-8-sig')
    def capture(p,t):
        m=re.search(p,t,re.M);return m[1] if m else '(missing)'
    header=read('wb_ver.h'); build=read('build.sh'); package=read('package.sh'); verifier=read('verify_package.py')
    record('core header',capture(r'^#define\s+WB_VERSION\s+"([^"]+)"',header),expected_core)
    record('derived display tag',bool(re.search(r'^#define\s+WB_BUILD_TAG\s+WB_VERSION\s+"-live-s1"',header,re.M)),True)
    record('main title SFO generator',capture(r'^vita-mksfoex\s+-s TITLE_ID=INAP00018\s+-s APP_VER=([0-9.]+)',build),expected_core)
    record('build VPK filename',set(re.findall(r'workbench_(\d{4})\.vpk',build)),{'0134'})
    record('package helper filename',set(re.findall(r'workbench_(\d{4})\.vpk',package)),{'0134'})
    record('package verifier APP_VER',capture(r'^APP_VER\s*=\s*"([^"]+)"',verifier),expected_core)
    p=root/'build/workbench_0134.vpk'
    record('archived VPK SHA-256',sha(p.read_bytes()),expected_vpk)
    with zipfile.ZipFile(p) as z:
        record('ZIP member CRC check',z.testzip(),None)
        meta=sfo(z.read('sce_sys/param.sfo'))
        record('VPK TITLE_ID / APP_VER',(meta.get('TITLE_ID'),meta.get('APP_VER')),('INAP00018',expected_core))
        record('eboot build tag',b'01.34-live-s1\0' in z.read('eboot.bin'),True)
        record('embedded payload',sha(z.read('workbench_payload.suprx')),expected_payload)
    record('pinned input payload',sha((root/'payload/release_0122_p2_1.suprx').read_bytes()),expected_payload)
    print(f'RESULT {sum(facts)}/{len(facts)} PASS')
    return 0 if all(facts) else 1
if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('root',nargs='?',type=Path,default=Path(__file__).resolve().parents[1]);a=ap.parse_args()
    try:sys.exit(check(a.root))
    except (OSError,KeyError,ValueError,zipfile.BadZipFile,struct.error) as ex:
        print('ERROR '+str(ex),file=sys.stderr);sys.exit(2)

