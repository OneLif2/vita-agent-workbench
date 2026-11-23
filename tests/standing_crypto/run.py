"""Compile actual canonical bytes/scalar parser; Python verifies fixture signatures only."""
import hashlib,os,subprocess,tempfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature,encode_dss_signature
R=Path(__file__).resolve().parents[2]
CODE=r'''
#include <string.h>
#include <stdio.h>
#include "wb_standing_message.h"
int main(int n,char **v) {
 if(n==8) {
    char s[WB_STANDING_MSG_CAP]={0};
    if(!wb_standing_message(s,v[1],v[2],v[3],v[4],v[5]) ||
       !wb_standing_scalars(v[6],v[7]))return 2;
    fwrite(s,1,strlen(s),stdout);return 0;
 }
 return 3;
}
'''
H='a1'*32; O='b2'*32; RUN='3AE69169B9D90645'; DIGEST='cd'*32
N=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
MSG=(
 f'WB-R1-AUTO-v1\nINAP00018 01.85 {DIGEST} 2474300\n'
 f'HOST {H}\nOWNER {O}\nSOURCE 01.84 {RUN}\n').encode()
def main():
 with tempfile.TemporaryDirectory() as t:
  s=Path(t)/'verify.c';s.write_text(CODE,encoding='ascii');exe=Path(t)/('verify.exe' if os.name=='nt' else 'verify')
  subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(R/'source'),str(s),'-o',str(exe)],check=True,capture_output=True)
  key=ec.generate_private_key(ec.SECP256R1());a,b=decode_dss_signature(key.sign(MSG,ec.ECDSA(hashes.SHA256())))
  if b>N//2:b=N-b
  inputs=[f'WBQ2 01.85 {DIGEST} 2474300\n','01.84',RUN,H.upper(),O.upper(),f'{a:064x}',f'{b:064x}']
  def call(v):
   return subprocess.run([str(exe),*v],capture_output=True)
  c=call(inputs);assert c.returncode==0 and c.stdout.replace(b'\r\n',b'\n')==MSG,c
  key.public_key().verify(encode_dss_signature(a,b),c.stdout.replace(b'\r\n',b'\n'),ec.ECDSA(hashes.SHA256()))
  for i,v in [
      (0,f'WBQ2 01.85 {DIGEST} 02474300\n'),(0,f'WBQ2 01.85 {DIGEST.upper()} 2474300\n'),
      (0,f'WBQ2 01.85 {DIGEST} 2474300\n\n'),(0,'WBQ1 01.85\n'),
      (1,'01.85'),(2,RUN.lower()),(2,'0'*16),(3,'0'*64),(3,'+'*64),(4,H),
      (5,'0'*64),(5,f'{N:064x}'),(6,'0'*64),(6,f'{N-b:064x}')]:
   neg=inputs.copy();neg[i]=v;r=call(neg);assert r.returncode==2 and not r.stdout,(i,v,r)
  print('PASS canonical C/Python interoperability; 14 malformed/range/pin cases denied; transcript fixture SHA-256',hashlib.sha256(MSG).hexdigest())
if __name__=='__main__':main()
