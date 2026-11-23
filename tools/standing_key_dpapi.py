"""Windows current-user DPAPI storage for a Workbench-only release signer.

Never prints, writes to the repo, or returns private serialized bytes. DPAPI
doesn't protect against code already running as the same Windows user.
"""
import ctypes, os
from ctypes import wintypes
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

class Blob(ctypes.Structure):
    _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]

def crypt(raw,protect):
    if os.name!='nt':raise OSError('Windows current-user DPAPI required')
    if not 0<len(raw)<=16384:raise ValueError('invalid bounded key blob')
    c=ctypes.WinDLL('crypt32',use_last_error=True)
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    srcbuf=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
    src=Blob(len(raw),srcbuf);dst=Blob()
    fn=c.CryptProtectData if protect else c.CryptUnprotectData
    p=ctypes.POINTER(Blob)
    fn.argtypes=[p,wintypes.LPCWSTR if protect else ctypes.c_void_p,p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,p]
    fn.restype=wintypes.BOOL
    k.LocalFree.argtypes=[ctypes.c_void_p];k.LocalFree.restype=ctypes.c_void_p
    try:
        if not fn(ctypes.byref(src),'Vita Workbench standing release P-256' if protect else None,None,None,None,1,ctypes.byref(dst)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not 0<dst.cbData<=16384:raise ValueError('invalid DPAPI result')
        return ctypes.string_at(dst.pbData,dst.cbData)
    finally:
        ctypes.memset(srcbuf,0,len(raw))
        if dst.pbData:
            ctypes.memset(dst.pbData,0,dst.cbData)
            k.LocalFree(dst.pbData)

def key_file(p):
    p=Path(p).absolute()
    base=Path(os.environ['LOCALAPPDATA']).resolve(strict=True)/'VitaWorkbench/trust/standing-r1'
    if not p.is_relative_to(base) or '..' in p.parts or p.name!='release-p256.dpapi':
        raise ValueError('key must be in the dedicated current-user local trust directory')
    from wb_tree import source_path
    return source_path(p)

def load(key_path):
    from wb_tree import checked_open
    with checked_open(key_file(key_path)) as f:raw=f.read(16385)
    k=serialization.load_der_private_key(crypt(raw,False),password=None)
    if not isinstance(k,ec.EllipticCurvePrivateKey) or not isinstance(k.curve,ec.SECP256R1):
        raise ValueError('not a P-256 signing key')
    return k

def create_once(key_path):
    p=key_file(key_path)
    if p.exists():raise FileExistsError('existing release key preserved')
    k=ec.generate_private_key(ec.SECP256R1())
    raw=k.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    blob=crypt(raw,True)
    with p.open('xb') as f:f.write(blob);f.flush();os.fsync(f.fileno())
    got=load(p)
    if got.public_key().public_numbers()!=k.public_key().public_numbers():
        raise ValueError('DPAPI readback failed')
    return got.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
