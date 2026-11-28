"""Bounded-RAM host large-app/transfer regression; synthetic data, no sockets/Vita.

--probe prints the same >192MiB registry-preflight outcome with WB_TEST_TOOLS
pointing at pristine/restored tools. Run without flags for the changed host suite.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock
import zipfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,os.environ.get('WB_TEST_TOOLS',str(ROOT/'tools')))
import app_registry as registry
import wb_tree as tree
if '--probe' not in sys.argv:
    import wbctl as ctl
    import wbctl_pty as adapter
    import wbterm as terminal

MIB=1024*1024
TITLE='LARG12345'
VERSION='01.00'

def sfo(title=TITLE,version=VERSION):
    fields=[('TITLE_ID',title),('APP_VER',version)]
    keys=b''; values=b''; entries=[]
    for key,value in fields:
        raw=value.encode('ascii')+b'\0'
        entries.append(struct.pack('<HHIII',len(keys),0x204,len(raw),len(raw),len(values)))
        keys+=key.encode('ascii')+b'\0'; values+=raw
    ko=20+16*len(fields); vo=(ko+len(keys)+3)&~3
    return struct.pack('<4s4I',b'\0PSF',0x101,ko,vo,len(fields))+b''.join(entries)+keys+b'\0'*(vo-ko-len(keys))+values

def digest(path):
    with path.open('rb') as file:
        h=hashlib.sha256()
        while block:=file.read(65536):h.update(block)
    return h.hexdigest()

def build(base,payload=193*MIB+17,assets=300):
    package=base/'fixture.vpk'
    block=bytes(range(256))*256
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_STORED,allowZip64=False) as archive:
        archive.writestr(zipfile.ZipInfo('eboot.bin'),b'\x7fELFsynthetic-host-fixture')
        archive.writestr(zipfile.ZipInfo('sce_sys/param.sfo'),sfo())
        with archive.open('data/large.bin','w') as out:
            left=payload
            while left:
                part=block[:min(left,len(block))];out.write(part);left-=len(part)
        for n in range(assets):archive.writestr(zipfile.ZipInfo(f'data/assets/{n:05d}.bin'),b'asset')
    approval=base/'apps.txt'
    approval.write_text(f'{TITLE} {VERSION} {digest(package)} -\n',encoding='ascii')
    return package,approval

def probe():
    with tempfile.TemporaryDirectory(prefix='wb-large-host-probe-') as tmp:
        package,approval=build(Path(tmp))
        try:
            if hasattr(registry,'approve_file'):
                with registry.approve_file(package,registry=approval) as (facts,_):pass
            else:facts,_=registry.approve(package,registry=approval)
            print(f"APPROVED title={facts['title_id']} version={facts['app_ver']} bytes={facts['bytes']} sha256={facts['sha256']}")
        except registry.Denied as error:
            print('DENIED '+str(error))

class Wire:
    """Finite fragmented SSH byte stream only; never opens a socket."""
    def __init__(self,body):
        self.data=bytearray(b'VITA AGENT TERMINAL 02.09 (Workbench)\r\nType help for commands.\r\nux0:/> '+body)
        self.sent=[];self.timeout=[]
    def recv(self,n):
        part=bytes(self.data[:min(n,997)]);del self.data[:len(part)];return part
    def recv_stderr_ready(self):return False
    def sendall(self,data):self.sent.append(data)
    def settimeout(self,value):self.timeout.append(value)
    def exit_status_ready(self):return not self.data
    def recv_exit_status(self):return 0

class LargeHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='wb-large-host-')
        cls.base=Path(cls.tmp.name)
        cls.package,cls.approval=build(cls.base)
        cls.sha=digest(cls.package)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def test_stream_approval_above_old_caps_bounded_ram_and_exact_snapshot(self):
        tracemalloc.start()
        with mock.patch.object(Path,'read_bytes',side_effect=AssertionError('whole-file read forbidden')):
            with registry.approve_file(self.package,registry=self.approval) as (facts,source):
                saved=source.path
                self.assertEqual((facts['title_id'],facts['app_ver'],facts['sha256']), (TITLE,VERSION,self.sha))
                self.assertEqual(source.size,self.package.stat().st_size)
                self.assertGreater(source.size,192*MIB)
                self.assertEqual(digest(source.path),self.sha)
                self.assertTrue(facts['install_only'])
        _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
        self.assertLess(peak,12*MIB)
        self.assertFalse(saved.exists())
        print(f'OBSERVED streaming approval bytes={self.package.stat().st_size} peak_python_bytes={peak}')

    def test_facts_same_file_bounded_sfo_no_read_bytes(self):
        tracemalloc.start()
        with mock.patch.object(Path,'read_bytes',side_effect=AssertionError('whole-file read forbidden')):
            facts=ctl.vpk_facts(self.package)
        _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
        self.assertEqual(facts['sha256'],self.sha)
        self.assertEqual(len(facts['members']),303)
        self.assertEqual((facts['title_id'],facts['app_ver']),(TITLE,VERSION))
        self.assertLess(peak,12*MIB)

    def test_full_large_terminal_push_streams_exact_chunks_without_buffering(self):
        remote='ux0:/VITA-POC/large.vpk'; position=0; sent=hashlib.sha256(); ready=True; ended=False
        term=terminal.Terminal.__new__(terminal.Terminal)
        term.version='02.09'
        def command(value):
            self.assertEqual(value,f'put "{remote}" {self.package.stat().st_size} sha256={self.sha}')
        def send(value):
            nonlocal position,ended
            if value=='END':
                self.assertEqual(position,self.package.stat().st_size)
                self.assertEqual(sent.hexdigest(),self.sha);ended=True;return
            prefix,offset,data=value.split()
            self.assertEqual(prefix,'D');self.assertEqual(int(offset),position)
            block=bytes.fromhex(data);self.assertLessEqual(len(block),2048)
            sent.update(block);position+=len(block)
        def reply():
            nonlocal ready
            if ready:ready=False;return f'TTY1 READY PUT {self.package.stat().st_size} 2048'
            return f'TTY1 OK PUT {position} {sent.hexdigest()}' if ended else f'TTY1 ACK {position}'
        term.command=command;term.send=send;term.reply=reply
        term.exact=lambda token:self.assertEqual(token,terminal.ROOT_PROMPT)
        tracemalloc.start()
        result=term.push(self.package,remote)
        _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
        self.assertEqual((result['bytes'],result['sha256']),(self.package.stat().st_size,self.sha))
        self.assertLess(peak,12*MIB)
        print(f'OBSERVED complete simulated TTY upload bytes={position} peak_python_bytes={peak}')

    def test_app_cli_transmits_approved_snapshot_and_no_launch(self):
        calls=[];paths=[]
        def peer(command,*,timeout,stdin_bytes=None,progress_total=None):
            self.assertEqual(timeout,7200)
            calls.append(command)
            if command.startswith('put '):
                _,remote,size,sha=command.split()
                self.assertIsNone(progress_total)
                self.assertIsInstance(stdin_bytes,tree.FileSource)
                paths.append(stdin_bytes.path)
                self.assertEqual((int(size),sha),(stdin_bytes.size,'sha256='+self.sha))
                self.assertEqual(digest(stdin_bytes.path),self.sha)
                return 0,f'OK put path={remote} bytes={size} {sha}'
            self.assertEqual(command,'app-install '+calls[0].split()[1])
            self.assertEqual(progress_total,self.package.stat().st_size)
            return 0,f'OK app-install title={TITLE} app_ver={VERSION} files=303 detail=0 session=kept'
        with mock.patch.object(registry,'REGISTRY',self.approval),mock.patch.object(ctl,'ssh',side_effect=peer),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ctl.main(['app','install',str(self.package),'--yes']),0)
        self.assertEqual(len(calls),2)
        self.assertTrue(all(not p.exists() for p in paths))

    def test_registry_hash_identity_and_case_remain_required(self):
        with registry.approve_file(self.package,registry=self.approval) as (_,source):
            with mock.patch.object(terminal,'paired_terminal',side_effect=AssertionError('must fail before network')):
                bad=tree.FileSource(source.path,source.size,'0'*64,source.sig)
                self.assertNotEqual(adapter.exchange(f'put ux0:/VITA-POC/x.vpk {source.size} sha256={self.sha}',7200,bad)[0],0)
        with self.assertRaisesRegex(registry.Denied,'case-not-approved'):
            with registry.approve_file(self.package,'fs-smoke',registry=self.approval):pass
        wrong=self.base/'wrong.txt';wrong.write_text(f'LARG12346 {VERSION} {self.sha} -\n')
        with self.assertRaisesRegex(registry.Denied,'package-identity-mismatch'):
            with registry.approve_file(self.package,registry=wrong):pass
        missing=self.base/'missing.txt';missing.write_text(f'{TITLE} {VERSION} '+('0'*64)+' -\n')
        with mock.patch.object(registry,'read_identity',side_effect=AssertionError('identity before hash forbidden')):
            with self.assertRaisesRegex(registry.Denied,'sha256-not-approved'):
                with registry.approve_file(self.package,registry=missing):pass

    def test_zip64_and_unbounded_sfo_denied(self):
        for label,sfo_data,zip64 in [('sfo',b'x'*65537,False),('zip64',sfo(),True)]:
            package=self.base/(label+'.vpk')
            with zipfile.ZipFile(package,'w') as archive:
                with archive.open('eboot.bin','w',force_zip64=zip64) as out:out.write(b'fixture')
                archive.writestr('sce_sys/param.sfo',sfo_data)
            approval=self.base/(label+'.txt');approval.write_text(f'{TITLE} {VERSION} {digest(package)} -\n')
            with self.assertRaises(registry.Denied):
                with registry.approve_file(package,registry=approval):pass

    def test_tree_no_256_entry_12_depth_or_192mib_batch_quota(self):
        folder=self.base/'tree';folder.mkdir()
        for n in range(300):(folder/f'{n:03d}').write_bytes(b'x')
        nested=folder
        for _ in range(13):nested=nested/'a';nested.mkdir()
        (nested/'x').write_bytes(b'x')
        batch=tree.plan([folder,self.package],tree.ROOT,True,terminal.quoted_path)
        self.assertGreater(len(batch.entries),300)
        self.assertGreater(batch.total,192*MIB)
        with mock.patch.object(tree,'MAX_BYTES',3):
            with self.assertRaises(tree.TreeError):tree.plan([self.package],tree.ROOT,False,terminal.quoted_path)
        with self.assertRaises(terminal.Refused):tree.plan([self.package],tree.ROOT+'/a'*60,False,terminal.quoted_path)

    def test_file_source_revalidated_by_terminal_and_adapter(self):
        local=self.base/'small';local.write_bytes(b'small fixture')
        class Device:
            deadline=0
            def push(self,source,remote):
                self.source=source
                return dict(remote=remote,bytes=source.size,sha256=source.sha256)
        device=Device()
        with tree.file_snapshot(local) as source:
            request=f'put ux0:/VITA-POC/x {source.size} sha256={source.sha256}'
            with mock.patch.object(terminal,'paired_terminal',return_value=contextlib.nullcontext(device)):
                self.assertEqual(adapter.exchange(request,7200,source)[0],0)
            source.path.write_bytes(b'mutated source')
            with mock.patch.object(terminal,'paired_terminal',side_effect=AssertionError('no network after mutation')):
                self.assertNotEqual(adapter.exchange(request,7200,source)[0],0)
            wire=Wire(b'');term=terminal.Terminal(wire)
            with self.assertRaises(tree.TreeError):term.push(source,'ux0:/VITA-POC/x')
            self.assertFalse(wire.sent)

    def test_streamed_progress_over_64k_and_long_timeout_exact_receipt(self):
        command='app-install "ux0:/VITA-POC/x.vpk"'
        progress=b''.join(f'app-progress phase=copy bytes={n}\r\n'.encode() for n in range(2400))
        progress+=b'app-progress phase=validate bytes=0\r\napp-progress phase=extract bytes=558000000\r\n'
        receipt=f'OK app-install title={TITLE} app_ver={VERSION} files=303 detail=0 session=kept\r\n'.encode()
        wire=Wire(command.encode()+b'\r\n'+progress+receipt+b'ux0:/> exit\r\nBye.\r\n')
        term=terminal.Terminal(wire)
        with contextlib.redirect_stderr(io.StringIO()) as log:result=term._transcript_and_exit(command,7200)
        self.assertEqual(result['stdout'],receipt.decode().replace('\r\n','\n'))
        self.assertEqual(result['progress'],{'count':2402,'last':{'phase':'extract','bytes':558000000}})
        self.assertGreater(len(log.getvalue()),65536)
        self.assertEqual(wire.sent,[command.encode()+b'\n',b'exit\n'])

    def test_progress_regression_malformed_overflow_or_missing_receipt_refused(self):
        command='app-install "ux0:/VITA-POC/x.vpk"'
        for bad in [b'app-progress phase=copy bytes=18446744073709551616\r\n',
                    b'app-progress phase=copy bytes=01\r\n',
                    b'app-progress phase=copy bytes=2\r\napp-progress phase=copy bytes=1\r\n',
                    b'app-progress phase=extract bytes=1\r\napp-progress phase=validate bytes=2\r\n',
                    b'app-progress phase=copy bytes=1\r\n']:
            wire=Wire(command.encode()+b'\r\n'+bad)
            term=terminal.Terminal(wire)
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(terminal.Refused):
                term._transcript_and_exit(command,7200)
        self.assertEqual(terminal.LIMIT,0xffffffff)
        self.assertEqual(registry.MAX_VPK,0xfffffffe)
        # 10-digit request is parsed and rejected on absent data before transport,
        # rather than being interpreted as a text command. Width is not 999MB.
        with mock.patch.object(terminal,'paired_terminal',side_effect=AssertionError('no network')):
            rc,text=adapter.exchange('put ux0:/VITA-POC/x 1000000000 sha256='+('0'*64),7200,b'x')
        self.assertEqual(rc,1);self.assertIn('upload bytes differ',text)

if __name__=='__main__':
    if sys.argv[1:]==['--probe']:probe()
    else:unittest.main(verbosity=2)
