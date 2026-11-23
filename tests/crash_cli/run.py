"""5090 CLI host positive/negative cases. No live transport; sockets fail the test."""
import argparse,contextlib,io,json,pathlib,socket,sys,time,unittest
from unittest.mock import patch
T=pathlib.Path(__file__).resolve().parents[2]/'tools'
sys.path.insert(0,str(T))
import crash_cli as c
import wbctl

PIN='a'*64
SESSION='b'*64
RUN='E6F28CAEAE7E5914'
EP=(c.wb.HOST,str(c.wb.PORT),c.wb.USER)
ARG=lambda **kw: argparse.Namespace(**dict(dict(limit=None,since=None,until=None,json=True),**kw))

def wire(rows,total=None,truncated=False):
    total=len(rows) if total is None else total
    return '\n'.join([f'OK crash-index matched={total} shown={len(rows)} truncated={int(truncated)} clock=device-local',
                     *[f'crash name={n} modified={t} bytes={s}' for n,t,s in rows],'END crash-index',''])
DATA=[('psp2core-1795249989-0x0000712f9b-eboot.bin.psp2dmp.tmp','2026-11-21T08:33:09',2560),
      ('psp2core-1795248808-0x00009f26ab-eboot.bin.psp2dmp','2026-11-21T08:13:28',130016),
      ('psp2core-1795247912-0x0000a62633-eboot.bin.psp2dmp.tmp','2026-11-21T07:58:32',2560)]

class Term:
    def __init__(self,out):
        self.version='01.80';self.host_pin=PIN;self.transport_id=SESSION;self.deadline=time.monotonic()+600
        self.out=out;self.calls=[];self.count=0
    def check(self):
        self.calls.append('ver/status/ver')
        return dict(version=self.version,build=self.version+'-live-index',run=RUN,
                    channel='one interactive PTY',host_sha256=self.host_pin,transport_sha256=self.transport_id)
    def _transcript_and_exit(self,cmd,timeout):
        self.calls.extend((cmd,'exit'))
        return dict(command=cmd,shell_exit=0,host_sha256=self.host_pin,transport_sha256=self.transport_id,stdout=self.out)
    @contextlib.contextmanager
    def paired(self):
        self.count+=1
        if self.count!=1:raise AssertionError('more than one session')
        yield self
    def run(self,limit=10,explicit=False):return c.session_query(limit,explicit,self.paired,lambda:PIN)

class Transport(unittest.TestCase):
    def test_one_pinned_pty(self):
        t=Term(wire(DATA));j=t.run()
        self.assertEqual(t.count,1);self.assertEqual(t.calls,['ver/status/ver','diag crashes','exit'])
        self.assertEqual(j['transport_sha256'],SESSION);self.assertEqual(j['host_sha256'],PIN)
        self.assertEqual(j['entries'][0],dict(name=DATA[0][0],modified=DATA[0][1],bytes=2560))
        self.assertFalse(j['title_attributed']);self.assertEqual(j['matched'],3)
    def test_canonical_limit(self):
        t=Term(wire(DATA[:1],3,True));j=t.run(1,True)
        self.assertTrue(j['truncated']);self.assertEqual(t.calls[1],'diag crashes --limit 1')
    def test_older_device_rejected_no_index(self):
        t=Term('');t.version='01.79';self.assertEqual(t.run()['status'],'UNSUPPORTED_CORE')
        self.assertEqual(t.calls,['ver/status/ver'])
    def test_wrong_server_refused_before_command(self):
        t=Term(wire([]));t.host_pin='e'*64
        with self.assertRaises(c.ProtocolError):t.run()
        self.assertFalse(t.calls)
    def test_altered_channel_receipt(self):
        t=Term(wire([]));send=t._transcript_and_exit
        with patch.object(t,'_transcript_and_exit',side_effect=lambda cmd,timeout:dict(send(cmd,timeout),transport_sha256='c'*64)):
            with self.assertRaises(c.ProtocolError):t.run()
    def test_removed_pin_prevents_connect(self):
        t=Term('')
        def missing():raise c.wb.pin.PairError('missing pin')
        with self.assertRaises(c.wb.pin.PairError):c.session_query(10,False,t.paired,missing)
        self.assertEqual(t.count,0)
    def test_no_endpoint_fallback(self):
        self.assertEqual(c.execute(ARG(),('192.0.2.2','1337','pi'),lambda *a:self.fail('dialed'))[0],78)
    def test_no_error_leak_or_retry(self):
        hits=[]
        def bad(*a):hits.append(1);raise OSError("UNRELATED_NAME_SHOULD_NOT_LEAK")
        rc,j=c.execute(ARG(),EP,bad);self.assertNotEqual(rc,0);self.assertEqual(hits,[1])
        self.assertNotIn('UNRELATED_NAME',str(j))

    def test_fragmented_real_terminal(self):
        # Exercise wbterm.Terminal itself: fragmented CRLFs/echo/prompt, max
        # response size, and SSH exit status. This fake has no socket or exec.
        class Channel:
            def __init__(self):
                self.buf=bytearray(b'VITA AGENT TERMINAL 01.80 (Workbench)\r\nType help for commands.\r\nux0:/> ')
                self.sent=[];self.rc=0
            def sendall(self,data):
                line=data.decode('ascii').removesuffix('\n');self.sent.append(line)
                version=f'wb version=01.80 build=01.80-live-crashindex abi=3 proto=wb10 run={RUN} payload=none uptime_ms=104'
                status=f'run={RUN} uptime_ms=104 ssh=connected cmds=3 payload=none core=01.80 last_install=none peer=127.0.0.1:2222'
                text={'ver':version+'\n','status':status+'\n','diag crashes --limit 32':self.reply,'exit':'Bye.\n'}[line]
                msg=line+'\n'+text+('ux0:/> ' if line!='exit' else '')
                self.buf.extend(msg.replace('\n','\r\n').encode('ascii'))
            def recv(self,n): part=self.buf[:min(n,11)];del self.buf[:len(part)];return bytes(part)
            def recv_stderr_ready(self):return False
            def settimeout(self,_):pass
            def exit_status_ready(self):return self.sent[-1]=='exit' and not self.buf
            def recv_exit_status(self):return self.rc
        rows=[('psp2core-'+'a'*115+f'{i:03}', '1980-02-29T00:00:00',2**63-1) for i in range(32)]
        for status in (0,1):
            ch=Channel();ch.reply=wire(rows,1024,True);ch.rc=status
            term=c.wb.Terminal(ch,PIN,SESSION)
            def q():return c.session_query(32,True,lambda:contextlib.nullcontext(term),lambda:PIN)
            if status==0:
                j=q();self.assertEqual((j['shown'],j['matched'],j['truncated']),(32,1024,True))
            else:
                with self.assertRaises(c.wb.Refused):q()
            self.assertEqual(ch.sent,['ver','status','ver','diag crashes --limit 32','exit'])

class Grammar(unittest.TestCase):
    def test_empty_is_a_success(self):
        self.assertEqual(c.parse(wire([]),10)['entries'],[])
    def test_known_errors_distinct_from_empty(self):
        for r in ('usage','no-pty','nomem','open','read','close','scan-limit','metadata'):
            self.assertEqual(c.parse('ERR crash-index '+r+'\n',10),dict(status='DEVICE_ERROR',reason=r))
    def test_bad_fields_and_footers(self):
        original=wire(DATA[:1])
        for f in (original.replace('END crash-index',''),original.replace('truncated=0','truncated=1'),
                  original.replace(' matched=1',' matched=99'),original.replace(' shown=1',' shown=4'),
                  original.replace('matched=1','matched=01'),original+'ux0:/> ',original.replace('bytes=2560','bytes=-1'),
                  original.replace('bytes=2560','bytes=9223372036854775808'),original.replace('2026-11-21','2026-02-30'),
                  original.replace('2026-11-21','1979-12-31'),
                  original.replace('psp2core-','other-'),original.replace('-eboot','/eboot'),original.replace('1795249989','..a'),
                  original.replace('-eboot','\x1beboot'),'ERR crash-index read\nEND crash-index\n','ERR crash-index private-name',
                  original.replace('psp2core-','psp2core-'+'a'*128),wire([DATA[0],DATA[0]])):
            with self.subTest(reply=f[:120]), self.assertRaises(c.ProtocolError):c.parse(f,10)
    def test_sort_order_and_unknown(self):
        a=('psp2core-A','unknown',0);b=('psp2core-B','unknown',2)
        self.assertEqual(c.parse(wire([*DATA,a,b]),10)['shown'],5)
        for bad in ([DATA[2],DATA[0]],[a,DATA[0]],[b,a]):
            with self.assertRaises(c.ProtocolError):c.parse(wire(bad),10)
    def test_ties_ordered_bytewise(self):
        d=DATA[0][1];valid=[('psp2core-A',d,2),('psp2core-a',d,1)]
        self.assertEqual(c.parse(wire(valid),10)['shown'],2)
        with self.assertRaises(c.ProtocolError):c.parse(wire(valid[::-1]),10)

class Cli(unittest.TestCase):
    def invoke(self,args,run):
        out=io.StringIO()
        with patch.object(c,'execute',side_effect=run),contextlib.redirect_stdout(out):
            rc=wbctl.main(args)
        return rc,out.getvalue()
    def test_both_json_forms(self):
        def run(a,ep):
            self.assertIs(a.json,True);self.assertEqual(ep,EP)
            return 0,dict(status='OK',entries=[])
        for args in (['--json','diag','crashes'],['diag','crashes','--json']):
            rc,out=self.invoke(args,run);self.assertEqual(rc,0);self.assertEqual(json.loads(out)['status'],'OK')
    def test_no_freeform_remote_arguments(self):
        for suffix in (['ux0:data'],['--limit','-1'],['--limit','33'],['--limit','01'],['--limit','1;foo'],['--lim','2'],['--port','21']):
            with self.subTest(suffix=suffix),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as e:
                self.invoke(['diag','crashes',*suffix],lambda *x:self.fail('bad argument reached query'))
            self.assertEqual(e.exception.code,2)
    def test_human_readable(self):
        rc,out=self.invoke(['diag','crashes'],lambda *x:(0,Term(wire(DATA)).run()))
        self.assertEqual(rc,0);self.assertIn('device-local time',out);self.assertIn('130016',out)
    def test_window_argument_and_default(self):
        calls=[]
        def query(n,explicit):calls.append(n);return Term(wire(DATA)).run(n,explicit)
        rc,j=c.execute(ARG(since='2026-11-22T23:09:00',until='2026-11-22T23:20:00'),EP,query)
        self.assertEqual(rc,0);self.assertEqual(calls,[32]);self.assertEqual(j['window']['status'],'NO_MATCH')
    def test_window_on_explicit_limit(self):
        calls=[]
        def query(n,explicit):
            calls.append((n,explicit));return Term(wire(DATA[:1],3,True)).run(n,explicit)
        start=end='2026-11-21T08:13:28'
        rc,j=c.execute(ARG(since=start,until=end,limit=1),EP,query)
        self.assertEqual(rc,0);self.assertEqual(calls,[(1,True)]);self.assertEqual(j['window']['status'],'INCONCLUSIVE')
    def test_invalid_window_never_dials(self):
        for kw in (dict(since='a'),dict(until='a'),dict(since='a',until='b'),
                   dict(since='2026-11-22T23:20:00',until='2026-11-22T23:19:59')):
            self.assertEqual(c.execute(ARG(**kw),EP,lambda *x:self.fail('invalid window dialed'))[0],2)

if __name__=='__main__':
    with patch.object(socket,'socket',side_effect=AssertionError('network disabled in host tests')):
        unittest.main(verbosity=2)
