from pathlib import Path
import sys, unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import crash_window as w

A="2026-11-22T23:10:00";B="2026-11-22T23:20:00"
def row(t):return dict(name='psp2core-test.tmp',modified=t,bytes=123)
def call(rows,matched=None,truncated=0):return w.classify(rows,len(rows) if matched is None else matched,truncated,A,B)
class TestWindow(unittest.TestCase):
    def test_empty_complete(self):self.assertEqual(call([])['status'],'NO_MATCH')
    def test_complete_old_file(self):self.assertEqual(call([row('2026-11-21T08:33:09')])['status'],'NO_MATCH')
    def test_endpoints_included(self):
        for time in [A,B]:self.assertEqual(call([row(time)])['status'],'MATCH')
    def test_outside_by_one_second(self):
        for at in ['2026-11-22T23:09:59','2026-11-22T23:20:01']:self.assertEqual(call([row(at)])['status'],'NO_MATCH')
    def test_missing_time(self):
        for at in (None,'unknown'):
            item=call([row(at)]);self.assertEqual((item['status'],item['unknown_time_count']),('INCONCLUSIVE',1))
    def test_omitted_file(self):self.assertEqual(call([row('2026-11-23T00:00:00')],2,1)['status'],'INCONCLUSIVE')
    def test_truncated_match_still_not_complete(self):
        item=call([row(B)],2,1);self.assertEqual((item['status'],item['coverage']),('MATCH','incomplete'))
    def test_filenames_are_not_evidence_of_time_or_title(self):
        item=call([dict(name='psp2core-1795350000-eboot.bin.psp2dmp',modified='unknown',bytes=128)])
        self.assertEqual(item['candidates'],[])
    def test_arguments(self):
        for a,b in ((A,None),(None,B),(B,A),('2026-02-29T12:00:00',B),(A,B+'Z'),(A,B+'+08:00'),(A,B+' command')):
            with self.subTest(a=a,b=b),self.assertRaises(ValueError):w.validate_window(a,b)
    def test_counts(self):
        for n,cut in ((0,0),(3,0),(1,1),(1,'false')):
            with self.assertRaises(ValueError):call([row(A)],n,cut)
    def test_across_midnight(self):
        item=w.classify([row('2026-11-23T00:00:00')],1,0,'2026-11-22T23:59:00','2026-11-23T00:01:00')
        self.assertEqual(item['status'],'MATCH')
    def test_no_optional_window(self):self.assertIsNone(w.validate_window(None,None))
if __name__=='__main__':unittest.main(verbosity=2)
