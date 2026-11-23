import sys, unittest
from apply_verify import verify_behavior
class TestBehavior(unittest.TestCase):
    def test_success(self):
        spec={'command':[sys.executable,'-c','print("RESULT:"+"{input}")','{binary}'],'inputs':[0,-1]}
        self.assertEqual(verify_behavior(spec,'a','b')['status'],'passed')
    def test_failure(self):
        spec={'command':[sys.executable,'-c','print("RESULT:1" if "{binary}" == "a" else "RESULT:2")'],'inputs':[1]}
        self.assertEqual(verify_behavior(spec,'a','b')['status'],'failed')
    def test_unavailable(self):
        self.assertEqual(verify_behavior({'command':['missing-runner-xyz'],'inputs':[1]},'a','b')['status'],'not_run')
if __name__ == '__main__': unittest.main()

class TestApply(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pathlib import Path
        from static_export import export
        from apply_verify import sha
        from probe import digest
        fixture=Path(__file__).parent / 'tests/fixtures/lesson_score'
        cls.binary=fixture / 'libflatten_fla_android.so'
        cls.table,cls.cfg=export(fixture / 'lesson_score_trace_disasm.txt',sha(cls.binary.read_bytes()),'lesson_score',cls.binary)
        cls.structure={'selected_candidate':'0x1604','candidates':[{'hub':'0x1604','dispatcher_blocks':['0x1604']}]}
        first=cls.table['instructions'][0]
        cls.plan={'binary_id':sha(cls.binary.read_bytes()),'function':'lesson_score','strategy':'arm64_direct_edges_v1','input_hashes':{'instruction_table':digest(cls.table),'static_cfg':digest(cls.cfg),'structure_candidates':digest(cls.structure)},'unresolved':[], 'entries':[{'status':'ready','audit':{'passed':True},'patches':[{'site':first['module_offset'],'old_bytes':first['bytes'],'new_bytes':'02000014','kind':'b','condition':None,'target':'0x1604'}]}]}
    def test_apply_and_rollback(self):
        import tempfile
        from pathlib import Path
        from apply_verify import apply_plan, sha
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'patched.so'; before=sha(self.binary.read_bytes())
            result=apply_plan(self.binary,self.plan,out,self.table,self.cfg,self.structure)
            self.assertTrue(result['rollback_ok']); self.assertEqual(before,sha(self.binary.read_bytes()))
            self.assertNotEqual(before,sha(out.read_bytes()))
            self.assertEqual(result['static_checks']['reachable_dispatcher_blocks'],1)
            self.assertEqual(result['patched_instruction_table']['instructions'][0]['mnemonic'],'b')
    def test_rejections(self):
        import tempfile, copy
        from pathlib import Path
        from apply_verify import apply_plan
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'patched.so'
            for mutate in ('old','hash','status','target'):
                plan=copy.deepcopy(self.plan)
                if mutate=='old': plan['entries'][0]['patches'][0]['old_bytes']='00000000'
                if mutate=='hash': plan['binary_id']='0'*64
                if mutate=='status': plan['entries'][0]['status']='unresolved'
                if mutate=='target': plan['entries'][0]['patches'][0]['target']='0x1608'
                with self.subTest(mutate=mutate), self.assertRaises(ValueError): apply_plan(self.binary,plan,out,self.table,self.cfg,self.structure)
                self.assertFalse(out.exists())
