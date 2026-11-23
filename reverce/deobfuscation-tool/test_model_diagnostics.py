import unittest
from copy import deepcopy
from model_diagnostics import build_diagnostic_request, validate_diagnostic, ReplayDiagnosticAdapter

class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.r = build_diagnostic_request(4, {'reason':'unknown'}, 'bin', {'instruction_table':{'instructions':[{'module_offset':hex(i)} for i in range(50)]}, 'transition_observations':{'records':[{'id':str(i)} for i in range(20)]}})
        self.p = {'schema_version':1,'stage':4,'binary_id':'bin','reason_code':'unknown','findings':[{'explanation':'inspect','evidence_refs':[self.r['evidence_refs'][0]]}],'next_action':'inspect','rule_ids':[],'probe_sites':[]}
    def test_limits_and_replay(self):
        self.assertEqual(len(self.r['instructions']),32)
        self.assertEqual(len(self.r['observations']),8)
        self.assertEqual(ReplayDiagnosticAdapter({'request':self.r,'proposal':self.p}).propose(self.r),self.p)
    def test_graph_and_source_focus(self):
        ins = [{'module_offset':hex(i)} for i in range(100)]
        blocks = [{'start':'0x0','end_exclusive':'0x20','successors':[{'target':'0x40','in_function':True}]},
                  {'start':'0x40','end_exclusive':'0x50','successors':[]}]
        artifacts = {'instruction_table':{'instructions':ins}, 'static_cfg':{'blocks':blocks},
                     'structure_candidates':{'observed_graph':{'nodes':[{'start':'0x40','visits':20}], 'observed_transitions':[{'source':'0x0','target':'0x40','count':5}]},'candidates':[]}}
        r = build_diagnostic_request(2, {'reason':'no_candidates'}, 'bin', artifacts)
        self.assertEqual(r['instructions'][0]['module_offset'], '0x40')
        self.assertEqual(r['context']['observed_edges'][0]['target'], '0x40')
        self.assertIn('block:0x40', r['evidence_refs'])
        r = build_diagnostic_request(3, {'reason':'unsupported','source_block':'0x40'}, 'bin', artifacts)
        self.assertEqual(r['instructions'][0]['module_offset'], '0x40')
        self.assertNotIn('block:0xffff', r['evidence_refs'])
    def test_reject_invalid(self):
        for key,value in [('binary_id','other'),('probe_sites',['0xffff']),('rule_ids',['unknown'])]:
            p=deepcopy(self.p); p[key]=value
            with self.assertRaises(ValueError): validate_diagnostic(self.r,p)
        p=deepcopy(self.p); p['findings'][0]['evidence_refs']=['invented']
        with self.assertRaises(ValueError): validate_diagnostic(self.r,p)

    def test_late_behavior_difference_is_in_request(self):
        unavailable = {'match':False,'input':0,'original':{'exit_code':0,'return_value':1},
                       'patched':{'exit_code':1,'return_value':None,'stderr':'library not found'}}
        mismatch = {'match':False,'input':9,'original':{'exit_code':0,'return_value':1},
                    'patched':{'exit_code':0,'return_value':2,'stderr':''}}
        artifacts = {'verification_report': {'behavior': {'status':'failed',
                                                          'cases':[unavailable]*8+[mismatch]}}}
        from model_policy import classify_blocker
        blocker = classify_blocker(6, {'verification_report': {'static_checks':
                                    {'patch_count':1,'reachable_dispatcher_blocks':0},
                                    'rollback_ok':True, **artifacts['verification_report']}})
        self.assertIsNotNone(blocker)
        request = build_diagnostic_request(6, blocker, 'bin', artifacts)
        self.assertEqual(request['context']['behavior']['cases'][0]['input'], 9)

if __name__ == '__main__': unittest.main()
