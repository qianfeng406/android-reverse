import unittest
from model_policy import classify_blocker as c

class PolicyTests(unittest.TestCase):
    def test_d0_d1(self):
        for n in (0, 1): self.assertIsNone(c(n, {}))
    def test_d2(self):
        self.assertIsNotNone(c(2, {'structure_candidates': {'candidates': []}}))
        x = {'hub':'1', 'state_slot':'s', 'state_writers':['a'], 'comparison_blocks':['b'], 'fan_in':2}
        self.assertIsNone(c(2, {'structure_candidates': {'candidates':[x]}}))
        self.assertIsNotNone(c(2, {'structure_candidates': {'candidates':[x, {**x, 'hub':'2'}]}}))
    def test_d3(self):
        self.assertIsNotNone(c(3, {'compiled_probe_plan': {'unsupported':[{'reason':'state_write_count'}]}}))
        self.assertIsNone(c(3, {'observations': {'missing_events': 1}}))
    def test_d4(self):
        self.assertIsNotNone(c(4, {'unresolved_rules': {'unresolved':[{'reason':'unsupported_instruction'}]}}))
        self.assertIsNone(c(4, {'unresolved_rules': {'unresolved':[{'reason':'stale_input'}]}}))
        rules = {'rules':[{'source_block':'0x1', 'alternatives':[{'status':'contradicted'}]}]}
        obs = {'diagnostics':[], 'unpaired_events':[], 'records':[{'quality':{'complete':True}}]}
        self.assertIsNone(c(4, {'transition_rules':rules}))
        self.assertIsNotNone(c(4, {'transition_rules':rules, 'transition_observations':obs}))
        self.assertIsNone(c(4, {'transition_rules':rules, 'transition_observations':{**obs, 'diagnostics':[{'reason':'gap'}]}}))
        self.assertIsNone(c(4, {'transition_rules':rules, 'transition_observations':{**obs, 'unpaired_events':[{}]}}))
        self.assertIsNone(c(4, {'transition_rules':rules, 'transition_observations':{**obs, 'records':[{'quality':{'complete':False}}]}}))
    def test_d5(self):
        self.assertIsNotNone(c(5, {'patch_plan': {'unresolved':[{'reason':'conditional_template_mismatch'}]}}))
        self.assertIsNone(c(5, {'patch_plan': {'unresolved':[{'reason':'instruction_bytes_mismatch'}]}}))
    def test_d6(self):
        report = {'static_checks':{'patch_count':1,'reachable_dispatcher_blocks':0}, 'rollback_ok':True, 'behavior':{'status':'failed','cases':[{'match':False, 'original':{'exit_code':0,'return_value':1}, 'patched':{'exit_code':0,'return_value':2}}]}}
        self.assertIsNotNone(c(6, {'verification_report': report}))
        self.assertEqual(c(2, {'structure_candidates': {'candidates':[{'hub':'0x1', 'state_slot':'a'}, {'hub':'0x2', 'state_slot':'b'}]}})['sources'], ['0x1', '0x2'])
        report['behavior']['cases'][0]['patched'] = {'exit_code':139,'return_value':None,'stderr':'segmentation fault'}
        self.assertIsNotNone(c(6, {'verification_report': report}))
        report['behavior']['cases'][0]['patched'] = {'exit_code':1,'return_value':None,'stderr':'dlopen failed'}
        self.assertIsNotNone(c(6, {'verification_report': report}))
        report['behavior']['cases'][0]['patched']['stderr'] = 'no devices found'
        self.assertIsNone(c(6, {'verification_report': report}))
        report['behavior']['cases'][0]['patched'] = {'exit_code':1,'return_value':None,'stderr':'no devices/emulators found'}
        self.assertIsNone(c(6, {'verification_report': report}))
        report['behavior']['status'] = 'not_run'
        self.assertIsNone(c(6, {'verification_report': report}))

if __name__ == '__main__': unittest.main()
