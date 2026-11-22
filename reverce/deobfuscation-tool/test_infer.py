"""D4 regression tests using the verified D0/D2 fixture."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from infer import infer_rules

ROOT = Path(__file__).parent
FIXTURE = ROOT / 'tests/fixtures/lesson_score'


class InferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            b = FIXTURE / 'libflatten_fla_android.so'
            commands = [('init','--binary',b,'--output',d),
                        ('static','--binary',b,'--disasm',FIXTURE/'lesson_score_trace_disasm.txt','--function','lesson_score','--output',d),
                        ('import-legacy','--binary',b,'--log',FIXTURE/'lesson_score_trace_raw.log','--output',d),
                        ('discover','--output',d)]
            for args in commands:
                subprocess.run([sys.executable,str(ROOT/'cli.py'),*map(str,args)],check=True,capture_output=True)
            def load(name): return json.loads((Path(d)/name).read_text())['data']
            cls.instructions = load('instruction_table.json'); cls.cfg = load('static_cfg.json'); cls.structure = load('structure_candidates.json')

    def infer(self, records=(), instructions=None):
        return infer_rules(instructions or self.instructions, self.cfg, self.structure, {'records':list(records)}, 'test')

    def test_fixture_static_alternatives(self):
        rules, unresolved = self.infer()
        self.assertEqual(sorted(len(r['alternatives']) for r in rules['rules']), [1]*10+[2]*4)
        self.assertFalse(unresolved['unresolved'])
        self.assertTrue(all(a['status'] == 'static_proven' for r in rules['rules'] for a in r['alternatives']))
        rule = next(r for r in rules['rules'] if r['source_block'] == '0x17e0')
        self.assertEqual({(a['state_ast']['hex'],a['target_block']) for a in rule['alternatives']},
                         {('0x81fc94e6','0x1804'),('0xe6e37d04','0x182c')})

    def record(self, value, state, target):
        return {'id':'r','origin':{'source_block':'0x17e0'},
                'decision':{'values':{'w8':{'width':32,'hex':hex(value)}}},
                'transfer':{'kind':'state_write','site':'0x17fc','location':'sp+0x4','value':{'width':32,'hex':state}},
                'route':{'immediate_successor':'0x18f8','eventual_target':target},'quality':{'complete':True,'ambiguous':False}}

    def test_observations_and_conflict(self):
        for value,state,target in [(2,'0x81fc94e6','0x1804'),(3,'0xe6e37d04','0x182c')]:
            rules, errors = self.infer([self.record(value,state,target)])
            rule = next(r for r in rules['rules'] if r['source_block']=='0x17e0')
            self.assertEqual(sorted(a['status'] for a in rule['alternatives']), ['observed_and_static_proven','static_proven'])
            self.assertFalse(errors['unresolved'])
        rules, errors = self.infer([self.record(2,'0x00000000','0x1804')])
        rule = next(r for r in rules['rules'] if r['source_block']=='0x17e0')
        self.assertIn('contradicted', [a['status'] for a in rule['alternatives']])
        self.assertTrue(any(e['reason']=='observation_conflict' for e in errors['unresolved']))

    def test_incomplete_and_wrong_target(self):
        missing = self.record(2, '0x81fc94e6', '0x1804')
        missing['quality']['complete'] = False
        rules, errors = self.infer([missing])
        rule = next(r for r in rules['rules'] if r['source_block'] == '0x17e0')
        self.assertTrue(all(a['status'] == 'static_proven' for a in rule['alternatives']))
        self.assertTrue(any(e['reason'] == 'incomplete_observation' for e in errors['unresolved']))
        rules, errors = self.infer([self.record(2, '0x81fc94e6', '0x182c')])
        rule = next(r for r in rules['rules'] if r['source_block'] == '0x17e0')
        self.assertIn('contradicted', [a['status'] for a in rule['alternatives']])

    def test_entry_return_and_transfer_validation(self):
        entry = {'id':'entry', 'origin':{'source_block':'0x15fc'},
                 'decision':None,
                 'transfer':{'kind':'state_write','site':'0x161c','location':'sp+0x4',
                             'value':{'width':32,'hex':'0x31077cc4'}},
                 'route':{'immediate_successor':'0x1620','eventual_target':'0x1760'},
                 'quality':{'complete':True,'ambiguous':False}}
        rules, errors = self.infer([entry])
        source = next(r for r in rules['rules'] if r['source_block']=='0x15fc')
        self.assertEqual(source['alternatives'][0]['target_block'], '0x1760')
        self.assertEqual(source['alternatives'][0]['status'], 'observed_and_static_proven')
        coalesced = deepcopy(entry); coalesced['route']['immediate_successor'] = '0x1638'
        coalesced_rules, coalesced_errors = self.infer([coalesced])
        coalesced_rule = next(r for r in coalesced_rules['rules'] if r['source_block']=='0x15fc')
        self.assertEqual(coalesced_rule['alternatives'][0]['status'], 'observed_and_static_proven')
        self.assertFalse(coalesced_errors['unresolved'])
        terminal = next(r for r in rules['rules'] if r['source_block']=='0x18ec')
        self.assertEqual(terminal['transfer_kind'], 'return')
        self.assertEqual(terminal['alternatives'][0]['status'], 'static_proven')
        for field, wrong in [('kind','direct_branch'), ('site','0x1618'), ('location','sp+0x8')]:
            bad = deepcopy(entry); bad['transfer'][field] = wrong
            output, unresolved = self.infer([bad])
            rule = next(r for r in output['rules'] if r['source_block']=='0x15fc')
            self.assertEqual(rule['alternatives'][0]['status'], 'static_proven')
            self.assertTrue(any(e['reason']=='observation_transfer_mismatch' for e in unresolved['unresolved']))
        bad = deepcopy(entry); bad['route']['immediate_successor'] = '0x18f8'
        output, unresolved = self.infer([bad])
        self.assertTrue(any(e['reason']=='observation_transfer_mismatch' for e in unresolved['unresolved']))

    def test_unknown_instruction_stops_proof(self):
        instructions = deepcopy(self.instructions)
        next(i for i in instructions['instructions'] if i['module_offset']=='0x17f8')['mnemonic'] = 'unsupported'
        rules, errors = self.infer(instructions=instructions)
        rule = next(r for r in rules['rules'] if r['source_block']=='0x17e0')
        self.assertEqual(rule['alternatives'], [])
        self.assertTrue(any('unsupported_instruction' in e['reason'] for e in errors['unresolved']))


if __name__ == '__main__': unittest.main()
