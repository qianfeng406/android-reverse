"""D2 checks using the checked-in ARM64 sample and an ordinary loop."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from discover import discover, choose_model_rules
from validation import validate


ROOT = Path(__file__).parent
FIXTURE = ROOT / 'tests/fixtures/lesson_score'


class DiscoveryTests(unittest.TestCase):
    def test_unknown_discovery_strategy_is_explicit(self):
        with self.assertRaisesRegex(ValueError,'unsupported D2 discovery strategy'):
            discover({}, {}, {}, strategy='register_dispatch_v1')

    def test_demo_end_to_end_without_addresses(self):
        with tempfile.TemporaryDirectory() as d:
            base = [sys.executable, str(ROOT/'cli.py')]
            binary = FIXTURE/'libflatten_fla_android.so'
            def run(*args):
                result = subprocess.run(base + list(map(str,args)), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            run('init','--binary',binary,'--output',d)
            run('static','--binary',binary,'--disasm',FIXTURE/'lesson_score_trace_disasm.txt','--function','lesson_score','--output',d)
            run('import-legacy','--binary',binary,'--log',FIXTURE/'lesson_score_trace_raw.log','--output',d)
            run('discover','--output',d)
            run('stage','--output',d,'--from-stage','2')
            structure=json.loads((Path(d)/'structure_candidates.json').read_text())['data']
            plan=json.loads((Path(d)/'probe_plan.json').read_text())['data']
            dot=(Path(d)/'observed_graph.dot').read_text()
            self.assertIn('style=dashed',dot)
            self.assertEqual((structure['selected_candidate'],structure['candidates'][0]['state_slot']),('0x18f8','sp+4'))
            self.assertEqual({x['source_block'] for x in plan['probes']}, {'0x1760','0x17bc','0x17e0','0x188c'})
            self.assertTrue(all(x['direct_cfg_edge'] is None for x in structure['observed_graph']['observed_transitions']))
            self.assertTrue(all(x['event_evidence'] for x in structure['observed_graph']['observed_transitions']))
            self.assertTrue(structure['unresolved'])
            run('discover','--output',d,'--rules','fanin,routing')
            narrowed=json.loads((Path(d)/'structure_candidates.json').read_text())['data']
            self.assertIsNone(narrowed['selected_candidate'])
            self.assertTrue(narrowed['unresolved'])

    def test_hot_ordinary_loop_is_not_dispatcher(self):
        instruction={'instructions':[
            {'module_offset':'0x100','mnemonic':'add','operands':'w0, w0, #1'},
            {'module_offset':'0x104','mnemonic':'cmp','operands':'w0, #9'},
            {'module_offset':'0x108','mnemonic':'b.lt','operands':'#0x100'},
            {'module_offset':'0x10c','mnemonic':'ret','operands':''}]}
        cfg={'blocks':[{'start':'0x100','end_exclusive':'0x10c','successors':[{'target':'0x100','kind':'branch','in_function':True},{'target':'0x10c','kind':'fallthrough','in_function':True}]},
                       {'start':'0x10c','end_exclusive':'0x110','successors':[]}]}
        trace={'runs':[{'run_id':'loop','thread_id':1,'invocation_id':1,
                        'events':[{'type':'block','event_index':i+1,'start':{'module_offset':'0x100'}} for i in range(20)]}]}
        structure,plan=discover(instruction,cfg,trace)
        self.assertIsNone(structure['selected_candidate'])
        self.assertFalse(plan['probes'])

    def test_foreign_module_offset_is_not_counted(self):
        instruction={'instructions':[{'module_offset':'0x100','mnemonic':'ret','operands':''}]}
        cfg={'blocks':[{'start':'0x100','end_exclusive':'0x104','successors':[]}]}
        trace={'runs':[{'run_id':'r','thread_id':1,'invocation_id':1,'events':[
            {'type':'block','event_index':1,'start':{'binary_id':'other','module_offset':'0x100'}},
            {'type':'block','event_index':2,'start':{'binary_id':'target','module_offset':'0x101'}}]}]}
        structure,_=discover(instruction,cfg,trace,binary_id='target')
        self.assertEqual(structure['observed_graph']['nodes'][0]['visits'],1)

    def test_saved_model_proposal_rejects_unknown_reference(self):
        binary='a'*64
        request={'schema_version':1,'binary_id':binary,'evidence_refs':['insn:0x100'],
                 'scope':{'start':'0x100','end_exclusive':'0x200'}}
        proposal={'schema_version':1,'kind':'dispatcher_candidate','region':['0x100','0x120'],
                  'supporting_refs':['insn:0x999']}
        with self.assertRaises(ValueError):
            validate('model_proposal',{'request':request,'proposal':proposal,'adapter':'codex_exec'},binary)

    def test_model_selects_optional_rules_but_keeps_core(self):
        selected, requested = choose_model_rules({'checks_requested':['rule:side_effect']}, ('fanin',))
        self.assertEqual(requested,['side_effect'])
        self.assertIn('recurrence',selected)
        self.assertIn('side_effect',selected)
        self.assertNotIn('provenance',selected)
        with self.assertRaises(ValueError):
            choose_model_rules({'checks_requested':['rule:patch_everything']}, ())


if __name__ == '__main__': unittest.main()
