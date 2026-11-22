"""Exercise the saved-artifact D2 -> D3 -> D4 command boundary."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent
FIXTURE = ROOT / 'tests/fixtures/lesson_score'


class PipelineD3D4Tests(unittest.TestCase):
    def test_probe_capture_to_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)

            def run(*args):
                subprocess.run([sys.executable, str(ROOT / 'cli.py'), *map(str, args)],
                               check=True, capture_output=True, text=True)

            def data(name):
                return json.loads((output / (name + '.json')).read_text())['data']

            binary = FIXTURE / 'libflatten_fla_android.so'
            run('init', '--binary', binary, '--output', output)
            run('static', '--binary', binary, '--disasm',
                FIXTURE / 'lesson_score_trace_disasm.txt', '--function', 'lesson_score',
                '--output', output)
            run('import-legacy', '--binary', binary, '--log',
                FIXTURE / 'lesson_score_trace_raw.log', '--output', output)
            run('discover', '--output', output)
            run('plan-probes', '--output', output)
            plan = data('compiled_probe_plan')
            source = next(x for x in plan['sources'] if x['source_block'] == '0x17e0')
            identity = {'run_id': 'fixture', 'thread_id': 1, 'invocation_id': 1,
                        'plan_id': plan['plan_id']}
            events = [
                {'type': 'enter', 'module': 'target'},
                {'type': 'block', 'start': {'module': 'target', 'module_offset': '0x17e0'}},
                {'type': 'probe', 'site': source['decision_site'], 'role': 'decision',
                 'source_block': '0x17e0', 'source_ordinal': 1,
                 'values': {'w8': {'width': 32, 'hex': '0x00000002'}}},
                {'type': 'probe', 'site': source['transfer_site'], 'role': 'state_write',
                 'source_block': '0x17e0', 'source_ordinal': 1,
                 'values': {'w8': {'width': 32, 'hex': '0x81fc94e6'}}},
                {'type': 'block', 'start': {'module': 'target', 'module_offset': '0x18f8'}},
                {'type': 'block', 'start': {'module': 'target', 'module_offset': '0x1620'}},
                {'type': 'block', 'start': {'module': 'target', 'module_offset': '0x1804'}},
                {'type': 'leave'},
            ]
            capture = output / 'capture.jsonl'
            capture.write_text(''.join(json.dumps({**identity, **event, 'event_index': index}) + '\n'
                                       for index, event in enumerate(events, 1)))
            run('import-probes', '--capture', capture, '--output', output)
            run('stage', '--output', output, '--from-stage', 3)
            run('infer', '--output', output)
            run('stage', '--output', output, '--from-stage', 4)
            observations = data('transition_observations')
            rules = data('transition_rules')['rules']
            observed_source = next(x for x in observations['records']
                                   if x['origin']['source_block'] == '0x17e0')
            self.assertTrue(observed_source['quality']['complete'])
            self.assertEqual(observations['capture_source']['sha256'],
                             hashlib.sha256(capture.read_bytes()).hexdigest())
            source_rule = next(x for x in rules if x['source_block'] == '0x17e0')
            self.assertEqual({(x['target_block'], x['status']) for x in source_rule['alternatives']},
                             {('0x1804', 'observed_and_static_proven'),
                              ('0x182c', 'static_proven')})


if __name__ == '__main__':
    unittest.main()
