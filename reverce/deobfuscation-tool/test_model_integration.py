"""CLI boundary: deterministic results remain authoritative when model review is optional."""
import json
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cli import read, review_blocker
from model_diagnostics import build_diagnostic_request
from model_policy import classify_blocker


ROOT = Path(__file__).parent
FIXTURE = ROOT / 'tests/fixtures/lesson_score'
BINARY_ID = 'a' * 64


class ModelIntegrationTests(unittest.TestCase):
    def test_known_demo_skips_model(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            binary = FIXTURE / 'libflatten_fla_android.so'
            def run(*args):
                subprocess.run([sys.executable, str(ROOT / 'cli.py'), *map(str, args)],
                               check=True, capture_output=True, text=True)
            run('init', '--binary', binary, '--output', out)
            run('static', '--binary', binary, '--disasm', FIXTURE / 'lesson_score_trace_disasm.txt',
                '--function', 'lesson_score', '--output', out)
            run('import-legacy', '--binary', binary, '--log', FIXTURE / 'lesson_score_trace_raw.log', '--output', out)
            run('discover', '--output', out, '--model-policy', 'on_blocker', '--model-saved', out / 'missing.json')
            run('plan-probes', '--output', out, '--model-policy', 'on_blocker', '--model-saved', out / 'missing.json')
            self.assertFalse((out / 'model_diagnostic_reviews.json').exists())

    def test_replay_is_saved_once_without_promoting_rule(self):
        artifacts = {'unresolved_rules': {'unresolved': [{'source_block': '0x1000',
                                                         'reason': 'unsupported_instruction'}]},
                     'instruction_table': {'instructions': [{'module_offset': '0x1000',
                                                             'mnemonic': 'br', 'operands': 'x9'}]}}
        blocker = classify_blocker(4, artifacts)
        request = build_diagnostic_request(4, blocker, BINARY_ID, artifacts)
        proposal = {'schema_version': 1, 'stage': 4, 'binary_id': BINARY_ID,
                    'reason_code': request['reason_code'],
                    'findings': [{'explanation': 'Inspect the target register definition.',
                                  'evidence_refs': [request['evidence_refs'][0]]}],
                    'next_action': 'implement_strategy', 'rule_ids': [], 'probe_sites': []}
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            saved = out / 'saved.json'
            args = SimpleNamespace(model_policy='on_blocker', model_saved=str(saved), model_timeout=10)
            review_blocker(4, artifacts, out, BINARY_ID, args, {'model': {}})
            self.assertEqual(read(out, 'model_diagnostic_reviews', BINARY_ID)['data']['reviews'][0]['status'],
                             'model_failed')
            saved.write_text(json.dumps({'request': request, 'proposal': proposal}), encoding='utf-8')
            for _ in range(2): review_blocker(4, artifacts, out, BINARY_ID, args, {'model': {}})
            data = read(out, 'model_diagnostic_reviews', BINARY_ID)['data']
            self.assertEqual(len(data['reviews']), 1)
            self.assertEqual(data['reviews'][0]['status'], 'proposed')
            self.assertEqual(artifacts['unresolved_rules']['unresolved'][0]['reason'],
                             'unsupported_instruction')

    def test_invalid_d2_plan_does_not_trigger_d3_model(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            binary = FIXTURE / 'libflatten_fla_android.so'
            def run(*args):
                return subprocess.run([sys.executable, str(ROOT / 'cli.py'), *map(str, args)],
                                      capture_output=True, text=True)
            for args in [('init','--binary',binary,'--output',out),
                         ('static','--binary',binary,'--disasm',FIXTURE / 'lesson_score_trace_disasm.txt',
                          '--function','lesson_score','--output',out),
                         ('import-legacy','--binary',binary,'--log',FIXTURE / 'lesson_score_trace_raw.log',
                          '--output',out), ('discover','--output',out)]:
                self.assertEqual(run(*args).returncode, 0)
            path = out / 'structure_candidates.json'
            data = json.loads(path.read_text(encoding='utf-8'))
            data['data']['selected_candidate'] = None
            path.write_text(json.dumps(data), encoding='utf-8')
            result = run('plan-probes','--output',out,'--model-policy','on_blocker',
                         '--model-saved',out / 'missing.json')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('no selected structure candidate', result.stderr)
            self.assertFalse((out / 'model_diagnostic_reviews.json').exists())

    def test_diagnostic_artifact_errors_do_not_fail_stage(self):
        artifacts = {'unresolved_rules': {'unresolved': [{'reason': 'unsupported_instruction'}]}}
        args = SimpleNamespace(model_policy='on_blocker', model_saved='missing.json', model_timeout=10)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 'model_diagnostic_reviews.json').write_text('broken', encoding='utf-8')
            with redirect_stderr(io.StringIO()), patch('cli.read', side_effect=ValueError('broken previous review')):
                review_blocker(4, artifacts, out, BINARY_ID, args, {'model': {}})
            (out / 'model_diagnostic_reviews.json').unlink()
            with redirect_stderr(io.StringIO()), patch('cli.write', side_effect=OSError('disk error')):
                review_blocker(4, artifacts, out, BINARY_ID, args, {'model': {}})


if __name__ == '__main__':
    unittest.main()
