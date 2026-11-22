import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from model_adapter import CodexExecAdapter, ReplayAdapter, validate_proposal


class ModelAdapterTests(unittest.TestCase):
    def setUp(self):
        self.request = {'schema_version': 1, 'scope': {'start': '0x100', 'end_exclusive': '0x200'}, 'evidence_refs': ['insn:0x100']}
        self.proposal = {'schema_version': 1, 'kind': 'dispatcher_candidate', 'region': ['0x100', '0x110'], 'state_location': 'sp+4', 'supporting_refs': ['insn:0x100'], 'checks_requested': ['find_writers']}

    def test_replay_and_reject_invalid_evidence_and_range(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'saved.json'
            path.write_text(json.dumps({'request': self.request, 'proposal': self.proposal}))
            self.assertEqual(ReplayAdapter(path).propose(self.request), self.proposal)
            for replacement in ({'supporting_refs': ['unknown']}, {'region': ['0x100', '0x201']}):
                with self.assertRaises(ValueError): validate_proposal(self.request, dict(self.proposal, **replacement))

    def test_codex_command_and_output(self):
        def run(command, **kwargs):
            self.assertIn('read-only', command)
            self.assertIn('gpt-6-sol', command)
            self.assertIn('model_reasoning_effort="high"', command)
            self.assertEqual(json.loads(kwargs['input'].split('\n', 1)[1]), self.request)
            Path(command[command.index('-o') + 1]).write_text(json.dumps(self.proposal))
            return SimpleNamespace(returncode=0, stderr='')
        with tempfile.TemporaryDirectory() as d, patch('model_adapter.subprocess.run', side_effect=run):
            self.assertEqual(CodexExecAdapter({}, d).propose(self.request), self.proposal)

    def test_codex_failure_is_explicit(self):
        with tempfile.TemporaryDirectory() as d, patch('model_adapter.subprocess.run', return_value=SimpleNamespace(returncode=1, stderr='failed')):
            with self.assertRaisesRegex(ValueError, 'codex exec failed'): CodexExecAdapter({}, d).propose(self.request)

if __name__ == '__main__': unittest.main()
