import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from rule_review import CodexRuleReviewAdapter, ReplayRuleReviewAdapter, validate_review


class RuleReviewTests(unittest.TestCase):
    def setUp(self):
        self.request = {'source_block':'0x100','evidence_refs':['insn:0x104'],
                        'available_probe_sites':['0x104','0x108']}
        self.proposal = {'schema_version':1,'source_block':'0x100','disposition':'needs_check',
                         'findings':[{'reason':'check state alias','evidence_refs':['insn:0x104']}],
                         'suggested_probes':[{'site':'0x104','reason':'read state'}]}

    def test_replay_and_evidence_validation(self):
        with tempfile.TemporaryDirectory() as d:
            saved = Path(d)/'review.json'
            saved.write_text(json.dumps({'request':self.request,'proposal':self.proposal}))
            self.assertEqual(ReplayRuleReviewAdapter(saved).propose(self.request),self.proposal)
            bad = dict(self.proposal, findings=[{'reason':'unsupported','evidence_refs':['insn:0x108']}])
            with self.assertRaisesRegex(ValueError,'unknown evidence'): validate_review(self.request,bad)
            bad = dict(self.proposal, suggested_probes=[{'site':'0x10c','reason':'outside instruction table'}])
            with self.assertRaisesRegex(ValueError,'invalid probe'): validate_review(self.request,bad)

    def test_model_is_read_only_and_cannot_change_rules(self):
        def run(command, **kwargs):
            self.assertIn('read-only',command)
            self.assertIn('gpt-6-sol',command)
            self.assertIn('model_reasoning_effort="high"',command)
            self.assertEqual(json.loads(kwargs['input'].split('\n',1)[1]),self.request)
            Path(command[command.index('-o')+1]).write_text(json.dumps(self.proposal))
            return SimpleNamespace(returncode=0,stderr='')
        with tempfile.TemporaryDirectory() as d, patch('model_adapter.subprocess.run',side_effect=run):
            self.assertEqual(CodexRuleReviewAdapter({},d).propose(self.request),self.proposal)


if __name__ == '__main__': unittest.main()
