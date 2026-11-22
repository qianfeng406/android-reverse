"""Read-only model proposals and deterministic replay."""
from abc import ABC, abstractmethod
import json
from pathlib import Path
import subprocess
import tempfile


class ModelAdapter(ABC):
    @abstractmethod
    def propose(self, request):
        pass


def validate_proposal(request, proposal):
    if request.get('schema_version') != 1 or not isinstance(request.get('evidence_refs'), list) or not all(isinstance(x, str) for x in request['evidence_refs']):
        raise ValueError('invalid model request')
    if not isinstance(proposal, dict) or proposal.get('schema_version') != 1 or not isinstance(proposal.get('kind'), str) or not isinstance(proposal.get('supporting_refs'), list) or not all(isinstance(x, str) for x in proposal['supporting_refs']):
        raise ValueError('invalid model proposal')
    if not set(proposal['supporting_refs']).issubset(request['evidence_refs']):
        raise ValueError('proposal references unknown evidence')
    region = proposal.get('region')
    if region is not None:
        if not isinstance(region, list) or len(region) != 2:
            raise ValueError('invalid proposal region')
        try:
            if any(not isinstance(x, str) or not x.startswith('0x') for x in region): raise ValueError()
            start, end = (int(x, 16) for x in region)
            scope = request.get('scope', {})
            lower, upper = int(scope['start'], 16), int(scope['end_exclusive'], 16)
            if not lower <= start < end <= upper: raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise ValueError('proposal region %r outside function scope %r or invalid scope' % (region, request.get('scope')))
    return proposal


class ReplayAdapter(ModelAdapter):
    def __init__(self, path): self.path = Path(path)
    def propose(self, request):
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        if saved.get('request') != request: raise ValueError('replay request mismatch')
        return validate_proposal(request, saved.get('proposal'))


def run_codex_json(config, workdir, schema, prompt, timeout=120, executable='codex'):
    with tempfile.TemporaryDirectory(prefix='model-proposal-') as directory:
        schema_path, output_path = Path(directory)/'schema.json', Path(directory)/'proposal.json'
        schema_path.write_text(json.dumps(schema), encoding='utf-8')
        command = [executable, 'exec', '-C', str(Path(workdir).resolve()), '-s', 'read-only',
                   '-m', config.get('name', 'gpt-6-sol'), '-c',
                   'model_reasoning_effort=' + json.dumps(config.get('reasoning_effort', 'high')),
                   '--output-schema', str(schema_path), '-o', str(output_path), '-']
        try:
            result = subprocess.run(command, input=prompt, text=True, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError('codex exec unavailable or timed out: %s' % exc) from exc
        if result.returncode != 0: raise ValueError('codex exec failed (exit %s): %s' % (result.returncode, result.stderr[-1000:]))
        try: return json.loads(output_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc: raise ValueError('codex exec produced no valid JSON proposal') from exc


class CodexExecAdapter(ModelAdapter):
    """Run a separate read-only Codex task. Returned proposals are hypotheses only."""
    def __init__(self, config, workdir, executable='codex', timeout=120):
        self.config, self.workdir, self.executable, self.timeout = config, Path(workdir), executable, timeout

    def propose(self, request):
        # The output schema is deliberately small; it does not permit commands or patches.
        schema = {'type': 'object', 'additionalProperties': False,
                  'required': ['schema_version', 'kind', 'region', 'state_location', 'supporting_refs', 'checks_requested'],
                  'properties': {'schema_version': {'type': 'integer', 'enum': [1]},
                      'kind': {'type': 'string'}, 'region': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 2, 'maxItems': 2},
                      'state_location': {'type': 'string'}, 'supporting_refs': {'type': 'array', 'items': {'type': 'string'}},
                      'checks_requested': {'type': 'array', 'items': {'type': 'string'}}}}
        prompt = ('Propose one cautious dispatcher hypothesis based only on this evidence. Never modify files. '
                  'Use only supplied evidence references. region must be a contiguous [start, end_exclusive] '
                  'hex interval inside scope, with start < end_exclusive; if a dispatcher wraps around the '
                  'function, choose only its hub block. In checks_requested, include any applicable rule IDs '
                  'as rule:fanin, rule:recurrence, rule:routing, rule:state_read, rule:state_write, '
                  'rule:provenance, or rule:side_effect; you may also include human-readable checks. '
                  'Return JSON matching the schema.\n' + json.dumps(request))
        proposal = run_codex_json(self.config,self.workdir,schema,prompt,self.timeout,self.executable)
        if set(proposal) != set(schema['required']) or not isinstance(proposal.get('state_location'), str) or not isinstance(proposal.get('checks_requested'), list) or not all(isinstance(x, str) for x in proposal['checks_requested']):
            raise ValueError('codex exec proposal does not match schema')
        return validate_proposal(request, proposal)
