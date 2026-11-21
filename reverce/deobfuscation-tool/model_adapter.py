"""Proposal interface. Replay never contacts a model."""
from abc import ABC, abstractmethod
import json
from pathlib import Path

class ModelAdapter(ABC):
    @abstractmethod
    def propose(self, request):
        pass

class ReplayAdapter(ModelAdapter):
    def __init__(self, path): self.path = Path(path)
    def propose(self, request):
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        if request.get('schema_version') != 1 or not isinstance(request.get('evidence_refs'), list): raise ValueError('invalid model request')
        if saved.get('request') != request: raise ValueError('replay request mismatch')
        proposal = saved.get('proposal')
        if not isinstance(proposal, dict) or proposal.get('schema_version') != 1 or not isinstance(proposal.get('kind'), str) or not isinstance(proposal.get('supporting_refs'), list): raise ValueError('invalid replay proposal')
        if not set(proposal['supporting_refs']).issubset(request['evidence_refs']): raise ValueError('proposal references unknown evidence')
        return proposal
