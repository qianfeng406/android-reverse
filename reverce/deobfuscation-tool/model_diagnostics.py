"""Bounded, evidence-linked diagnostic proposals; never executable patches."""
import json
import re
from pathlib import Path
from discover import DEFAULT_RULES
from probe import digest
from model_adapter import run_codex_json
from model_policy import real_behavior_difference

ACTIONS = ('recollect', 'inspect', 'use_registered_rule', 'implement_strategy', 'review_patch')

def _bounded(value, depth=0):
    if depth >= 5: return str(value)[:160]
    if isinstance(value, dict): return {str(k)[:80]: _bounded(v, depth+1) for k,v in list(value.items())[:16]}
    if isinstance(value, list): return [_bounded(v, depth+1) for v in value[:8]]
    if isinstance(value, str): return value[:500]
    return value

def _address(value):
    try:
        if not isinstance(value, str) or not value.startswith('0x'): return None
        return int(value, 16)
    except ValueError: return None

def build_diagnostic_request(stage, blocker, binary_id, artifacts):
    if stage not in range(2, 7) or not isinstance(blocker, dict) or not isinstance(artifacts, dict):
        raise ValueError('invalid diagnostic input')
    ins = artifacts.get('instruction_table', {}).get('instructions', [])
    blocks = artifacts.get('static_cfg', {}).get('blocks', [])
    ins = [x for x in ins if isinstance(x, dict) and _address(x.get('module_offset')) is not None]
    blocks = [x for x in blocks if isinstance(x, dict) and _address(x.get('start')) is not None and _address(x.get('end_exclusive')) is not None]
    block_map = {b['start']: b for b in blocks}
    blocker_text = json.dumps(blocker, sort_keys=True)
    focus = {b for b in block_map if re.search(r'(?<![0-9a-fA-F])' + re.escape(b) + r'(?![0-9a-fA-F])', blocker_text)}
    # Include explicit unsupported sources as well as the selected blocker.
    if stage == 3:
        text = json.dumps(artifacts.get('compiled_probe_plan', {}).get('unsupported', []))
        focus.update(b for b in block_map if re.search(r'(?<![0-9a-fA-F])' + re.escape(b) + r'(?![0-9a-fA-F])', text))
    context = {}
    if stage == 2:
        structure = artifacts.get('structure_candidates', {})
        graph = structure.get('observed_graph', {})
        nodes = [n for n in graph.get('nodes', []) if isinstance(n, dict) and n.get('start') in block_map]
        edges = [e for e in graph.get('observed_transitions', []) if isinstance(e, dict) and e.get('source') in block_map and e.get('target') in block_map]
        indegree = {b: set() for b in block_map}
        for b in blocks:
            for edge in b.get('successors', []):
                if edge.get('in_function') and edge.get('target') in indegree: indegree[edge['target']].add(b['start'])
        nodes.sort(key=lambda n: (-len(indegree[n['start']]), -n.get('visits', 0)))
        ranked = nodes[:8]
        # Preserve both high-frequency and high-in-degree nodes.
        for node in sorted(nodes, key=lambda n: -n.get('visits', 0))[:4]:
            if node not in ranked: ranked.append(node)
        focus.update(n['start'] for n in ranked)
        context['observed_nodes'] = [_bounded(dict(n, static_in_degree=len(indegree[n['start']]))) for n in ranked]
        context['observed_edges'] = [_bounded(e) for e in sorted((e for e in edges if e['source'] in focus or e['target'] in focus), key=lambda e: -e.get('count', 0))[:24]]
        context['candidates'] = [_bounded(c) for c in structure.get('candidates', [])[:4]]
    if stage == 3: context['unsupported'] = _bounded(artifacts.get('compiled_probe_plan', {}).get('unsupported', []))
    if stage in (4, 5):
        for name, key in [('unresolved_rules','unresolved'), ('patch_plan','unresolved')]:
            if name in artifacts: context[name] = _bounded(artifacts[name].get(key, []))
    if stage == 6:
        behavior = artifacts.get('verification_report', {}).get('behavior', {})
        cases = behavior.get('cases', [])
        failed = [case for case in cases if real_behavior_difference(case)]
        context['behavior'] = _bounded({'status': behavior.get('status'),
                                        'cases': failed[:8] if failed else cases[:8]})
    def in_focus(row):
        address = _address(row.get('module_offset'))
        return any(_address(block_map[b]['start']) <= address < _address(block_map[b]['end_exclusive']) for b in focus)
    instructions = sorted(ins, key=lambda x: not in_focus(x))[:32]
    records = artifacts.get('transition_observations', {}).get('records', [])
    def relevant(record):
        return isinstance(record, dict) and (record.get('origin', {}).get('source_block') in focus or str(record.get('id', '')) in blocker_text)
    observations = sorted((r for r in records if isinstance(r, dict)), key=lambda r: not relevant(r))[:8]
    sites = list(dict.fromkeys(x['module_offset'] for x in instructions))
    refs = ['artifact:' + str(k) for k in sorted(artifacts)] + ['insn:' + s for s in sites]
    refs += ['block:' + b for b in sorted(focus) if any(_address(block_map[b]['start']) <= _address(i['module_offset']) < _address(block_map[b]['end_exclusive']) for i in ins)]
    refs += ['observation:' + str(x['id']) for x in observations if 'id' in x]
    return {'schema_version': 1, 'stage': stage, 'reason_code': blocker.get('reason_code', blocker.get('reason', 'unknown')),
            'binary_id': binary_id, 'source': _bounded(blocker), 'artifact_hashes': {str(k): digest(v) for k, v in artifacts.items()},
            'context': context, 'instructions': [_bounded(x) for x in instructions], 'observations': [_bounded(x) for x in observations], 'available_probe_sites': sites,
            'evidence_refs': list(dict.fromkeys(refs))}

SCHEMA = {'type':'object', 'additionalProperties':False,
 'required':['schema_version','stage','binary_id','reason_code','findings','next_action','rule_ids','probe_sites'],
 'properties':{'schema_version':{'type':'integer','enum':[1]}, 'stage':{'type':'integer'},
 'binary_id':{'type':'string'}, 'reason_code':{'type':'string'},
 'findings':{'type':'array','items':{'type':'object','additionalProperties':False,'required':['explanation','evidence_refs'],
 'properties':{'explanation':{'type':'string'},'evidence_refs':{'type':'array','minItems':1,'items':{'type':'string'}}}}},
 'next_action':{'type':'string','enum':list(ACTIONS)}, 'rule_ids':{'type':'array','items':{'type':'string'}},
 'probe_sites':{'type':'array','items':{'type':'string'}}}}

def validate_diagnostic(request, proposal):
    if not isinstance(proposal, dict) or set(proposal) != set(SCHEMA['required']): raise ValueError('invalid diagnostic schema')
    if proposal['schema_version'] != 1 or any(proposal[k] != request.get(k) for k in ('stage','binary_id','reason_code')): raise ValueError('diagnostic identity mismatch')
    if proposal['next_action'] not in ACTIONS: raise ValueError('invalid action')
    findings = proposal['findings']
    if not isinstance(findings, list) or not findings: raise ValueError('missing evidence')
    for f in findings:
        if (not isinstance(f, dict) or set(f) != {'explanation','evidence_refs'} or not isinstance(f['explanation'], str)
            or not f['explanation'].strip() or not isinstance(f['evidence_refs'], list) or not f['evidence_refs']
            or any(not isinstance(r, str) or r not in request['evidence_refs'] for r in f['evidence_refs'])): raise ValueError('invalid finding evidence')
    for key, allowed in [('rule_ids', DEFAULT_RULES), ('probe_sites', request['available_probe_sites'])]:
        if not isinstance(proposal[key], list) or any(not isinstance(x, str) or x not in allowed for x in proposal[key]): raise ValueError('invalid ' + key)
    return proposal

class ReplayDiagnosticAdapter:
    def __init__(self, saved): self.saved = saved
    def propose(self, request):
        saved = self.saved if isinstance(self.saved, dict) else json.loads(Path(self.saved).read_text(encoding='utf-8'))
        if saved.get('request') != request: raise ValueError('diagnostic replay request mismatch')
        return validate_diagnostic(request, saved.get('proposal'))

class CodexDiagnosticAdapter:
    def __init__(self, config, workdir, timeout=120): self.config, self.workdir, self.timeout = config, workdir, timeout
    def propose(self, request):
        prompt = ('Diagnose using only supplied evidence. Cite evidence for every finding. Suggest only listed probe sites and registered rules. Never provide code or patch bytes. Return JSON.\n' + json.dumps(request))
        return validate_diagnostic(request, run_codex_json(self.config, self.workdir, SCHEMA, prompt, self.timeout))
