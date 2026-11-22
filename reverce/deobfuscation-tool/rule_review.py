"""Optional, read-only model review of one inferred transition rule."""
import json
import re
from pathlib import Path
from model_adapter import run_codex_json
from probe import digest


def build_request(rule, instructions, observations, binary_id):
    refs = sorted({ref for alt in rule['alternatives'] for ref in alt['instruction_refs']}
                  | set(rule['evidence']))
    sites = {ref[5:] for ref in refs if ref.startswith('insn:')}
    rows = [row for row in instructions['instructions'] if row['module_offset'] in sites]
    ids = {item for alt in rule['alternatives'] for item in alt['observation_ids']}
    records = [record for record in observations['records'] if record['id'] in ids]
    distinct = {}
    for record in records:
        values = (record.get('decision') or {}).get('values') or {}
        key = json.dumps(values,sort_keys=True)
        distinct.setdefault(key,{'values':values,'count':0,'record':record})['count'] += 1
    samples = [item['record'] for item in list(distinct.values())[:8]]
    samples += [record for record in records if record not in samples][:8-len(samples)]
    evidence_refs = refs + ['observation:' + item for item in sorted(ids)]
    return {'schema_version':1,'task':'transition_rule_review','binary_id':binary_id,
            'source_block':rule['source_block'],'rule_hash':digest(rule),
            'rule':rule,'instructions':rows,'observation_count':len(records),
            'observation_samples':samples,'distinct_input_count':len(distinct),
            'observed_inputs':[{'values':x['values'],'count':x['count']} for x in list(distinct.values())[:24]],
            'evidence_refs':evidence_refs,
            'available_probe_sites':[row['module_offset'] for row in instructions['instructions']]}


def validate_review(request, proposal):
    if not isinstance(proposal,dict) or proposal.get('schema_version') != 1 or proposal.get('source_block') != request['source_block']:
        raise ValueError('invalid rule review identity')
    if proposal.get('disposition') not in ('no_issue','needs_check','conflict'):
        raise ValueError('invalid rule review disposition')
    findings = proposal.get('findings')
    probes = proposal.get('suggested_probes')
    if not isinstance(findings,list) or not isinstance(probes,list): raise ValueError('invalid rule review lists')
    available = set(request['evidence_refs'])
    sites = set(request['available_probe_sites'])
    for item in findings:
        if (not isinstance(item,dict) or not isinstance(item.get('reason'),str)
                or not isinstance(item.get('evidence_refs'),list)
                or not all(isinstance(ref,str) and ref in available for ref in item['evidence_refs'])):
            raise ValueError('rule review cites unknown evidence')
    for item in probes:
        if not isinstance(item,dict) or not isinstance(item.get('site'),str) or item['site'] not in sites or not isinstance(item.get('reason'),str):
            raise ValueError('rule review suggests invalid probe')
    return proposal


class ReplayRuleReviewAdapter:
    def __init__(self, path): self.path = Path(path)
    def propose(self, request):
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        if saved.get('request') != request: raise ValueError('rule review replay request mismatch')
        return validate_review(request, saved.get('proposal'))


class CodexRuleReviewAdapter:
    def __init__(self, config, workdir, timeout=120):
        self.config, self.workdir, self.timeout = config, workdir, timeout

    def propose(self, request):
        finding = {'type':'object','additionalProperties':False,'required':['reason','evidence_refs'],
                   'properties':{'reason':{'type':'string'},'evidence_refs':{'type':'array','items':{'type':'string'}}}}
        probe = {'type':'object','additionalProperties':False,'required':['site','reason'],
                 'properties':{'site':{'type':'string'},'reason':{'type':'string'}}}
        schema = {'type':'object','additionalProperties':False,
                  'required':['schema_version','source_block','disposition','findings','suggested_probes'],
                  'properties':{'schema_version':{'type':'integer','enum':[1]},'source_block':{'type':'string'},
                                'disposition':{'type':'string','enum':['no_issue','needs_check','conflict']},
                                'findings':{'type':'array','items':finding},'suggested_probes':{'type':'array','items':probe}}}
        prompt = ('Review this inferred transition rule as a hypothesis. Find missing semantics, conflicting '
                  'observations, and useful additional probe sites. Do not approve patches or change proof '
                  'status. Cite only evidence_refs from the request; probe sites must appear in available_probe_sites. '
                  'Return JSON matching the schema.\n' + json.dumps(request))
        proposal = run_codex_json(self.config,self.workdir,schema,prompt,self.timeout)
        return validate_review(request,proposal)
