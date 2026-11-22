"""D0/D1 offline artifact exporter; Python 3.8+."""
import argparse
import hashlib
import json
import re
import sys
import tomli
from static_export import export
from normalize_capture import normalize
from model_adapter import ReplayAdapter
from model_adapter import CodexExecAdapter
from discover import discover, to_dot, choose_model_rules, DEFAULT_RULES
from probe import compile_plan, normalize_probe_capture, selected_structure_id, digest as artifact_digest
from infer import infer_rules
from rule_review import build_request as build_rule_review_request, ReplayRuleReviewAdapter, CodexRuleReviewAdapter
from validation import validate
from pathlib import Path

VERSION = 1

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def write(out, name, binary_id, data):
    if not re.fullmatch(r'[0-9a-f]{64}', binary_id): raise ValueError('invalid binary_id')
    validate(name, data, binary_id)
    out.mkdir(parents=True, exist_ok=True)
    (out / (name + '.json')).write_text(json.dumps({'schema_version': VERSION, 'kind': name, 'binary_id': binary_id, 'data': data}, indent=2) + '\n', encoding='utf-8')

def read(out, name, binary_id=None):
    path = out / (name + '.json')
    if not path.is_file(): raise ValueError('missing artifact: ' + str(path))
    obj = json.loads(path.read_text(encoding='utf-8'))
    if obj.get('schema_version') != VERSION or obj.get('kind') != name: raise ValueError('artifact version or kind mismatch: ' + str(path))
    if not re.fullmatch(r'[0-9a-f]{64}', obj.get('binary_id', '')): raise ValueError('invalid binary_id: ' + str(path))
    if binary_id and obj['binary_id'] != binary_id: raise ValueError('binary mismatch: ' + str(path))
    if 'data' not in obj: raise ValueError('missing data: ' + str(path))
    data = obj['data']
    if not isinstance(data, dict): raise ValueError('invalid artifact data: ' + str(path))
    fields = {'binary_manifest':['sha256','filename'], 'instruction_table':['function','instructions','source_sha256'], 'static_cfg':['function','blocks','source_sha256'], 'raw_trace':['runs','missing_fields'], 'structure_candidates':['rules_enabled','observed_graph','candidates','selected_candidate','unresolved'], 'probe_plan':['candidate_hub','probes','unresolved'], 'compiled_probe_plan':['function','structure_id','plan_id','binary_id','sources','probes'], 'transition_observations':['function','structure_id','plan_id','capture_ids','capture_source','records','router_observations','unpaired_events','diagnostics'], 'transition_rules':['function','structure_id','plan_id','rules'], 'unresolved_rules':['function','structure_id','plan_id','unresolved'], 'rule_reviews':['rules_hash','reviews'], 'model_proposal':['request','proposal','adapter']}
    if name not in fields: raise ValueError('unsupported artifact kind: ' + name)
    if any(field not in data for field in fields[name]): raise ValueError('missing required fields: ' + str(path))
    if name == 'binary_manifest' and data['sha256'] != obj['binary_id']: raise ValueError('manifest hash mismatch')
    if name in ('instruction_table','static_cfg','raw_trace'):
        key = {'instruction_table':'instructions','static_cfg':'blocks','raw_trace':'runs'}[name]
        if not isinstance(data[key], list) or not data[key]: raise ValueError('empty or invalid ' + key)
    if name == 'raw_trace':
        seen = set()
        for run in data['runs']:
            if not isinstance(run, dict) or any(k not in run for k in ('run_id','thread_id','invocation_id','input','return_value','events')): raise ValueError('invalid run')
            identity = (run['run_id'],run['thread_id'],run['invocation_id'])
            if identity in seen: raise ValueError('duplicate invocation')
            seen.add(identity)
            if not isinstance(run['events'], list) or any(event.get('event_index') != i for i,event in enumerate(run['events'],1)): raise ValueError('invalid event sequence')
    validate(name, data, obj['binary_id'])
    return obj

def legacy(path, binary_id):
    runs = {}
    source = digest(path)
    for line_no, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        m = re.match(r'^RUN (\d+): input=(-?\d+)$', line)
        b = re.match(r'^RUN (\d+) BLOCK (\d+): \+0x([\da-fA-F]+)', line)
        e = re.match(r'^END (\d+): input=(-?\d+) result=(-?\d+)$', line)
        if m:
            run, value = map(int, m.groups())
            if run in runs: raise ValueError('duplicate run at line %d' % line_no)
            runs[run] = {'run_id': run, 'input': value, 'return_value': None, 'thread_id': None, 'invocation_id': None, 'events': [], 'evidence': ['sha256:%s:line:%d' % (source, line_no)]}
        elif b:
            run, ordinal = map(int, b.group(1, 2))
            if run not in runs or runs[run]['return_value'] is not None or ordinal != len(runs[run]['events']) + 1: raise ValueError('invalid block order at line %d' % line_no)
            runs[run]['events'].append({'event_index': ordinal, 'type': 'block', 'start': {'binary_id': binary_id, 'module_offset': '0x%x' % int(b.group(3), 16)}, 'end': None, 'evidence': ['sha256:%s:line:%d' % (source, line_no)]})
        elif e:
            run, value, result = map(int, e.groups())
            if run not in runs or runs[run]['input'] != value or runs[run]['return_value'] is not None: raise ValueError('invalid end at line %d' % line_no)
            runs[run]['return_value'] = result
            runs[run]['evidence'].append('sha256:%s:line:%d' % (source, line_no))
    if not runs or any(x['return_value'] is None for x in runs.values()): raise ValueError('no complete runs')
    return {'source_sha256': source, 'missing_fields': ['thread_id', 'invocation_id', 'block_end', 'call_events', 'ret_events', 'out_of_function_events'], 'runs': list(runs.values())}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', default=str(Path(__file__).parent / 'config/default.toml'))
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('init'); a.add_argument('--binary', required=True); a.add_argument('--output', required=True)
    a = sub.add_parser('import-legacy'); a.add_argument('--binary', required=True); a.add_argument('--log', required=True); a.add_argument('--output', required=True)
    a = sub.add_parser('static'); a.add_argument('--binary', required=True); a.add_argument('--disasm', required=True); a.add_argument('--function', required=True); a.add_argument('--output', required=True)
    a = sub.add_parser('import-capture'); a.add_argument('--binary', required=True); a.add_argument('--module', required=True); a.add_argument('--capture', required=True); a.add_argument('--output', required=True); a.add_argument('--merge', action='store_true')
    a = sub.add_parser('replay'); a.add_argument('--request', required=True); a.add_argument('--saved', required=True); a.add_argument('--output', required=True)
    a = sub.add_parser('discover'); a.add_argument('--output', required=True); a.add_argument('--rules', default=','.join(DEFAULT_RULES)); a.add_argument('--strategy', default='stack_comparison_chain_v1'); a.add_argument('--use-model', action='store_true'); a.add_argument('--model-timeout', type=int, default=120)
    a = sub.add_parser('plan-probes'); a.add_argument('--output', required=True)
    a = sub.add_parser('import-probes'); a.add_argument('--capture', required=True); a.add_argument('--output', required=True)
    a = sub.add_parser('infer'); a.add_argument('--output', required=True)
    a = sub.add_parser('review-rules'); a.add_argument('--output', required=True); a.add_argument('--source', required=True); a.add_argument('--use-model', action='store_true'); a.add_argument('--saved'); a.add_argument('--model-timeout', type=int, default=120)
    a = sub.add_parser('stage'); a.add_argument('--output', required=True); a.add_argument('--from-stage', type=int, required=True)
    a = sub.add_parser('check'); a.add_argument('--output', required=True); a.add_argument('--artifact', required=True)
    args = p.parse_args(); out = Path(args.output)
    with open(args.config, 'rb') as f: config = tomli.load(f)
    if not isinstance(config.get('model'), dict): raise ValueError('config requires [model]')
    if args.command == 'init':
        bid = digest(args.binary); write(out, 'binary_manifest', bid, {'sha256': bid, 'filename': Path(args.binary).name})
    elif args.command == 'import-legacy':
        bid = digest(args.binary); read(out, 'binary_manifest', bid); write(out, 'raw_trace', bid, legacy(args.log, bid))
    elif args.command == 'static':
        bid = digest(args.binary); read(out, 'binary_manifest', bid)
        instructions, cfg = export(args.disasm, bid, args.function, args.binary)
        instructions['source_sha256'] = digest(args.disasm); cfg['source_sha256'] = digest(args.disasm)
        write(out, 'instruction_table', bid, instructions); write(out, 'static_cfg', bid, cfg)
    elif args.command == 'import-capture':
        bid = digest(args.binary); read(out, 'binary_manifest', bid)
        data = normalize(args.capture, bid, args.module)
        if args.merge:
            previous = read(out, 'raw_trace', bid)['data']
            keys = {(r['run_id'],r['thread_id'],r['invocation_id']) for r in previous['runs']}
            run_ids = {r['run_id'] for r in previous['runs']}
            if any(r['run_id'] in run_ids for r in data['runs']): raise ValueError('duplicate run_id during merge')
            data['source_sha256s'] = sorted(set(previous.get('source_sha256s', []) + ([previous['source_sha256']] if 'source_sha256' in previous else []) + [data['source_sha256']]))
            data['runs'] = previous['runs'] + data['runs']
            data['missing_fields'] = sorted(set(previous['missing_fields'] + data['missing_fields']))
        write(out, 'raw_trace', bid, data)
    elif args.command == 'replay':
        request = json.loads(Path(args.request).read_text(encoding='utf-8')); proposal = ReplayAdapter(args.saved).propose(request)
        write(out, 'model_proposal', request['binary_id'], {'request':request, 'proposal':proposal, 'adapter':'replay'})
    elif args.command == 'discover':
        manifest = read(out, 'binary_manifest'); bid = manifest['binary_id']
        instruction = read(out, 'instruction_table', bid)['data']
        cfg = read(out, 'static_cfg', bid)['data']
        trace = read(out, 'raw_trace', bid)['data']
        rules = tuple(x.strip() for x in args.rules.split(',') if x.strip())
        if instruction['function'] != cfg['function'] or instruction['source_sha256'] != cfg['source_sha256']:
            raise ValueError('static instruction/CFG source mismatch')
        structure, plan = discover(instruction, cfg, trace, rules, bid, args.strategy)
        if args.use_model:
            if config['model'].get('provider') != 'codex_exec':
                raise ValueError('--use-model requires model.provider=codex_exec')
            if args.model_timeout < 1:
                raise ValueError('--model-timeout must be positive')
            blocks = cfg['blocks']; selected = structure['candidates'][:3]
            focus = set()
            for candidate in selected:
                focus.add(candidate['hub'])
                focus.update(candidate['comparison_blocks'][:3])
                focus.update(candidate['state_writers'][:2])
            spans = [(int(b['start'],16),int(b['end_exclusive'],16)) for b in blocks if b['start'] in focus]
            slices = [{'address':i['module_offset'],'mnemonic':i['mnemonic'],'operands':i['operands']}
                      for i in instruction['instructions'] if any(a <= int(i['module_offset'],16) < z for a,z in spans)][:48]
            refs = sorted({ref for x in selected for ref in x['evidence']} | {'insn:'+i['address'] for i in slices})
            summaries = [{'hub':x['hub'], 'state_slot':x['state_slot'], 'fan_in':x['fan_in'],
                          'observed_visits':x['observed_visits'], 'comparison_blocks':x['comparison_blocks'][:5],
                          'state_writers':x['state_writers'][:5], 'counterexamples':x['counterexamples']}
                         for x in selected]
            request = {'schema_version':1, 'task':'structure_hypothesis', 'binary_id':bid,
                       'scope':{'start':blocks[0]['start'], 'end_exclusive':blocks[-1]['end_exclusive']},
                       'evidence_refs':refs,
                       'facts':{'candidates':summaries, 'instruction_slice':slices, 'rules_enabled':list(rules)}}
            proposal = CodexExecAdapter(config['model'], Path(__file__).parent, timeout=args.model_timeout).propose(request)
            rules, requested = choose_model_rules(proposal, rules)
            if requested:
                structure, plan = discover(instruction, cfg, trace, rules, bid, args.strategy)
                structure['model_rule_selection'] = requested
            write(out, 'model_proposal', bid, {'request':request,'proposal':proposal,'adapter':'codex_exec'})
        write(out, 'structure_candidates', bid, structure)
        write(out, 'probe_plan', bid, plan)
        (out / 'observed_graph.dot').write_text(to_dot(structure), encoding='utf-8')
    elif args.command == 'plan-probes':
        bid = read(out, 'binary_manifest')['binary_id']
        instruction = read(out, 'instruction_table', bid)['data']
        cfg = read(out, 'static_cfg', bid)['data']
        structure = read(out, 'structure_candidates', bid)['data']
        probes = read(out, 'probe_plan', bid)['data']
        plan = compile_plan(instruction, cfg, structure, probes, bid)
        write(out, 'compiled_probe_plan', bid, plan)
    elif args.command == 'import-probes':
        bid = read(out, 'binary_manifest')['binary_id']
        plan = read(out, 'compiled_probe_plan', bid)['data']
        structure = read(out, 'structure_candidates', bid)['data']
        cfg = read(out, 'static_cfg', bid)['data']
        observations = normalize_probe_capture(args.capture, bid, plan, structure, cfg)
        write(out, 'transition_observations', bid, observations)
    elif args.command == 'infer':
        bid = read(out, 'binary_manifest')['binary_id']
        instruction = read(out, 'instruction_table', bid)['data']
        cfg = read(out, 'static_cfg', bid)['data']
        structure = read(out, 'structure_candidates', bid)['data']
        observations = read(out, 'transition_observations', bid)['data']
        plan = read(out, 'compiled_probe_plan', bid)['data']
        if (observations['plan_id'] != plan['plan_id'] or observations['structure_id'] != plan['structure_id']
                or observations.get('strategy','stack_slot_v1') != plan.get('strategy','stack_slot_v1')):
            raise ValueError('D3 observation/plan mismatch')
        if plan['structure_id'] != selected_structure_id(structure, bid):
            raise ValueError('D3 plan/current D2 structure mismatch')
        rules, unresolved = infer_rules(instruction, cfg, structure, observations, bid)
        write(out, 'transition_rules', bid, rules)
        write(out, 'unresolved_rules', bid, unresolved)
    elif args.command == 'review-rules':
        bid = read(out, 'binary_manifest')['binary_id']
        rules = read(out, 'transition_rules', bid)['data']
        observations = read(out, 'transition_observations', bid)['data']
        instructions = read(out, 'instruction_table', bid)['data']
        source = next((x for x in rules['rules'] if x['source_block'] == args.source), None)
        if source is None: raise ValueError('unknown D4 rule source: ' + args.source)
        if args.use_model == bool(args.saved): raise ValueError('choose exactly one of --use-model or --saved')
        request = build_rule_review_request(source, instructions, observations, bid)
        if args.use_model:
            if config['model'].get('provider') != 'codex_exec' or args.model_timeout < 1:
                raise ValueError('review requires codex_exec and positive --model-timeout')
            proposal = CodexRuleReviewAdapter(config['model'], Path(__file__).parent, args.model_timeout).propose(request)
            adapter = 'codex_exec'
        else:
            proposal = ReplayRuleReviewAdapter(args.saved).propose(request)
            adapter = 'replay'
        identity = artifact_digest(rules)
        previous = read(out, 'rule_reviews', bid)['data'] if (out/'rule_reviews.json').is_file() else None
        reviews = [x for x in previous['reviews'] if x['request']['source_block'] != args.source] if previous and previous['rules_hash'] == identity else []
        reviews.append({'request':request,'proposal':proposal,'adapter':adapter})
        write(out, 'rule_reviews', bid, {'rules_hash':identity,'reviews':sorted(reviews,key=lambda x:int(x['request']['source_block'],16))})
    elif args.command == 'stage':
        if args.from_stage not in range(0, 7): raise ValueError('stage must be 0 through 6')
        required = {0:['binary_manifest'], 1:['binary_manifest','instruction_table','static_cfg','raw_trace'], 2:['structure_candidates','probe_plan'], 3:['compiled_probe_plan','transition_observations'], 4:['transition_rules','unresolved_rules'], 5:['patch_plan'], 6:['verification_report']}
        manifest = read(out, 'binary_manifest'); bid = manifest['binary_id']
        artifacts = {name:read(out, name, bid) for name in required[args.from_stage]}
        if args.from_stage == 2:
            if artifacts['structure_candidates']['data']['selected_candidate'] != artifacts['probe_plan']['data']['candidate_hub']:
                raise ValueError('D2 candidate/probe plan mismatch')
        if args.from_stage == 3:
            plan = artifacts['compiled_probe_plan']['data']
            observed = artifacts['transition_observations']['data']
            if any(plan[k] != observed[k] for k in ('plan_id', 'structure_id', 'function')):
                raise ValueError('D3 plan/observation mismatch')
            if plan.get('strategy','stack_slot_v1') != observed.get('strategy','stack_slot_v1'):
                raise ValueError('D3 strategy mismatch')
            structure = read(out, 'structure_candidates', bid)['data']
            if plan['structure_id'] != selected_structure_id(structure, bid):
                raise ValueError('D3 plan/current D2 structure mismatch')
        if args.from_stage == 4:
            rules = artifacts['transition_rules']['data']
            unresolved = artifacts['unresolved_rules']['data']
            if any(rules[k] != unresolved[k] for k in ('plan_id', 'structure_id', 'function')):
                raise ValueError('D4 rules/unresolved mismatch')
            observed = read(out, 'transition_observations', bid)['data']
            if any(rules[k] != observed[k] for k in ('plan_id', 'structure_id', 'function')):
                raise ValueError('D4 rules/observations mismatch')
            if rules.get('strategy','stack_slot_v1') != observed.get('strategy','stack_slot_v1'):
                raise ValueError('D4 strategy mismatch')
            if rules.get('input_hashes') != unresolved.get('input_hashes'):
                raise ValueError('D4 rules/unresolved input mismatch')
            if rules.get('input_hashes'):
                current = {name:artifact_digest(read(out, name, bid)['data']) for name in
                           ('instruction_table','static_cfg','structure_candidates','transition_observations')}
                if rules['input_hashes'] != current:
                    raise ValueError('D4 inputs changed since inference')
        print('stage %d inputs validated' % args.from_stage)
    else:
        print(json.dumps(read(out, args.artifact), indent=2))

if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print('error: %s' % exc, file=sys.stderr); sys.exit(1)
