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
    fields = {'binary_manifest':['sha256','filename'], 'instruction_table':['function','instructions','source_sha256'], 'static_cfg':['function','blocks','source_sha256'], 'raw_trace':['runs','missing_fields'], 'model_proposal':['request','proposal','adapter']}
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
    elif args.command == 'stage':
        if args.from_stage not in range(0, 7): raise ValueError('stage must be 0 through 6')
        required = {0:['binary_manifest'], 1:['binary_manifest','instruction_table','static_cfg','raw_trace'], 2:['structure_candidates','probe_plan'], 3:['transition_observations'], 4:['transition_rules'], 5:['patch_plan'], 6:['verification_report']}
        manifest = read(out, 'binary_manifest'); bid = manifest['binary_id']
        for name in required[args.from_stage]: read(out, name, bid)
        print('stage %d inputs validated; subsequent stages are not implemented' % args.from_stage)
    else:
        print(json.dumps(read(out, args.artifact), indent=2))

if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print('error: %s' % exc, file=sys.stderr); sys.exit(1)
