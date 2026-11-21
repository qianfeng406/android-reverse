"""Validate and group captured Frida JSONL by invocation."""
import json
import hashlib
from pathlib import Path

def normalize(path, binary_id, module):
    source = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    runs = {}; completed = set()
    for line_no, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        x = json.loads(line); kind = x.get('type')
        if kind == 'error': raise ValueError('collector error at line %d: %s' % (line_no, x.get('reason')))
        key = (x.get('run_id'), x.get('thread_id'), x.get('invocation_id'))
        if any(v is None for v in key): raise ValueError('missing invocation identity at line %d' % line_no)
        if kind == 'enter':
            if key in runs or x.get('module') != module or not isinstance(x.get('input'), int): raise ValueError('invalid enter at line %d' % line_no)
            runs[key] = {'run_id':key[0], 'thread_id':key[1], 'invocation_id':key[2], 'input':x['input'], 'return_value':None, 'events':[]}
        elif key not in runs or key in completed: raise ValueError('event outside invocation at line %d' % line_no)
        elif kind == 'leave':
            if not isinstance(x.get('return_value'), int): raise ValueError('missing return value at line %d' % line_no)
            runs[key]['return_value'] = x['return_value']; completed.add(key)
        elif kind in ('block','call','ret'):
            if x.get('event_index') != len(runs[key]['events'])+1 or not isinstance(x.get('raw'), list): raise ValueError('invalid event order at line %d' % line_no)
            for field in ('start','end','location','target'):
                addr = x.get(field)
                if addr and addr.get('module') == module:
                    addr['binary_id'] = binary_id
            x['evidence'] = ['sha256:%s:line:%d' % (source, line_no)]; runs[key]['events'].append(x)
        else: raise ValueError('unknown event at line %d' % line_no)
    if not runs or len(completed) != len(runs): raise ValueError('incomplete capture')
    return {'runs':list(runs.values()), 'missing_fields':[], 'source_sha256':source}
