import hashlib, json, re
from pathlib import Path

def digest(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def selected_structure_id(structure, binary_id):
    candidate = next((c for c in structure['candidates'] if c['hub'] == structure['selected_candidate']), None)
    if candidate is None: raise ValueError('D2 has no selected structure candidate')
    identity = {'binary_id':binary_id,'candidate':candidate,'rules_enabled':structure.get('rules_enabled')}
    if structure.get('strategy'): identity['strategy'] = structure['strategy']
    return digest(identity)

def slot(s):
    value = s.lower()
    memory = re.search(r'\[(sp|x29)(?:,\s*#?(0x[\da-f]+|\d+))?\]', value)
    if memory:
        return '%s+0x%x' % (memory.group(1), int(memory.group(2) or '0', 0))
    named = re.fullmatch(r'(sp|x29)\+(?:0x)?([\da-f]+)', value)
    return '%s+0x%x' % (named.group(1), int(named.group(2), 16)) if named else None


def plan_stack_slot(instructions, cfg, candidate, probe_plan):
    wanted = slot(candidate['state_slot'])
    if wanted is None: raise ValueError('unsupported D2 state location: ' + str(candidate['state_slot']))
    ins, blocks = instructions['instructions'], cfg['blocks']
    existing = {p['source_block']: p for p in probe_plan['probes']}
    sources, probes, unsupported = [], [], []
    entry = blocks[0]['start']
    for block in blocks:
        source = block['start']
        if source not in candidate['state_writers'] and source != entry: continue
        rows = [i for i in ins if int(source,16) <= int(i['module_offset'],16) < int(block['end_exclusive'],16)]
        writes = [i for i in rows if i['mnemonic'].lower() in ('str','stur') and slot(i['operands']) == wanted]
        if len(writes) != 1:
            unsupported.append({'source_block':source,'reason':'state_write_count','sites':[i['module_offset'] for i in writes]})
            continue
        w = writes[0]; reg = w['operands'].split(',')[0].strip().lower(); site = w['module_offset']
        cond = existing.get(source,{}).get('condition_at')
        src = {'source_block':source,'transfer_site':site,'location':wanted,'register':reg,
               'width':32 if reg.startswith('w') else 64,'decision_site':cond,
               'end_exclusive':block['end_exclusive'],'entry':source == entry}
        sources.append(src)
        probes.append({'site':site,'phase':'before','role':'state_write','source_block':source,
                       'registers':[reg],'location':wanted,'width':src['width']})
        if cond:
            row = next((i for i in rows if i['module_offset'] == cond), None)
            if row is None or int(cond,16) >= int(site,16): raise ValueError('invalid D2 decision site: ' + str(cond))
            regs = re.findall(r'\b[wx]\d+\b', row['operands'].lower())
            probes.append({'site':cond,'phase':'before','role':'decision','source_block':source,'registers':regs})
    for i in ins:
        if i['mnemonic'].lower() not in ('ldr','ldur') or slot(i['operands']) != wanted: continue
        if any(int(b['start'],16) <= int(i['module_offset'],16) < int(b['end_exclusive'],16)
               and b['start'] in candidate['dispatcher_blocks'] for b in blocks):
            width = 64 if i['operands'].strip().lower().startswith('x') else 32
            probes.append({'site':i['module_offset'],'phase':'before','role':'dispatcher_read',
                           'source_block':None,'registers':[],'location':wanted,'width':width})
            break
    else:
        unsupported.append({'source_block':candidate['hub'],'reason':'dispatcher_read_not_found','sites':[]})
    return sources, probes, unsupported


PROBE_PLANNERS = {'stack_slot_v1': plan_stack_slot}

def compile_plan(instructions, cfg, structure, probe_plan, binary_id):
    candidates = [c for c in structure['candidates'] if c['hub'] == structure['selected_candidate']]
    if not candidates: raise ValueError('D2 has no selected structure candidate')
    candidate = candidates[0]
    sid = selected_structure_id(structure, binary_id)
    strategy = 'stack_slot_v1'
    sources, probes, unsupported = PROBE_PLANNERS[strategy](instructions, cfg, candidate, probe_plan)
    if not sources: raise ValueError('D3 found no supported state writes: ' + str(unsupported))
    plan={'function':instructions.get('function'), 'binary_id':binary_id,'structure_id':sid,
          'strategy':strategy,'sources':sources,'probes':probes,'unsupported':unsupported}
    plan['plan_id']=digest(plan)
    return plan

def valid_value(v):
    if not isinstance(v, dict) or v.get('width') not in (8,16,32,64): return False
    h=v.get('hex')
    return isinstance(h,str) and bool(re.fullmatch(r'0x[0-9a-fA-F]{%d}' % (v['width']//4),h))

def normalize_probe_capture(path,binary_id,plan,structure,cfg):
    capture_path=Path(path); raw=capture_path.read_bytes()
    events=[json.loads(line) for line in raw.decode('utf-8').splitlines() if line.strip()]
    groups={}; unpaired=[]; diagnostics=[]; records=[]; router_observations=[]
    if plan.get('binary_id') != binary_id: raise ValueError('plan binary_id mismatch')
    if plan.get('structure_id') != selected_structure_id(structure, binary_id): raise ValueError('plan/D2 structure mismatch')
    if any(e.get('plan_id') != plan['plan_id'] for e in events): raise ValueError('capture plan_id missing or mismatched')
    for e in events:
        key=(e.get('run_id'),e.get('thread_id'),e.get('invocation_id'))
        if None in key: unpaired.append(e); continue
        groups.setdefault(key,[]).append(e)
    c=next(c for c in structure['candidates'] if c['hub']==structure['selected_candidate'])
    routing=set(c['dispatcher_blocks']); entries=set(c['execution_entries']); sources={s['source_block']:s for s in plan['sources']}
    for key, es in groups.items():
        indices=[e.get('event_index') for e in es]
        if any(not isinstance(i,int) for i in indices) or len(set(indices)) != len(indices): raise ValueError('missing or duplicate event_index')
        es.sort(key=lambda e:e['event_index']); gaps=indices and sorted(indices) != list(range(1,max(indices)+1))
        if gaps: diagnostics.append({'capture_id':list(key),'reason':'event_index_gap'})
        ended=any(e['type']=='leave' for e in es)
        boundaries=[e['type'] for e in es if e['type'] in ('enter','leave')]
        invalid_boundary=boundaries != ['enter','leave'] or es[0]['type'] != 'enter' or es[-1]['type'] != 'leave'
        errors=[e for e in es if e['type']=='error']
        if invalid_boundary: diagnostics.append({'capture_id':list(key),'reason':'invalid_invocation_boundary'})
        for e in errors: diagnostics.append({'capture_id':list(key),'reason':e.get('reason','capture_error'),'event_index':e['event_index']})
        blocks=[e for e in es if e['type']=='block']; counts={}
        for e in es:
            if e['type'] == 'probe' and not any(p['site']==e.get('site') and p['role']==e.get('role') and p['source_block']==e.get('source_block') for p in plan['probes']):
                raise ValueError('probe does not match plan')
        module=next((e.get('module') for e in es if e['type']=='enter'), None)
        first_target=True; paired_events=set()
        for n,b in enumerate(blocks):
            addr=b.get('start',{}); source=addr.get('module_offset')
            if addr.get('binary_id',binary_id)!=binary_id or (module and addr.get('module')!=module): continue
            if source not in sources and first_target and source is not None:
                source=next((x['source_block'] for x in plan['sources'] if x.get('entry') and int(x['source_block'],16)<=int(source,16)<int(x['end_exclusive'],16)),source)
            first_target=False
            if source not in sources: continue
            s=sources[source]; counts[source]=counts.get(source,0)+1; ordinal=counts[source]
            next_index=blocks[n+1]['event_index'] if n+1 < len(blocks) else es[-1]['event_index']
            found=[e for e in es if e['type']=='probe' and e.get('source_block')==source
                   and e.get('source_ordinal')==ordinal and b['event_index'] < e['event_index'] < next_index]
            paired_events.update(e['event_index'] for e in found)
            def ref(e): return '%s:%s:%s:%s:%s' % (e['type'],*key,e.get('event_index'))
            def one(role): return [e for e in found if e.get('role')==role]
            w=one('state_write'); d=one('decision'); missing=[]
            if len(w)!=1: missing.append('state_write_probe')
            if s['decision_site'] and len(d)!=1: missing.append('decision_probe')
            if s['decision_site'] and len(d)==1:
                spec=next(p for p in plan['probes'] if p['role']=='decision' and p['site']==s['decision_site'])
                if any(r not in d[0].get('values',{}) for r in spec['registers']): missing.append('decision_values')
            if gaps: missing.append('event_index_gap')
            if invalid_boundary: missing.append('invalid_invocation_boundary')
            if errors: missing.append('capture_error')
            if not ended: missing.append('invocation_end')
            if not any(e['type']=='enter' for e in es): missing.append('invocation_start')
            value=w[0].get('values',{}).get(s['register']) if len(w)==1 else None
            if not valid_value(value) and 'state_write_probe' not in missing: missing.append('state_write_value')
            if s['decision_site'] and len(d)==1 and any(not valid_value(v) for v in d[0].get('values',{}).values()): missing.append('invalid_decision_value')
            path=[]; target=None; status='unresolved'; immediate=None
            for nxt in blocks[n+1:]:
                a=nxt.get('start',{}); off=a.get('module_offset')
                if immediate is None: immediate=off
                if a.get('binary_id',binary_id)!=binary_id or (module and a.get('module')!=module): status='foreign_module'; break
                if off in routing: path.append(ref(nxt)); continue
                if off in entries: target=off; status='observed_candidate_boundary'
                break
            dispatch_reads=[]
            if target is not None:
                target_index=nxt.get('event_index', 0)
                if any(e['type'] in ('call','error') and b.get('event_index',0) < e.get('event_index',0) < target_index for e in es):
                    target=None; status='unresolved'; missing.append('unsupported_call_or_error')
                else:
                    dispatch_reads=[{'event_ref':ref(e),'site':e['site'],'value':e.get('values',{}).get(s['location'])}
                                    for e in es if e['type']=='probe' and e.get('role')=='dispatcher_read'
                                    and (w[0]['event_index'] if len(w)==1 else b['event_index']) < e['event_index'] < target_index]
            if target is None: missing.append('eventual_target')
            ambiguous=len(w)>1 or len(d)>1
            decision={'site':s['decision_site'],'phase':'before','values':d[0].get('values',{}) if len(d)==1 else {}} if s['decision_site'] else None
            records.append({'id':'%s/%s/%s/%s/%s'%(*key,source,ordinal),'origin':{'source_block':source,'source_ordinal':ordinal,'block_event_ref':ref(b)},'decision':decision,'transfer':{'kind':'state_write','site':s['transfer_site'],'location':s['location'],'value':value},'route':{'immediate_successor':immediate,'eventual_target':target,'path_refs':path,'target_status':status,'dispatch_reads':dispatch_reads},'quality':{'complete':not missing and not ambiguous,'missing':missing,'ambiguous':ambiguous},'evidence':[ref(b)]+[ref(e) for e in found]+['insn:'+s['transfer_site']]})
        router_observations.extend(e for e in es if e['type']=='probe' and e.get('role')=='dispatcher_read')
        unpaired.extend(e for e in es if e['type']=='probe' and e.get('role') != 'dispatcher_read' and e['event_index'] not in paired_events)
    return {'function':plan['function'],'structure_id':plan['structure_id'],'plan_id':plan['plan_id'],
            'strategy':plan.get('strategy','stack_slot_v1'),'capture_ids':[list(k) for k in groups],
            'capture_source':{'path':str(capture_path),'sha256':hashlib.sha256(raw).hexdigest()},
            'records':records,'router_observations':router_observations,'unpaired_events':unpaired,
            'diagnostics':diagnostics,'plan_unsupported':plan['unsupported']}
