"""Conservative ARM64 state-transition inference for comparison-chain dispatchers."""
from collections import defaultdict
import re
from probe import digest


def const(n, width=32):
    return {'op': 'const', 'width': width, 'hex': '0x%0*x' % (width // 4, n & ((1 << width) - 1))}


def number(s):
    return int(s.strip().lstrip('#'), 0)


def parts(s):
    return [x.strip().lower() for x in re.split(r',\s*(?![^\[]*\])', s)]


def slot(s):
    m = re.fullmatch(r'\[(sp|x29)(?:,\s*#(0x[0-9a-f]+|\d+))?\]', s)
    return '%s+0x%x' % (m.group(1), int(m.group(2) or '0', 0)) if m else None


def canonical_slot(s):
    base, offset = s.split('+')
    # D2 offsets are hexadecimal even without a 0x prefix.
    return base + '+0x%x' % int(offset, 16)


def expr(op, a, b):
    return {'op': op, 'width': 1, 'args': [a, b]}


def inverse(guard):
    return {**guard, 'op': {'eq':'ne', 'ne':'eq', 'slt':'sge', 'sge':'slt', 'sgt':'sle', 'sle':'sgt', 'ult':'uge', 'uge':'ult', 'ugt':'ule', 'ule':'ugt'}[guard['op']]}


def proof_ready(ast):
    if not isinstance(ast, dict): return False
    op, width = ast.get('op'), ast.get('width')
    if width not in (1,8,16,32,64): return False
    if op == 'const':
        try: return 0 <= int(ast['hex'],16) < 1 << width
        except (KeyError, TypeError, ValueError): return False
    if op == 'reg': return isinstance(ast.get('name'),str) and re.fullmatch(r'[wx]\d+',ast['name']) is not None
    if op == 'load': return isinstance(ast.get('location'),str) and ast['location'] != ''
    arity = {'and': 2, 'eq': 2, 'ne': 2, 'slt': 2, 'sge': 2,
             'sgt': 2, 'sle': 2, 'ult': 2, 'uge': 2, 'ugt': 2, 'ule': 2}
    args = ast.get('args')
    if op not in arity or not isinstance(args,list) or len(args) != arity[op] or not all(proof_ready(x) for x in args):
        return False
    return args[0]['width'] == args[1]['width'] and width == (args[0]['width'] if op == 'and' else 1)


def router_matches(read, observed):
    try:
        value = read['value']
        return value['width'] == observed['width'] and int(value['hex'],16) == int(observed['hex'],16)
    except (KeyError, TypeError, ValueError):
        return False


def val(ast, inputs=None):
    if ast is None: return None
    op = ast['op']; width = ast['width']
    if op == 'const': return int(ast['hex'], 16)
    if op in ('load', 'reg'): return (inputs or {}).get(ast.get('location') or ast.get('name'))
    if op not in ('and','eq','ne','slt','sge','sgt','sle','ult','uge','ugt','ule'): return None
    args = [val(x, inputs) for x in ast.get('args', [])]
    if any(x is None for x in args): return None
    a, b = args
    if op == 'and': return a & b
    bits = ast['args'][0]['width']; sign = 1 << (bits - 1)
    signed = lambda x: x - (1 << bits) if x & sign else x
    return {'eq': lambda: a == b, 'ne': lambda: a != b,
            'slt': lambda: signed(a) < signed(b), 'sge': lambda: signed(a) >= signed(b),
            'sgt': lambda: signed(a) > signed(b), 'sle': lambda: signed(a) <= signed(b),
            'ult': lambda: a < b, 'uge': lambda: a >= b, 'ugt': lambda: a > b, 'ule': lambda: a <= b}[op]()


def guard_for(cond, flags):
    if not flags: raise ValueError('missing_flags')
    op = {'eq':'eq','ne':'ne','lt':'slt','ge':'sge','gt':'sgt','le':'sle',
          'lo':'ult','cc':'ult','hs':'uge','cs':'uge','hi':'ugt','ls':'ule'}.get(cond)
    if not op: raise ValueError('unsupported_condition:' + cond)
    return expr(op, *flags)


def execute(group, initial_mem=None):
    regs, mem, flags, last_input, write = {}, dict(initial_mem or {}), None, None, None
    def get(s):
        if s.startswith('#'): return const(number(s))
        if s in ('wzr', 'xzr'): return const(0, 64 if s == 'xzr' else 32)
        return regs.get(s, {'op':'reg', 'width':64 if s.startswith('x') else 32, 'name':s})
    def put(name, value):
        regs[name] = value
        if re.fullmatch(r'[wx]\d+',name):
            peer = ('x' if name.startswith('w') else 'w') + name[1:]
            width = 64 if peer.startswith('x') else 32
            regs[peer] = const(int(value['hex'],16),width) if value.get('op') == 'const' else {'op':'unknown','width':width}
    branch = None
    for ins in group:
        op = ins['mnemonic'].lower(); p = parts(ins['operands']); site = ins['module_offset']
        if op == 'mov': put(p[0],const(number(p[1]),64 if p[0].startswith('x') else 32) if p[1].startswith('#') else get(p[1]))
        elif op == 'movk':
            old = val(get(p[0])); shift = number(p[2].split()[-1]) if len(p) > 2 else 0
            if old is None: raise ValueError('movk_unknown_input:' + site)
            put(p[0],const((old & ~(0xffff << shift)) | (number(p[1]) << shift), get(p[0])['width']))
        elif op in ('ldr','ldur'):
            loc = slot(p[1]); width = 64 if p[0].startswith('x') else 32
            if loc is None: raise ValueError('unsupported_load:' + site)
            put(p[0],mem.get(loc, {'op':'load','width':width,'location':loc}))
        elif op in ('str','stur'):
            loc = slot(p[1])
            if loc is None: raise ValueError('unsupported_store:' + site)
            mem[loc] = get(p[0]); write = (loc, mem[loc], site)
        elif op in ('cmp','tst','subs'):
            aidx = 1 if op == 'subs' else 0
            a, b = get(p[aidx]), get(p[aidx+1]); last_input = (p[aidx], a)
            flags = ({'op':'and','width':a['width'],'args':[a,b]}, const(0,a['width'])) if op == 'tst' else (a,b)
            if op == 'subs': put(p[0],{'op':'unknown','width':a['width']})
        elif op == 'csel':
            g = guard_for(p[3], flags)
            put(p[0],{'op':'ite','width':get(p[1])['width'],'args':[g,get(p[1]),get(p[2])], '_input':last_input})
        elif op in ('add','sub','eor','asr','mvn','and','lsr','mul'):
            # Keep business arithmetic; its result cannot prove a state or guard.
            put(p[0],{'op':'unknown','width':64 if p[0].startswith('x') else 32})
        elif op == 'b': branch = (None, hex(int(p[0].split()[0].lstrip('#'), 16)))
        elif op.startswith('b.'):
            branch = (guard_for(op[2:], flags), hex(int(p[0].split()[0].lstrip('#'), 16)))
        else: raise ValueError('unsupported_instruction:%s:%s' % (site, op))
    return mem, write, branch


def infer_stack_slot(instructions, cfg, structure, observations, binary_id):
    candidate = next((c for c in structure.get('candidates', []) if c.get('hub') == structure.get('selected_candidate')), None)
    metadata = {'function': observations.get('function'), 'structure_id': observations.get('structure_id'), 'plan_id': observations.get('plan_id'), 'binary_id': binary_id,
                'strategy':observations.get('strategy','stack_slot_v1'),
                'input_hashes':{'instruction_table':digest(instructions),'static_cfg':digest(cfg),
                                'structure_candidates':digest(structure),'transition_observations':digest(observations)}}
    failures, result = [], []
    if not candidate:
        return ({**metadata,'rules':[]}, {**metadata,'unresolved':[{'reason':'no_selected_candidate'}]})
    blocks = {b['start']:b for b in cfg['blocks']}; ins = instructions['instructions']
    groups = {s:[i for i in ins if int(s,16) <= int(i['module_offset'],16) < int(b['end_exclusive'],16)] for s,b in blocks.items()}
    region = set(candidate['dispatcher_blocks']); state_slot = canonical_slot(candidate['state_slot'])
    records = defaultdict(list)
    for r in observations.get('records', []): records[(r.get('origin') or {}).get('source_block')].append(r)
    unsupported_sources = {x['source_block']:x['reason'] for x in observations.get('plan_unsupported', [])
                           if isinstance(x,dict) and x.get('reason') == 'state_write_count'}
    def target(state, start=None):
        mem = {state_slot:state}; node = start or candidate['hub']; seen = set(); refs = []; path = []
        while node in region:
            if node in seen or node not in blocks: raise ValueError('dispatcher_cycle_or_missing_block')
            seen.add(node); path.append(node); group = groups[node]; refs.extend('insn:'+i['module_offset'] for i in group)
            mem, _, branch = execute(group, mem)
            if not branch: raise ValueError('dispatcher_missing_branch')
            cond, dest = branch
            if cond is None: node = dest
            else:
                decision = val(cond)
                if decision is None: raise ValueError('dispatcher_unknown_condition')
                falls = [e['target'] for e in blocks[node]['successors'] if e['kind'] == 'fallthrough']
                if len(falls) != 1: raise ValueError('dispatcher_missing_fallthrough')
                node = dest if decision else falls[0]
        if node not in candidate.get('execution_entries', []): raise ValueError('dispatcher_unmatched_target')
        return node, refs, path + [node]
    entry = cfg['blocks'][0]['start'] if cfg['blocks'] else None
    sources = list(candidate['state_writers'])
    if entry and entry not in sources and entry not in region:
        sources.insert(0, entry)
    for source in sources:
        refs = ['insn:'+i['module_offset'] for i in groups.get(source, [])]; alts = []; reasons = []
        try:
            if source not in blocks: raise ValueError('missing_source_block')
            if source in unsupported_sources: raise ValueError('probe_plan_unsupported:' + unsupported_sources[source])
            _, write, branch = execute(groups[source])
            if not write or write[0] != state_slot: raise ValueError('missing_state_write')
            if source == entry and source not in candidate['state_writers']:
                exits = [e['target'] for e in blocks[source]['successors'] if e.get('in_function') and e['kind'] in ('branch', 'fallthrough')]
                if len(exits) != 1 or exits[0] not in region or (branch and branch != (None, exits[0])):
                    raise ValueError('unsupported_entry_exit')
                immediate = exits[0]
            else:
                if not branch or branch != (None, candidate['hub']): raise ValueError('unsupported_source_exit')
                immediate = candidate['hub']
            state = write[1]
            if state['op'] == 'ite':
                guard, yes, no = state['args']; options = [(guard, yes), (inverse(guard), no)]
                input_info = state.get('_input')
            else: options = [(const(1,1), state)]; input_info = None
            for guard, value in options:
                if not proof_ready(guard): raise ValueError('unsupported_guard_expression')
                if val(guard) is False: continue
                if value.get('op') != 'const': raise ValueError('nonconstant_state')
                dest, dispatch_refs, route_path = target(value, immediate)
                alts.append({'guard_ast':guard, 'state_ast':value, 'target_ast':None, 'target_block':dest,
                             'route_path':route_path,'observation_ids':[],
                             'instruction_refs':list(dict.fromkeys(refs+dispatch_refs)), 'status':'static_proven'})
            # Stalker can coalesce the entry fallthrough and its first CFG block.
            # Accept that block's fallthrough only when concrete state proves it,
            # the blocks are contiguous, and no intervening branch is taken.
            accepted_immediates = {immediate}
            if source == entry and len(options) == 1 and immediate in region:
                first = blocks[immediate]
                if int(blocks[source]['end_exclusive'], 16) == int(immediate, 16):
                    _, _, first_branch = execute(groups[immediate], {state_slot:options[0][1]})
                    fall = [e['target'] for e in first['successors'] if e['kind'] == 'fallthrough']
                    if (first_branch and first_branch[0] is not None and val(first_branch[0]) is False
                            and len(fall) == 1 and int(first['end_exclusive'],16) == int(fall[0],16)):
                        accepted_immediates.add(fall[0])
            for record in records[source]:
                quality = record.get('quality') or {}; transfer = record.get('transfer') or {}; route = record.get('route') or {}
                if not quality.get('complete') or quality.get('ambiguous') or not transfer.get('value') or not route.get('eventual_target'):
                    reasons.append({'reason':'incomplete_observation','observation_id':record.get('id')}); continue
                try:
                    observed_location = canonical_slot(transfer.get('location', ''))
                except (ValueError, AttributeError):
                    observed_location = None
                if (transfer.get('kind') != 'state_write' or transfer.get('site') != write[2]
                        or observed_location != state_slot or route.get('immediate_successor') not in accepted_immediates):
                    reasons.append({'reason':'observation_transfer_mismatch','observation_id':record.get('id')})
                    continue
                observed = transfer['value']; observed_int = int(observed['hex'],16)
                inputs = {}; decision = (record.get('decision') or {}).get('values') or {}
                if input_info and input_info[0] in decision:
                    key = input_info[1].get('location') or input_info[1].get('name')
                    if key: inputs[key] = int(decision[input_info[0]]['hex'],16)
                matching = [a for a in alts if val(a['guard_ast'], inputs) is True or (len(alts)==1)]
                if not matching:
                    reasons.append({'reason':'unverified_observation_guard','observation_id':record.get('id')}); continue
                a = matching[0]
                reads = route.get('dispatch_reads', [])
                router_mismatch = any(not router_matches(read, observed) for read in reads)
                if observed.get('width') != a['state_ast']['width'] or observed_int != val(a['state_ast']) or route['eventual_target'] != a['target_block'] or router_mismatch:
                    a['status'] = 'contradicted'; a['observation_ids'].append(record.get('id'))
                    reasons.append({'reason':'dispatcher_read_mismatch' if router_mismatch else 'observation_conflict','observation_id':record.get('id')})
                else:
                    a['observation_ids'].append(record.get('id'))
                    if a['status'] != 'contradicted': a['status'] = 'observed_and_static_proven'
        except (ValueError, KeyError, IndexError, TypeError) as error:
            alts = []; reasons.append({'reason':str(error)})
        for reason in reasons: failures.append({'source_block':source, **reason})
        result.append({'source_block':source,'transfer_kind':'state_write','state_location':state_slot,'alternatives':alts,
                       'coverage':{'normal_exits_static':len(alts),'alternatives_observed':sum(bool(a['observation_ids']) for a in alts),
                                   'guards_disjoint':True if alts else None,'guards_exhaustive':True if alts else None},
                       'evidence':refs,'unresolved':reasons})
    # A terminal execution entry is represented explicitly, without claiming a
    # concrete caller return address or that the return value is constant.
    for source in candidate.get('execution_entries', []):
        group = groups.get(source, [])
        if not group or group[-1]['mnemonic'].lower() != 'ret':
            continue
        refs = ['insn:' + i['module_offset'] for i in group]
        reasons = []
        try:
            if blocks[source].get('successors'):
                raise ValueError('return_has_successors')
            execute(group[:-1])
            alternatives = [{'guard_ast':const(1,1), 'state_ast':None, 'target_ast':None,
                             'target_block':None, 'observation_ids':[], 'instruction_refs':refs,
                             'status':'static_proven'}]
        except (ValueError, KeyError, IndexError, TypeError) as error:
            alternatives = []; reasons.append({'reason':str(error)})
        for reason in reasons: failures.append({'source_block':source, **reason})
        result.append({'source_block':source, 'transfer_kind':'return', 'state_location':None,'alternatives':alternatives,
                       'coverage':{'normal_exits_static':len(alternatives), 'alternatives_observed':0,
                                   'guards_disjoint':True if alternatives else None,
                                   'guards_exhaustive':True if alternatives else None},
                       'evidence':refs, 'unresolved':reasons})
    return ({**metadata,'rules':result}, {**metadata,'unresolved':failures})


INFERENCE_STRATEGIES = {'stack_slot_v1': infer_stack_slot}


def infer_rules(instructions, cfg, structure, observations, binary_id):
    strategy = observations.get('strategy','stack_slot_v1')
    if strategy not in INFERENCE_STRATEGIES:
        metadata = {'function':observations.get('function'),'structure_id':observations.get('structure_id'),
                    'plan_id':observations.get('plan_id'),'binary_id':binary_id,'strategy':strategy}
        return ({**metadata,'rules':[]},
                {**metadata,'unresolved':[{'reason':'unsupported_inference_strategy','strategy':strategy}]})
    return INFERENCE_STRATEGIES[strategy](instructions,cfg,structure,observations,binary_id)
