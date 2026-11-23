"""Plan direct edges only where skipped effects and target live-ins are proven safe."""
import re
import hashlib
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from arm64_patch import encode_b, encode_b_cond
from static_export import build_cfg
from cleanup_analysis import analyze as analyze_cleanup
from infer import canonical_slot, execute, inverse, slot, parts, val
from probe import digest

INVERTED_CONDITIONS = {'eq':'ne','ne':'eq','cs':'cc','hs':'lo','cc':'cs','lo':'hs',
                       'mi':'pl','pl':'mi','vs':'vc','vc':'vs','hi':'ls','ls':'hi',
                       'ge':'lt','lt':'ge','gt':'le','le':'gt'}


def _reg(name):
    if re.fullmatch(r'[wx]\d+', name):
        return 'x' + name[1:]
    return name


def plan_patches(binary_path, instruction_table, cfg, structure, transition_rules,
                 unresolved_rules, binary_id):
    result = {'strategy': 'arm64_direct_edges_v1', 'function': transition_rules.get('function'),
              'binary_id': binary_id, 'plan_id': transition_rules.get('plan_id'),
              'input_hashes': {'instruction_table': digest(instruction_table), 'static_cfg': digest(cfg),
                               'structure_candidates': digest(structure), 'transition_rules': digest(transition_rules)},
              'entries': [], 'unresolved': list(unresolved_rules.get('unresolved', []))}
    rules = transition_rules.get('rules', [])
    counts = Counter(r.get('source_block') for r in rules)
    candidate = next((c for c in structure.get('candidates', []) if c.get('hub') == structure.get('selected_candidate')), None)
    blocks = {b['start']: b for b in cfg.get('blocks', [])}
    instructions = instruction_table.get('instructions', [])
    engine = Cs(CS_ARCH_ARM64, CS_MODE_ARM); engine.detail = True
    groups = {}
    decoded = {}
    invalid = None
    try:
        if hashlib.sha256(Path(binary_path).read_bytes()).hexdigest() != binary_id or transition_rules.get('binary_id') != binary_id:
            raise ValueError('binary_identity_mismatch')
        expected = transition_rules.get('input_hashes', {})
        for name, value in (('instruction_table', instruction_table), ('static_cfg', cfg), ('structure_candidates', structure)):
            if expected.get(name) != digest(value): raise ValueError('stale_input:' + name)
        with Path(binary_path).open('rb') as f:
            elf = ELFFile(f)
            segments = [(s['p_vaddr'], s.data()) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        for i in instructions:
            a = int(i['module_offset'], 16); raw = bytes.fromhex(i['bytes'])
            if a % 4 or len(raw) != 4 or a in decoded:
                raise ValueError('invalid_instruction_address_or_bytes')
            matches = [data[a-base:a-base+4] for base, data in segments if base <= a and a+4 <= base+len(data)]
            if len(matches) != 1 or matches[0] != raw:
                raise ValueError('instruction_bytes_mismatch:' + i['module_offset'])
            ds = list(engine.disasm(raw, a))
            if len(ds) != 1 or ds[0].mnemonic.lower() != i['mnemonic'].lower() or ds[0].op_str.lower().replace(' ', '') != i['operands'].lower().replace(' ', ''):
                raise ValueError('instruction_decode_mismatch:' + i['module_offset'])
            decoded[a] = ds[0]
        for start, b in blocks.items():
            lo, hi = int(start,16), int(b['end_exclusive'],16)
            if hi <= lo or lo % 4 or hi % 4 or any(a not in decoded for a in range(lo,hi,4)):
                raise ValueError('incomplete_block:' + start)
            groups[start] = [i for i in instructions if lo <= int(i['module_offset'],16) < hi]
            groups[start].sort(key=lambda i: int(i['module_offset'],16))
    except (ValueError, KeyError, OSError) as e:
        invalid = str(e)
    region = set(candidate.get('dispatcher_blocks', [])) if candidate else set()
    state = canonical_slot(candidate['state_slot']) if candidate and candidate.get('state_slot') else None

    def access(i):
        d = decoded[int(i['module_offset'],16)]
        reads, writes = d.regs_access()
        return ({_reg(d.reg_name(x)) for x in reads}, {_reg(d.reg_name(x)) for x in writes})

    def live_in(start, changed):
        # Follow every static successor, carrying values not yet overwritten.
        todo = [(start, frozenset(changed))]; seen = set()
        while todo:
            node, remaining = todo.pop()
            if not remaining or (node, remaining) in seen: continue
            seen.add((node, remaining))
            if node not in groups: raise ValueError('unknown_successor:' + str(node))
            alive = set(remaining)
            for i in groups[node]:
                op = i['mnemonic'].lower()
                if op in ('bl','blr','br','svc','hvc','smc','eret'):
                    raise ValueError('unknown_live_in_effect:' + i['module_offset'])
                reads, writes = access(i)
                if reads & alive: raise ValueError('live_in:' + i['module_offset'] + ':' + ','.join(sorted(reads & alive)))
                alive -= writes
                if op == 'ret':
                    if 'x0' in alive: raise ValueError('live_in_return:x0')
                    alive.clear(); break
            for edge in blocks[node].get('successors', []):
                if edge.get('in_function'): todo.append((edge['target'], frozenset(alive)))
                elif alive and edge.get('kind') not in ('return',): raise ValueError('unknown_successor_effect:' + node)

    for rule in rules:
        source = rule.get('source_block')
        try:
            if invalid: raise ValueError(invalid)
            if rule.get('transfer_kind') == 'return':
                if source not in groups or not groups[source] or groups[source][-1]['mnemonic'] != 'ret' or rule.get('unresolved'):
                    raise ValueError('invalid_return_rule')
                continue
            if not candidate or not state: raise ValueError('missing_dispatcher')
            if counts[source] != 1: raise ValueError('conflicting_source_rules')
            if any(x.get('source_block') == source for x in unresolved_rules.get('unresolved', [])): raise ValueError('source_has_unresolved_rule')
            if rule.get('unresolved'): raise ValueError('rule_unresolved')
            alts = rule.get('alternatives', [])
            if len(alts) not in (1,2) or any(a.get('status') not in ('static_proven','observed_and_static_proven') or not a.get('target_block') for a in alts):
                raise ValueError('unsupported_or_unproven_alternatives')
            cov = rule.get('coverage', {})
            if not cov.get('guards_disjoint') or not cov.get('guards_exhaustive'): raise ValueError('guards_not_complete')
            group = groups[source]
            _, write, branch = execute(group)
            if not write or write[0] != state: raise ValueError('state_write_not_proven')
            state_value = write[1]; site = int(write[2],16)
            entry = source == cfg['blocks'][0]['start']
            if len(alts) == 1:
                if state_value != alts[0]['state_ast']: raise ValueError('state_mismatch')
                if entry:
                    if group[-1]['module_offset'] != write[2]: raise ValueError('entry_template_mismatch')
                    specs = [(site, 'b', None, alts[0]['target_block'])]; kind = 'entry'
                else:
                    if not branch or branch != (None, candidate['hub']) or group[-1]['mnemonic'] != 'b': raise ValueError('single_template_mismatch')
                    specs = [(int(group[-1]['module_offset'],16), 'b', None, alts[0]['target_block'])]; kind = 'single'
            else:
                if entry or state_value.get('op') != 'ite' or len(group) < 3 or group[-2]['module_offset'] != write[2] or group[-1]['mnemonic'] != 'b' or branch != (None, candidate['hub']): raise ValueError('conditional_template_mismatch')
                csel = group[-3]
                if csel['mnemonic'] != 'csel': raise ValueError('conditional_csel_not_adjacent')
                condition = parts(csel['operands'])[-1]
                guard, yes, no = state_value['args']
                if [(a['guard_ast'], a['state_ast']) for a in alts] != [(guard,yes),(inverse(guard),no)]: raise ValueError('conditional_rule_mismatch')
                if int(alts[0]['target_block'], 16) == site + 8:
                    if condition not in INVERTED_CONDITIONS: raise ValueError('unsupported_conditional_inverse')
                    specs = [(int(csel['module_offset'], 16), 'b.cond', INVERTED_CONDITIONS[condition], alts[1]['target_block']),
                             (site, 'b', None, hex(site + 4)),
                             (site + 4, 'b', None, alts[0]['target_block'])]
                else:
                    specs = [(site, 'b.cond', condition, alts[0]['target_block']),
                             (site + 4, 'b', None, alts[1]['target_block'])]
                kind = 'conditional'
            skipped = set(); changed = set(); aliases = {}
            for alt in alts:
                path = alt.get('route_path', [])
                if not path or path[-1] != alt['target_block'] or any(n not in region for n in path[:-1]): raise ValueError('invalid_route_path')
                if path[0] not in [e['target'] for e in blocks[source].get('successors', []) if e.get('in_function')]: raise ValueError('route_start_mismatch')
                memory = {state: alt['state_ast']}
                for before, after in zip(path, path[1:]):
                    edges = blocks[before].get('successors', [])
                    if after not in [e['target'] for e in edges if e.get('in_function')]: raise ValueError('route_edge_mismatch')
                    memory, _, transfer = execute(groups[before], memory)
                    if not transfer: raise ValueError('route_transfer_missing')
                    guard, destination = transfer
                    if guard is None: expected_target = destination
                    else:
                        decision = val(guard)
                        if decision is None: raise ValueError('route_condition_unknown')
                        fallthrough = [e['target'] for e in edges if e.get('kind') == 'fallthrough' and e.get('in_function')]
                        if not decision and len(fallthrough) != 1: raise ValueError('route_fallthrough_unknown')
                        expected_target = destination if decision else fallthrough[0]
                    if after != expected_target: raise ValueError('route_state_mismatch')
                for node in path[:-1]:
                    skipped.add(node)
                    for i in groups[node]:
                        op = i['mnemonic'].lower(); p = parts(i['operands'])
                        if op not in ('mov','movk','ldr','ldur','str','stur','cmp','subs','tst','b') and not op.startswith('b.'):
                            raise ValueError('unsafe_dispatch_instruction:' + i['module_offset'])
                        if op in ('ldr','ldur','str','stur'):
                            loc = slot(p[1]) if len(p) > 1 else None
                            if not loc or not loc.startswith('sp+'): raise ValueError('unknown_dispatch_memory:' + i['module_offset'])
                            if op in ('str','stur'): aliases[loc] = max(aliases.get(loc, 0), 8 if p[0].startswith('x') else 4)
                        _, writes = access(i)
                        if 'sp' in writes: raise ValueError('dispatch_sp_write:' + i['module_offset'])
                        changed.update(writes)
            if kind in ('entry','conditional'):
                state_reg = parts(next(i for i in group if i['module_offset'] == write[2])['operands'])[0]
                aliases[state] = max(aliases.get(state, 0), 8 if state_reg.startswith('x') else 4)
            for i in instructions:
                op = i['mnemonic'].lower(); p = parts(i['operands'])
                if op in ('ldr','ldur','str','stur') and (len(p) < 2 or not slot(p[1]) or not slot(p[1]).startswith('sp+')):
                    raise ValueError('unproven_memory_alias:' + i['module_offset'])
                if re.search(r'\bsp\b', i['operands']) and '[' not in i['operands'] and not (op in ('add', 'sub') and len(p) == 3 and p[0] == 'sp' and p[1] == 'sp' and p[2].startswith('#')):
                    raise ValueError('stack_address_escape:' + i['module_offset'])
                if op in ('ldr','ldur','ldp'):
                    for operand in p[1:]:
                        loc = slot(operand)
                        width = 8 if p[0].startswith('x') else 4
                        overlaps = loc and any(loc.split('+')[0] == a.split('+')[0] and int(loc.split('+')[1],16) < int(a.split('+')[1],16)+aliases[a] and int(a.split('+')[1],16) < int(loc.split('+')[1],16)+width for a in aliases)
                        if overlaps and not any(int(n,16) <= int(i['module_offset'],16) < int(blocks[n]['end_exclusive'],16) for n in region):
                            raise ValueError('state_alias_read_outside_dispatcher:' + i['module_offset'])
                # Unrecognized addressing could alias a stack slot; do not assume otherwise.
                if '[' in i['operands'] and op not in ('ldr','ldur','str','stur'):
                    raise ValueError('unknown_memory_access:' + i['module_offset'])
            for alt in alts: live_in(alt['target_block'], changed)
            patches = []
            for addr, typ, cond, target in specs:
                if addr not in decoded: raise ValueError('patch_site_missing')
                new = encode_b(addr, int(target,16)) if typ == 'b' else encode_b_cond(addr,int(target,16),cond)
                patches.append({'site':hex(addr),'old_bytes':bytes(decoded[addr].bytes).hex(),'new_bytes':new,'kind':typ,'condition':cond,'target':target})
            result['entries'].append({'source_block':source,'kind':kind,'status':'ready','targets':[a['target_block'] for a in alts], 'patches':patches,
                                      'audit':{'passed':True,'checks':['decoded bytes match ELF','dispatcher effects and stack aliases checked','target live-in checked'], 'skipped_blocks':sorted(skipped,key=lambda x:int(x,16))},
                                      'evidence_refs':['insn:'+p['site'] for p in patches]})
        except (ValueError, KeyError, IndexError, TypeError) as e:
            result['unresolved'].append({'source_block':source,'reason':str(e)})
    sites = Counter(p['site'] for entry in result['entries'] for p in entry['patches'])
    conflicts = {s for s, count in sites.items() if count > 1}
    if conflicts:
        kept = []
        for entry in result['entries']:
            if any(p['site'] in conflicts for p in entry['patches']):
                result['unresolved'].append({'source_block':entry['source_block'], 'reason':'conflicting_patch_site'})
            else: kept.append(entry)
        result['entries'] = kept
    # Simulate the planned edges before considering cleanup. A branch to the
    # following instruction has exactly the same architectural effects as NOP.
    cleanup = {'version': 1, 'entries': [], 'unresolved': []}
    if not invalid and instructions and not result['unresolved']:
        replacements = {p['site']: p['new_bytes'] for e in result['entries'] for p in e['patches']}
        simulated = []
        for item in instructions:
            raw = bytes.fromhex(replacements.get(item['module_offset'], item['bytes']))
            d = next(engine.disasm(raw, int(item['module_offset'], 16)))
            simulated.append({'module_offset': hex(d.address), 'bytes': raw.hex(),
                              'mnemonic': d.mnemonic, 'operands': d.op_str})
        graph = build_cfg(simulated)
        blocks_by_start = {b['start']: b for b in graph}
        todo = [simulated[0]['module_offset']]; reachable = set(); unknown = False
        while todo:
            node = todo.pop()
            if node in reachable: continue
            if node not in blocks_by_start:
                unknown = True; continue
            reachable.add(node)
            for edge in blocks_by_start[node]['successors']:
                if edge['kind'] in ('indirect_unresolved', 'call_unresolved', 'call'):
                    unknown = True
                elif edge.get('in_function'): todo.append(edge['target'])
        if unknown:
            cleanup['unresolved'].append({'reason': 'unknown_reachable_control_flow'})
        else:
            # Fold a conditional fallthrough through a single-branch block only
            # when that block has exactly one reachable predecessor.
            incoming = {n: [] for n in reachable}
            for n in reachable:
                for e in blocks_by_start[n]['successors']:
                    if e.get('in_function') and e['target'] in incoming:
                        incoming[e['target']].append(n)
            by_addr = {int(i['module_offset'], 16): i for i in simulated}
            for n in sorted(reachable, key=lambda x:int(x,16)):
                block = blocks_by_start[n]; a = int(block['end_exclusive'],16)-4
                first = by_addr[a]; second = by_addr.get(a+4)
                cond = first['mnemonic'][2:] if first['mnemonic'].startswith('b.') else ''
                if (cond not in INVERTED_CONDITIONS or not second or second['mnemonic'] != 'b'
                    or int(first['operands'].lstrip('#'),0) != a+8
                    or hex(a+4) not in reachable or incoming.get(hex(a+4)) != [n]
                    or int(blocks_by_start[hex(a+4)]['end_exclusive'],16) != a+8): continue
                target = int(second['operands'].lstrip('#'),0)
                try:
                    encoded = encode_b_cond(a,target,INVERTED_CONDITIONS[cond])
                except ValueError as exc:
                    cleanup['unresolved'].append({'site':hex(a), 'reason':'trampoline_encode:'+str(exc)})
                    continue
                cleanup['entries'].append({'site':hex(a), 'old_bytes':first['bytes'],
                    'new_bytes':encoded, 'kind':'invert_cond',
                    'condition':INVERTED_CONDITIONS[cond], 'target':hex(target), 'paired_site':hex(a+4),
                    'reason':'conditional fallthrough is sole entry to one-instruction branch'})
                cleanup['entries'].append({'site':hex(a+4), 'old_bytes':second['bytes'],
                    'new_bytes':'1f2003d5', 'kind':'trampoline_nop', 'paired_site':hex(a),
                    'reason':'branch folded into preceding inverted condition'})
            proven, skipped = analyze_cleanup(simulated, state)
            cleanup['entries'].extend(proven)
            cleanup['unresolved'].extend(skipped)
            already = {p['site'] for p in cleanup['entries']}
            for item in simulated:
                a = int(item['module_offset'], 16)
                if not any(int(b['start'], 16) <= a < int(b['end_exclusive'], 16)
                           for b in graph if b['start'] in reachable): continue
                if item['module_offset'] not in already and item['mnemonic'] == 'b' and int(item['operands'].lstrip('#'), 0) == a + 4:
                    cleanup['entries'].append({'site': hex(a), 'old_bytes': item['bytes'],
                        'new_bytes': '1f2003d5', 'kind': 'nop',
                        'reason': 'reachable direct branch to next instruction has no effects'})
    else:
        cleanup['unresolved'].append({'reason': 'edge_plan_incomplete'})
    result['cleanup'] = cleanup
    return result
