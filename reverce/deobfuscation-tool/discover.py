"""D2 evidence rules for candidate flattened-control-flow regions."""
from collections import Counter, defaultdict
import re


DEFAULT_RULES = ('fanin', 'recurrence', 'routing', 'state_read', 'state_write', 'provenance', 'side_effect')
CORE_RULES = frozenset(('fanin', 'recurrence', 'routing', 'state_read', 'state_write'))
MEM = re.compile(r'\[\s*(sp|x29)(?:\s*,\s*#(0x[0-9a-f]+|\d+))?\s*\]', re.I)


def slots(instruction):
    return tuple('%s+%x' % (base.lower(), int(offset or '0', 0))
                 for base, offset in MEM.findall(instruction['operands']))


def choose_model_rules(proposal, current):
    requested = [x[5:] for x in proposal.get('checks_requested', []) if x.startswith('rule:')]
    unknown = set(requested) - set(DEFAULT_RULES)
    if unknown:
        raise ValueError('model selected unknown D2 rules: ' + ', '.join(sorted(unknown)))
    if not requested:
        return tuple(current), []
    return tuple(x for x in DEFAULT_RULES if x in CORE_RULES or x in requested), requested


def to_dot(structure):
    """Render observed order only; dashed arrows are not asserted CFG edges."""
    selected = next((x for x in structure['candidates'] if x['hub'] == structure['selected_candidate']), None)
    region = set(selected['dispatcher_blocks']) if selected else set()
    lines = ['digraph observed {', '  rankdir=LR;', '  node [shape=box];']
    for node in structure['observed_graph']['nodes']:
        start = node['start']
        color = 'lightblue' if start in region else 'white'
        lines.append('  "%s" [style=filled, fillcolor=%s, label="%s\\nvisits=%d"];' %
                     (start, color, start, node['visits']))
    for edge in structure['observed_graph']['observed_transitions']:
        lines.append('  "%s" -> "%s" [style=dashed, label="%d"];' %
                     (edge['source'], edge['target'], edge['count']))
    lines.append('}')
    return '\n'.join(lines) + '\n'


def discover_stack_comparison_chain(instructions, cfg, trace, enabled=DEFAULT_RULES, binary_id=None):
    enabled = tuple(enabled)
    unknown = set(enabled) - set(DEFAULT_RULES)
    if unknown:
        raise ValueError('unknown D2 rules: ' + ', '.join(sorted(unknown)))
    # A subset is allowed for exploration. Missing corroboration leaves the result unresolved.
    blocks = {b['start']: b for b in cfg['blocks']}
    ins = {b['start']: [x for x in instructions['instructions']
                         if int(b['start'], 16) <= int(x['module_offset'], 16) < int(b['end_exclusive'], 16)]
           for b in cfg['blocks']}
    predecessors = defaultdict(set)
    for b in cfg['blocks']:
        for edge in b['successors']:
            if edge['in_function'] and edge['kind'] in ('branch', 'fallthrough'):
                predecessors[edge['target']].add(b['start'])
    writes = defaultdict(set)
    reads = defaultdict(set)
    for start, group in ins.items():
        for x in group:
            op = x['mnemonic']
            for slot in slots(x):
                if op.startswith('str') or op.startswith('stur') or op.startswith('stp'):
                    writes[slot].add(start)
                elif op.startswith('ldr') or op.startswith('ldur'):
                    reads[slot].add(start)
    visits = Counter()
    observed = Counter()
    event_refs = defaultdict(list)
    visit_refs = defaultdict(list)
    ranges = [(int(b['start'],16), int(b['end_exclusive'],16), b['start']) for b in cfg['blocks']]
    for run in trace['runs']:
        last = None
        for event in run['events']:
            if event['type'] != 'block':
                last = None
                continue
            location = event.get('start') or {}
            if binary_id and location.get('binary_id') != binary_id:
                last = None
                continue
            offset = location.get('module_offset')
            if offset is None:
                last = None
                continue
            position = int(offset,16)
            address = next((name for lower,upper,name in ranges if lower <= position < upper), None)
            if address is None:
                last = None
                continue
            ref = 'trace:%s:%s:%s:%s' % (run['run_id'],run['thread_id'],run['invocation_id'],event['event_index'])
            visits[address] += 1
            visit_refs[address].append(ref)
            if last is not None:
                observed[(last, address)] += 1
                event_refs[(last,address)].append(ref)
            last = address
    # A common return point is a candidate, not a verdict: real loops can have high fan-in.
    hubs = sorted((x for x in blocks if 'fanin' in enabled and len(predecessors[x]) >= 2),
                  key=lambda x: (-len(predecessors[x]), -visits[x], int(x, 16)))
    candidates = []
    for hub in hubs:
        direct = predecessors[hub]
        # A state must be written by multiple blocks returning to this hub, then
        # read in the reachable routing region. Frequency alone is never enough.
        possible = sorted(writes, key=lambda s: (-len(writes[s] & direct), s))
        for slot in possible:
            writers = writes[slot] & direct
            if ('state_write' not in enabled or 'recurrence' not in enabled or len(writers) < 2
                    or visits[hub] <= len(trace['runs'])):
                continue
            region = set()
            pending = [hub]
            while pending:
                node = pending.pop()
                if node in region or node not in blocks or (node != hub and (node in writers or ins[node][-1]['mnemonic'] == 'ret')):
                    continue
                region.add(node)
                for edge in blocks[node]['successors']:
                    if edge['in_function'] and edge['kind'] in ('branch', 'fallthrough'):
                        pending.append(edge['target'])
            state_reads = reads[slot] & region
            routing = [x for x in region if sum(e['in_function'] is True for e in blocks[x]['successors']) >= 2]
            if 'state_read' not in enabled or 'routing' not in enabled or not state_reads or not routing:
                continue
            # Dispatcher may copy the state into a second slot before comparing.
            aliases = set()
            for node in region:
                group = ins[node]
                if node not in state_reads:
                    continue
                loaded = {x['operands'].split(',')[0].strip() for x in group
                          if x['mnemonic'].startswith(('ldr','ldur')) and slot in slots(x)}
                for other in writes:
                    if other != slot and node in writes[other] and reads[other] & region and any(
                            x['mnemonic'].startswith(('str','stur')) and other in slots(x)
                            and x['operands'].split(',')[0].strip() in loaded for x in group):
                        aliases.add(other)
            comparison_reads = {x for s in ({slot} | aliases) for x in reads[s] & region
                                if any(y['mnemonic'] in ('cmp', 'subs', 'tst') and any(
                                    re.search(r'\b'+re.escape(z['operands'].split(',')[0].strip())+r'\b', y['operands'])
                                    for z in ins[x] if z['mnemonic'].startswith(('ldr','ldur')) and s in slots(z))
                                       for y in ins[x])}
            if not comparison_reads:
                continue
            consumers = {e['target'] for node in region for e in blocks[node]['successors']
                         if e['in_function'] and e['target'] not in region}
            side_effects = [x['module_offset'] for node in sorted(region, key=lambda a: int(a, 16))
                            for x in ins[node] if x['mnemonic'] in ('bl', 'blr', 'svc') or
                            (x['mnemonic'].startswith(('str','stur','stp')) and
                             not any(s in slots(x) for s in ({slot} | aliases)))]
            evidence = ['block:' + hub] + visit_refs[hub][:3] + ['block:' + x for x in sorted(writers, key=lambda a: int(a, 16))]
            evidence += ['insn:' + x['module_offset'] for node in sorted(state_reads, key=lambda a: int(a, 16))
                         for x in ins[node] if x['mnemonic'].startswith(('ldr', 'ldur')) and slot in slots(x)]
            candidates.append({'hub': hub, 'state_slot': slot, 'state_aliases': sorted(aliases),
                               'dispatcher_blocks': sorted(region, key=lambda a: int(a, 16)),
                               'execution_entries': sorted(consumers, key=lambda a: int(a, 16)),
                               'state_writers': sorted(writers, key=lambda a: int(a, 16)),
                               'comparison_blocks': sorted(comparison_reads, key=lambda a: int(a, 16)),
                               'fan_in': len(direct), 'observed_visits': visits[hub],
                               'status': 'hypothesis', 'evidence': sorted(set(evidence)),
                               'rule_hits': ['fanin','routing','state_read','state_write']
                                            + (['recurrence'] if 'recurrence' in enabled and visits[hub] > len(trace['runs']) else [])
                                            + (['provenance'] if 'provenance' in enabled and comparison_reads else []),
                               'counterexamples': ['routing_side_effect:' + x for x in side_effects] if 'side_effect' in enabled else []})
    candidates.sort(key=lambda c: (-len(c['state_writers']), -len(c['comparison_blocks']),
                                   -c['fan_in'], int(c['hub'], 16)))
    selected = candidates[0] if candidates else None
    probes = []
    if selected:
        slot = selected['state_slot']
        for start in selected['state_writers']:
            group = ins[start]
            if not any(x['mnemonic'] in ('csel', 'csinc', 'csinv', 'csneg') for x in group):
                continue
            condition = [x for x in group if x['mnemonic'] in ('cmp', 'subs', 'tst')]
            store = [x for x in group if x['mnemonic'].startswith(('str', 'stur')) and slot in slots(x)]
            if condition and store:
                probes.append({'source_block': start, 'condition_at': condition[-1]['module_offset'],
                               'state_write_at': store[-1]['module_offset'], 'state_slot': slot,
                               'record': ['condition_operands', 'selected_state', 'immediate_successor', 'eventual_routed_target'],
                               'evidence': ['insn:' + condition[-1]['module_offset'],
                                            'insn:' + store[-1]['module_offset']]})
    graph = {'nodes': [{'start': x, 'visits': visits[x], 'static_in_degree': len(predecessors[x]),
                       'visit_evidence': visit_refs[x][:20]}
                       for x in sorted(blocks, key=lambda a: int(a, 16))],
             'observed_transitions': [{'source': a, 'target': b, 'count': n, 'direct_cfg_edge': None,
                                       'event_evidence': event_refs[(a,b)][:20]}
                                      for (a, b), n in sorted(observed.items())],
             'note': 'Adjacent observed target-module events are not asserted to be direct CFG edges.'}
    structure = {'rules_enabled': list(enabled), 'observed_graph': graph, 'candidates': candidates,
                 'selected_candidate': selected['hub'] if selected else None,
                 'unresolved': ['Alias/register links and complete side effects require D3–D5 verification.'] if selected else ['No region has corroborating observed recurrence, fan-in, routing, state read and returning state writers.']}
    plan = {'candidate_hub': selected['hub'] if selected else None, 'probes': probes,
            'unresolved': ['Pair eventual routed targets in D3; immediate successor alone is insufficient.'] if selected else ['No structure candidate; collect more runs or add a mechanism strategy.']}
    return structure, plan


DISCOVERY_STRATEGIES = {'stack_comparison_chain_v1': discover_stack_comparison_chain}


def discover(instructions, cfg, trace, enabled=DEFAULT_RULES, binary_id=None,
             strategy='stack_comparison_chain_v1'):
    if strategy not in DISCOVERY_STRATEGIES:
        raise ValueError('unsupported D2 discovery strategy: ' + strategy)
    structure, plan = DISCOVERY_STRATEGIES[strategy](instructions,cfg,trace,enabled,binary_id)
    if strategy != 'stack_comparison_chain_v1':
        structure['strategy'] = strategy
    return structure, plan
