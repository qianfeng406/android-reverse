"""Structural checks for version 1 artifacts."""
import re

def validate(kind, data, binary_id):
    def require(ok, message):
        if not ok: raise ValueError('invalid %s: %s' % (kind, message))
    def offset(value): return isinstance(value, str) and re.fullmatch(r'0x[0-9a-f]+', value) is not None
    def refs(value): return isinstance(value, list) and bool(value) and all(isinstance(x,str) and x for x in value)
    require(isinstance(data, dict), 'data')
    if kind == 'binary_manifest':
        require(data.get('sha256') == binary_id and isinstance(data.get('filename'),str) and bool(data['filename']), 'manifest')
    elif kind == 'instruction_table':
        items=data.get('instructions'); require(isinstance(data.get('function'),str) and isinstance(items,list) and bool(items), 'instructions')
        previous = -1
        for x in items:
            require(isinstance(x,dict) and offset(x.get('module_offset')) and isinstance(x.get('mnemonic'),str) and isinstance(x.get('operands'),str) and re.fullmatch(r'[0-9a-f]{8}',x.get('bytes','')) is not None and refs(x.get('evidence')), 'instruction')
            address=int(x['module_offset'],16); require(address > previous and address % 4 == 0, 'instruction order/alignment'); previous=address
    elif kind == 'static_cfg':
        blocks=data.get('blocks'); require(isinstance(data.get('function'),str) and isinstance(blocks,list) and bool(blocks), 'blocks')
        starts=set(); previous=-1
        for b in blocks:
            require(isinstance(b,dict) and offset(b.get('start')) and offset(b.get('end_exclusive')) and isinstance(b.get('successors'),list) and refs(b.get('evidence')), 'block')
            start=int(b['start'],16); end=int(b['end_exclusive'],16); require(start > previous and start % 4 == 0 and end > start and end % 4 == 0, 'block bounds/order'); previous=start; starts.add(b['start'])
        for b in blocks:
            for edge in b['successors']:
                require(isinstance(edge,dict) and edge.get('kind') in ('branch','fallthrough','indirect_unresolved','call','call_unresolved','call_return') and (edge.get('target') is None or offset(edge['target'])) and edge.get('in_function') in (True,False,None), 'edge')
                if edge.get('in_function') is True: require(edge['target'] in starts, 'edge target is not a leader')
    elif kind == 'raw_trace':
        runs=data.get('runs'); require(isinstance(runs,list) and bool(runs) and isinstance(data.get('missing_fields'),list), 'runs')
        seen=set()
        for r in runs:
            require(isinstance(r,dict) and all(k in r for k in ('run_id','thread_id','invocation_id','input','return_value','events')) and isinstance(r['input'],int) and isinstance(r['return_value'],int) and isinstance(r['events'],list), 'run')
            key=(r['run_id'],r['thread_id'],r['invocation_id']); require(key not in seen, 'duplicate invocation'); seen.add(key)
            for i,e in enumerate(r['events'],1):
                require(isinstance(e,dict) and e.get('event_index') == i and e.get('type') in ('block','call','ret') and refs(e.get('evidence')), 'event')
                for field in ('start','end','location','target'):
                    addr=e.get(field)
                    if addr is None: continue
                    require(isinstance(addr,dict), 'address')
                    if 'module_offset' in addr:
                        require(offset(addr['module_offset']), 'module offset')
                        if 'binary_id' in addr: require(addr['binary_id'] == binary_id, 'address binary')
                        else: require(isinstance(addr.get('module'),str), 'address module')
                    else: require(offset(addr.get('absolute')), 'absolute address')
    elif kind == 'structure_candidates':
        require(isinstance(data.get('rules_enabled'),list) and isinstance(data.get('observed_graph'),dict) and isinstance(data.get('candidates'),list) and isinstance(data.get('unresolved'),list), 'structure')
        require(isinstance(data['observed_graph'].get('nodes'),list) and isinstance(data['observed_graph'].get('observed_transitions'),list), 'graph')
        nodes={x.get('start') for x in data['observed_graph']['nodes'] if isinstance(x,dict)}
        require(all(offset(x) for x in nodes), 'graph nodes')
        for edge in data['observed_graph']['observed_transitions']:
            require(isinstance(edge,dict) and edge.get('source') in nodes and edge.get('target') in nodes
                    and isinstance(edge.get('count'),int) and edge['count'] > 0 and edge.get('direct_cfg_edge') is None
                    and isinstance(edge.get('event_evidence'),list), 'observed edge')
        for candidate in data['candidates']:
            require(isinstance(candidate,dict) and candidate.get('hub') in nodes and candidate.get('status') == 'hypothesis'
                    and isinstance(candidate.get('state_slot'),str) and isinstance(candidate.get('dispatcher_blocks'),list)
                    and refs(candidate.get('evidence')) and isinstance(candidate.get('state_writers'),list), 'candidate')
            require(all(x in nodes for x in candidate['dispatcher_blocks']+candidate['state_writers']), 'candidate blocks')
        require(data.get('selected_candidate') is None or data['selected_candidate'] in {x['hub'] for x in data['candidates']}, 'selection')
    elif kind == 'probe_plan':
        require(data.get('candidate_hub') is None or offset(data['candidate_hub']), 'candidate hub')
        require(isinstance(data.get('probes'),list) and isinstance(data.get('unresolved'),list), 'probes')
        for probe in data['probes']:
            require(isinstance(probe,dict) and all(offset(probe.get(k)) for k in ('source_block','condition_at','state_write_at')) and refs(probe.get('evidence')), 'probe')
    elif kind == 'model_proposal':
        require(isinstance(data.get('request'),dict) and isinstance(data.get('proposal'),dict) and data.get('adapter') in ('replay','codex_exec'), 'proposal')
        from model_adapter import validate_proposal
        require(data['request'].get('binary_id') == binary_id, 'proposal binary')
        validate_proposal(data['request'], data['proposal'])
    else: raise ValueError('unsupported artifact kind: ' + kind)
