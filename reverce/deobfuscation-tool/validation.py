"""Structural checks for version 1 artifacts."""
import re
from probe import digest

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
        require(data.get('strategy') is None or isinstance(data['strategy'],str), 'structure strategy')
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
    elif kind == 'compiled_probe_plan':
        require(data.get('binary_id') == binary_id and isinstance(data.get('function'),str), 'identity')
        require(all(re.fullmatch(r'[0-9a-f]{64}',data.get(k,'')) for k in ('structure_id','plan_id')), 'plan hashes')
        require(data['plan_id'] == digest({k:v for k,v in data.items() if k != 'plan_id'}), 'plan content hash')
        require(data.get('strategy') in (None,'stack_slot_v1') and isinstance(data.get('unsupported'),list), 'strategy')
        require(isinstance(data.get('sources'),list) and bool(data['sources']) and isinstance(data.get('probes'),list) and bool(data['probes']), 'plan entries')
        for source in data['sources']:
            require(isinstance(source,dict) and offset(source.get('source_block')) and offset(source.get('transfer_site')) and isinstance(source.get('location'),str), 'source')
        require(len({x['source_block'] for x in data['sources']}) == len(data['sources']), 'duplicate source block')
        for probe in data['probes']:
            require(isinstance(probe,dict) and offset(probe.get('site')) and probe.get('role') in ('state_write','decision','dispatcher_read') and isinstance(probe.get('registers'),list), 'probe')
    elif kind == 'transition_observations':
        require(isinstance(data.get('function'),str) and isinstance(data.get('capture_ids'),list) and isinstance(data.get('records'),list) and isinstance(data.get('unpaired_events'),list) and isinstance(data.get('diagnostics'),list), 'observation')
        require(data.get('strategy','stack_slot_v1') == 'stack_slot_v1', 'strategy')
        require(all(re.fullmatch(r'[0-9a-f]{64}',data.get(k,'')) for k in ('structure_id','plan_id')), 'observation hashes')
        require(isinstance(data.get('capture_source'),dict) and isinstance(data['capture_source'].get('path'),str) and re.fullmatch(r'[0-9a-f]{64}',data['capture_source'].get('sha256','')), 'capture source')
        require(isinstance(data.get('router_observations'),list), 'router observations')
        require(isinstance(data.get('plan_unsupported',[]),list), 'unsupported plan items')
        require(bool(data['records']), 'no observed source executions')
        ids=set()
        for record in data['records']:
            require(isinstance(record,dict) and isinstance(record.get('id'),str) and record['id'] not in ids, 'record id')
            ids.add(record['id'])
            require(isinstance(record.get('origin'),dict) and offset(record['origin'].get('source_block')), 'origin')
            require(isinstance(record.get('transfer'),dict) and record['transfer'].get('kind') in ('state_write','direct_branch','indirect_branch','call_return_target','unknown'), 'transfer')
            require(isinstance(record.get('route'),dict) and isinstance(record.get('quality'),dict) and isinstance(record.get('evidence'),list), 'route/quality/evidence')
            require(isinstance(record['quality'].get('complete'),bool) and isinstance(record['quality'].get('missing'),list) and isinstance(record['quality'].get('ambiguous'),bool), 'quality')
    elif kind == 'transition_rules':
        require(isinstance(data.get('function'),str) and isinstance(data.get('rules'),list), 'rules')
        require(isinstance(data.get('strategy','stack_slot_v1'),str), 'strategy')
        require(all(re.fullmatch(r'[0-9a-f]{64}',data.get(k,'')) for k in ('structure_id','plan_id')), 'rule hashes')
        if data.get('input_hashes') is not None:
            require(isinstance(data['input_hashes'],dict) and set(data['input_hashes']) == {'instruction_table','static_cfg','structure_candidates','transition_observations'} and all(re.fullmatch(r'[0-9a-f]{64}',x) for x in data['input_hashes'].values()), 'rule input hashes')
        for rule in data['rules']:
            require(isinstance(rule,dict) and offset(rule.get('source_block')) and isinstance(rule.get('alternatives'),list) and isinstance(rule.get('unresolved'),list), 'rule')
            if 'state_location' in rule:
                require(rule['state_location'] is None if rule.get('transfer_kind') == 'return' else isinstance(rule['state_location'],str), 'rule state location')
            for alt in rule['alternatives']:
                require(isinstance(alt,dict) and alt.get('status') in ('observed','static_proven','observed_and_static_proven','unresolved','contradicted') and isinstance(alt.get('observation_ids'),list) and isinstance(alt.get('instruction_refs'),list), 'alternative')
                if alt.get('route_path') is not None:
                    require(isinstance(alt['route_path'],list) and bool(alt['route_path']) and all(offset(x) for x in alt['route_path']) and alt['route_path'][-1] == alt.get('target_block'), 'alternative route')
    elif kind == 'unresolved_rules':
        require(isinstance(data.get('function'),str) and isinstance(data.get('unresolved'),list), 'unresolved')
        require(isinstance(data.get('strategy','stack_slot_v1'),str), 'strategy')
        require(all(re.fullmatch(r'[0-9a-f]{64}',data.get(k,'')) for k in ('structure_id','plan_id')), 'unresolved hashes')
        if data.get('input_hashes') is not None:
            require(isinstance(data['input_hashes'],dict) and set(data['input_hashes']) == {'instruction_table','static_cfg','structure_candidates','transition_observations'} and all(re.fullmatch(r'[0-9a-f]{64}',x) for x in data['input_hashes'].values()), 'unresolved input hashes')
    elif kind == 'patch_plan':
        require(data.get('binary_id') == binary_id and isinstance(data.get('function'),str), 'identity')
        require(data.get('strategy') == 'arm64_direct_edges_v1' and re.fullmatch(r'[0-9a-f]{64}',data.get('plan_id','')) is not None, 'strategy or plan')
        hashes=data.get('input_hashes')
        require(isinstance(hashes,dict) and set(hashes) == {'instruction_table','static_cfg','structure_candidates','transition_rules'} and all(re.fullmatch(r'[0-9a-f]{64}',x) for x in hashes.values()), 'input hashes')
        require(isinstance(data.get('entries'),list) and isinstance(data.get('unresolved'),list), 'entries')
        sources=set(); sites=set()
        for entry in data['entries']:
            require(isinstance(entry,dict) and offset(entry.get('source_block')) and entry.get('kind') in ('entry','single','conditional','return') and entry.get('status') in ('ready','unresolved') and isinstance(entry.get('targets'),list) and isinstance(entry.get('patches'),list) and isinstance(entry.get('audit'),dict) and isinstance(entry.get('evidence_refs'),list), 'entry')
            require(entry['source_block'] not in sources, 'duplicate source'); sources.add(entry['source_block'])
            require(all(offset(x) for x in entry['targets']), 'targets')
            if entry['status'] == 'ready': require(entry['audit'].get('passed') is True and bool(entry['patches']), 'ready audit')
            for patch in entry['patches']:
                require(isinstance(patch,dict) and offset(patch.get('site')) and patch.get('kind') in ('b','b.cond') and offset(patch.get('target')) and re.fullmatch(r'[0-9a-f]{8}',patch.get('old_bytes','')) is not None and re.fullmatch(r'[0-9a-f]{8}',patch.get('new_bytes','')) is not None, 'patch')
                require(patch['site'] not in sites, 'overlapping site'); sites.add(patch['site'])
    elif kind == 'verification_report':
        require(isinstance(data.get('function'),str) and all(re.fullmatch(r'[0-9a-f]{64}',data.get(k,'')) for k in ('plan_hash','original_sha256','patched_sha256')), 'identity')
        require(data['original_sha256'] == binary_id and isinstance(data.get('patched_binary_path'),str), 'binary path')
        require(isinstance(data.get('static_checks'),dict) and isinstance(data.get('rollback_ok'),bool) and isinstance(data.get('behavior'),dict), 'checks')
        require(data.get('status') in ('passed','failed','not_run'), 'status')
    elif kind == 'rule_reviews':
        require(re.fullmatch(r'[0-9a-f]{64}',data.get('rules_hash','')) and isinstance(data.get('reviews'),list), 'review identity')
        from rule_review import validate_review
        for item in data['reviews']:
            require(isinstance(item,dict) and item.get('adapter') in ('replay','codex_exec') and isinstance(item.get('request'),dict) and item['request'].get('binary_id') == binary_id, 'review')
            validate_review(item['request'],item.get('proposal'))
    elif kind == 'model_proposal':
        require(isinstance(data.get('request'),dict) and isinstance(data.get('proposal'),dict) and data.get('adapter') in ('replay','codex_exec'), 'proposal')
        from model_adapter import validate_proposal
        require(data['request'].get('binary_id') == binary_id, 'proposal binary')
        validate_proposal(data['request'], data['proposal'])
    else: raise ValueError('unsupported artifact kind: ' + kind)
