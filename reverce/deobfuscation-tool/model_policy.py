"""Conservative deterministic gates for optional model diagnostics."""

def real_behavior_difference(case):
    if not isinstance(case, dict) or case.get('match') is not False: return False
    original, patched = case.get('original', {}), case.get('patched', {})
    if original.get('exit_code') != 0: return False
    stderr = str(patched.get('stderr', '')).lower()
    unavailable = any(word in stderr for word in
                      ('no devices', 'device offline', 'device not found', 'no device',
                       'runner missing', 'not found', 'command not found'))
    return ((patched.get('exit_code') == 0 and original.get('return_value') is not None
             and patched.get('return_value') is not None and not unavailable
             and (original['return_value'] != patched['return_value']
                  or original.get('stderr', '') != patched.get('stderr', '')))
            or (isinstance(patched.get('exit_code'), int) and patched['exit_code'] != 0
                and patched.get('return_value') is None and not unavailable))

def classify_blocker(stage, artifacts):
    def result(code, source, items):
        items = items[:10]
        refs = [str(x.get('source_block')) for x in items if isinstance(x, dict) and x.get('source_block') is not None]
        return {'stage': stage, 'reason_code': code, 'sources': list(dict.fromkeys(refs)),
                'evidence_refs': ['block:' + x for x in refs],
                'facts': [{'reason': str(x.get('reason', ''))[:200]} for x in items if isinstance(x, dict)]}
    if stage == 2 and 'structure_candidates' in artifacts:
        cs = artifacts['structure_candidates'].get('candidates', [])
        if not cs:
            return result('no_candidates', 'structure_candidates', [])
        def score(c):
            return (len(c.get('state_writers', [])), len(c.get('comparison_blocks', [])), c.get('fan_in', 0))
        best = max(map(score, cs))
        tied = [c for c in cs if score(c) == best]
        if len({(str(c.get('hub')), str(c.get('state_slot'))) for c in tied}) > 1:
            return result('ambiguous_candidates', 'structure_candidates', [{'source_block': c.get('hub'), 'reason': str(score(c))} for c in tied])
    if stage == 3:
        items = artifacts.get('compiled_probe_plan', {}).get('unsupported', [])
        if items: return result('unsupported_probe', 'compiled_probe_plan', items)
    if stage == 4:
        items = artifacts.get('unresolved_rules', {}).get('unresolved', [])
        excluded = ('stale', 'hash', 'identity', 'format', 'missing_event', 'incomplete', 'observation_transfer_mismatch', 'unverified_observation_guard', 'observation_conflict', 'dispatcher_read_mismatch')
        items = [x for x in items if isinstance(x, dict) and not any(s in str(x.get('reason', '')).lower() for s in excluded)]
        if items: return result('unresolved_rules', 'unresolved_rules', items)
        rules = artifacts.get('transition_rules', {}).get('rules', [])
        contradicted = [r for r in rules if any(a.get('status') == 'contradicted' for a in r.get('alternatives', []))]
        obs = artifacts.get('transition_observations', {})
        records = obs.get('records', [])
        complete = ('diagnostics' in obs and 'unpaired_events' in obs and not obs['diagnostics'] and not obs['unpaired_events'] and bool(records) and all(r.get('quality', {}).get('complete') is True for r in records))
        if contradicted and complete: return result('contradicted_rules', 'transition_rules', contradicted)
    if stage == 5:
        items = artifacts.get('patch_plan', {}).get('unresolved', [])
        semantic = ('template', 'side_effect', 'unsafe_dispatch', 'unknown_dispatch_memory', 'unknown_memory_access', 'unknown_live_in_effect', 'unproven_memory_alias', 'stack_address_escape', 'live_in:', 'live_in_return', 'mixed_block', 'unsupported')
        excluded = ('stale', 'hash', 'bytes', 'address', 'identity', 'encoding')
        items = [x for x in items if isinstance(x, dict) and any(s in str(x.get('reason', '')).lower() for s in semantic) and not any(s in str(x.get('reason', '')).lower() for s in excluded)]
        if items: return result('patch_semantics', 'patch_plan', items)
    if stage == 6:
        report = artifacts.get('verification_report', artifacts.get('verification', artifacts.get('verify_report', {})))
        static = report.get('static_checks', {})
        behavior = report.get('behavior', {})
        if (static.get('passed') is True or (static.get('patch_count', 0) > 0 and static.get('reachable_dispatcher_blocks') == 0 and report.get('rollback_ok') is True)) and behavior.get('status') == 'failed':
            cases = behavior.get('cases', [])
            bad = []
            for c in cases:
                if real_behavior_difference(c):
                    bad.append({'reason': 'behavior_difference', 'source_block': None})
            if bad: return result('behavior_difference', 'verification', bad)
    return None
