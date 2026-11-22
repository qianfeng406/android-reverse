import hashlib, json, tempfile, unittest, subprocess, sys
from copy import deepcopy
from pathlib import Path
from probe import compile_plan, normalize_probe_capture

class ProbeTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).parent; fixture=root/'tests/fixtures/lesson_score'
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); p=Path(self.tmp.name)
        def run(*args): subprocess.run([sys.executable,str(root/'cli.py'),*map(str,args)],check=True,capture_output=True)
        binary=fixture/'libflatten_fla_android.so'
        run('init','--binary',binary,'--output',p)
        run('static','--binary',binary,'--disasm',fixture/'lesson_score_trace_disasm.txt','--function','lesson_score','--output',p)
        run('import-legacy','--binary',binary,'--log',fixture/'lesson_score_trace_raw.log','--output',p)
        run('discover','--output',p)
        def load(name): return json.loads((p/name).read_text())['data']
        self.ins=load('instruction_table.json'); self.cfg=load('static_cfg.json'); self.structure=load('structure_candidates.json'); self.d2=load('probe_plan.json')
        self.plan=compile_plan(self.ins,self.cfg,self.structure,self.d2,'binary')
    def test_expansion_and_identity(self):
        self.assertEqual(len(self.plan['sources']),13)
        self.assertEqual(sum(p['role']=='decision' for p in self.plan['probes']),4)
        self.assertNotEqual(self.plan['plan_id'],compile_plan(self.ins,self.cfg,self.structure,self.d2,'other')['plan_id'])
    def test_stack_base_and_unsupported_sources(self):
        instructions=deepcopy(self.ins); structure=deepcopy(self.structure)
        candidate=structure['candidates'][0]
        candidate['state_slot']='x29+4'
        for row in instructions['instructions']:
            if row['mnemonic'].lower() in ('str','ldr') and '[sp, #4]' in row['operands']:
                row['operands']=row['operands'].replace('[sp, #4]','[x29, #4]')
        plan=compile_plan(instructions,self.cfg,structure,self.d2,'binary')
        self.assertTrue(all(x['location']=='x29+0x4' for x in plan['sources']))
        self.assertTrue(any(x['location']=='x29+0x4' for x in plan['probes'] if x['role']=='dispatcher_read'))
        source=next(x for x in plan['sources'] if x['source_block']=='0x17e0')
        row=next(x for x in instructions['instructions'] if x['module_offset']==source['transfer_site'])
        row['mnemonic']='stur'
        self.assertIn('0x17e0',[x['source_block'] for x in compile_plan(instructions,self.cfg,structure,self.d2,'binary')['sources']])
        row['mnemonic']='nop'
        plan=compile_plan(instructions,self.cfg,structure,self.d2,'binary')
        self.assertTrue(any(x['source_block']=='0x17e0' and x['reason']=='state_write_count' for x in plan['unsupported']))
        self.assertNotIn('0x17e0',[x['source_block'] for x in plan['sources']])
    def test_two_outcomes_in_one_invocation(self):
        source = next(x for x in self.plan['sources'] if x['decision_site'])
        decision = next(x for x in self.plan['probes'] if x['role'] == 'decision' and x['site'] == source['decision_site'])
        candidate = self.structure['candidates'][0]
        hub = candidate['dispatcher_blocks'][0]
        targets = [x for x in candidate['execution_entries'] if x != source['source_block']][:2]
        identity = {'run_id': 'two', 'thread_id': 7, 'invocation_id': 3, 'plan_id': self.plan['plan_id']}
        events = [dict(identity, type='enter', module='target', event_index=1)]
        for ordinal, target in enumerate(targets, 1):
            index = ordinal * 10
            values = {reg: {'width': 32 if reg.startswith('w') else 64,
                            'hex': '0x' + format(ordinal, '08x' if reg.startswith('w') else '016x')}
                      for reg in decision['registers']}
            events.extend([
                dict(identity, type='block', start={'module': 'target', 'module_offset': source['source_block']}, event_index=index),
                dict(identity, type='probe', site=source['decision_site'], role='decision', source_block=source['source_block'], source_ordinal=ordinal, values=values, event_index=index+1),
                dict(identity, type='probe', site=source['transfer_site'], role='state_write', source_block=source['source_block'], source_ordinal=ordinal, values={source['register']: {'width': source['width'], 'hex': '0x' + format(ordinal, '08x')}}, event_index=index+2),
                dict(identity, type='block', start={'module': 'target', 'module_offset': hub}, event_index=index+3),
                dict(identity, type='block', start={'module': 'target', 'module_offset': target}, event_index=index+4),
            ])
        events.append(dict(identity, type='leave', event_index=99))
        for index, event in enumerate(events, 1): event['event_index'] = index
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'capture'; path.write_text('\n'.join(json.dumps(e) for e in reversed(events)))
            out = normalize_probe_capture(path, 'binary', self.plan, self.structure, self.cfg)
        records = [r for r in out['records'] if r['origin']['source_block'] == source['source_block']]
        self.assertEqual(len(records), 2)
        for ordinal, record in enumerate(records, 1):
            self.assertEqual(record['origin']['source_ordinal'], ordinal)
            self.assertEqual(record['transfer']['value']['hex'], '0x' + format(ordinal, '08x'))
            self.assertEqual(record['route']['immediate_successor'], hub)
            self.assertEqual(record['route']['eventual_target'], targets[ordinal-1])
            self.assertEqual(record['route']['target_status'], 'observed_candidate_boundary')
            self.assertEqual(record['quality'], {'complete': True, 'missing': [], 'ambiguous': False})
            self.assertEqual(record['decision']['values'], {reg: {'width': 32 if reg.startswith('w') else 64,
                'hex': '0x' + format(ordinal, '08x' if reg.startswith('w') else '016x')} for reg in decision['registers']})
    def test_router_observations_and_nested_error(self):
        source=next(x for x in self.plan['sources'] if x['decision_site'])
        router=next(x for x in self.plan['probes'] if x['role']=='dispatcher_read')
        identity={'run_id':'nested','thread_id':1,'invocation_id':1,'plan_id':self.plan['plan_id']}
        events=[dict(identity,type='enter',module='target',event_index=1),
                dict(identity,type='block',start={'module':'target','module_offset':source['source_block']},event_index=2),
                dict(identity,type='probe',site=router['site'],role='dispatcher_read',source_block=None,values={router['location']:{'width':32,'hex':'0x00000001'}},memory_address='0x1000',event_index=3),
                dict(identity,type='probe',site=source['transfer_site'],role='state_write',source_block=source['source_block'],source_ordinal=99,values={},event_index=4),
                dict(identity,type='error',reason='nested invocation interrupted capture',event_index=5),
                dict(identity,type='leave',event_index=6)]
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'capture'; path.write_text('\n'.join(json.dumps(e) for e in events))
            out=normalize_probe_capture(path,'binary',self.plan,self.structure,self.cfg)
        self.assertEqual(len(out['router_observations']),1)
        self.assertEqual(out['router_observations'][0]['memory_address'],'0x1000')
        self.assertEqual(len(out['unpaired_events']),1)
        self.assertEqual(out['unpaired_events'][0]['source_ordinal'],99)
        self.assertIn('capture_error',out['records'][0]['quality']['missing'])
        self.assertTrue(any(x['reason']=='nested invocation interrupted capture' for x in out['diagnostics']))
    def test_entry_inside_static_block_and_invalid_probe(self):
        source = next(x for x in self.plan['sources'] if x['entry'])
        ident = {'run_id': 'entry', 'thread_id': 1, 'invocation_id': 1, 'plan_id': self.plan['plan_id']}
        events = [dict(ident, type='enter', module='target', event_index=1),
                  dict(ident, type='block', start={'absolute':'0x70000000'}, event_index=2),
                  dict(ident, type='block', start={'module':'target', 'module_offset':hex(int(source['source_block'],16)+16)}, event_index=3),
                  dict(ident, type='probe', site=source['transfer_site'], role='state_write', source_block=source['source_block'], source_ordinal=1, values={source['register']:{'width':32,'hex':'0x00000001'}}, event_index=4),
                  dict(ident, type='leave', event_index=5)]
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'capture'
            def write(): path.write_text('\n'.join(json.dumps(e) for e in events))
            write(); out=normalize_probe_capture(path,'binary',self.plan,self.structure,self.cfg)
            self.assertEqual(out['records'][0]['transfer']['value']['hex'],'0x00000001')
            self.assertEqual(out['records'][0]['origin']['source_ordinal'],1)
            self.assertEqual(out['unpaired_events'],[])
            self.assertEqual(out['capture_source'],{'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
            events[3]['site']='0xffff'; write()
            with self.assertRaisesRegex(ValueError, 'probe does not match'): normalize_probe_capture(path,'binary',self.plan,self.structure,self.cfg)
            events[3]['site']=source['transfer_site']; events[3]['event_index']=2; write()
            with self.assertRaisesRegex(ValueError, 'duplicate'): normalize_probe_capture(path,'binary',self.plan,self.structure,self.cfg)
    def test_repeated_missing_and_foreign(self):
        s=next(x for x in self.plan['sources'] if x['decision_site']); run={'run_id':'r','thread_id':1,'invocation_id':1,'plan_id':self.plan['plan_id']}
        events=[dict(run,type='enter',module='target',event_index=1)]
        for ordinal in (1,2):
            events.extend([dict(run,type='block',start={'module':'target','module_offset':s['source_block']},event_index=ordinal*10),dict(run,type='probe',site=s['transfer_site'],role='state_write',source_block=s['source_block'],source_ordinal=ordinal,values={s['register']:{'width':32,'hex':'0x0000000'+str(ordinal)}},event_index=ordinal*10+1)])
            if ordinal==1: events.append(dict(run,type='probe',site=s['decision_site'],role='decision',source_block=s['source_block'],source_ordinal=ordinal,values={},event_index=ordinal*10+2))
            events.append(dict(run,type='block',start={'module':'foreign','module_offset':self.structure['candidates'][0]['execution_entries'][0]},event_index=ordinal*10+3))
        events.append(dict(run,type='leave',event_index=99))
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'capture'; path.write_text('\n'.join(json.dumps(e) for e in events))
            out=normalize_probe_capture(path,'binary',self.plan,self.structure,self.cfg)
        self.assertEqual(len(out['records']),2)
        self.assertEqual(out['records'][0]['route']['target_status'],'foreign_module')
        self.assertIn('decision_probe',out['records'][1]['quality']['missing'])
        self.assertNotEqual(out['records'][0]['transfer']['value'],out['records'][1]['transfer']['value'])
    def test_late_probe_is_unpaired(self):
        s=next(x for x in self.plan['sources'] if x['source_block']=='0x1804')
        ident={'run_id':'late','thread_id':1,'invocation_id':1,'plan_id':self.plan['plan_id']}
        events=[dict(ident,type='enter',module='target',event_index=1),
                dict(ident,type='block',start={'module':'target','module_offset':s['source_block']},event_index=2),
                dict(ident,type='block',start={'module':'target','module_offset':'0x18f8'},event_index=3),
                dict(ident,type='probe',site=s['transfer_site'],role='state_write',source_block=s['source_block'],source_ordinal=1,values={s['register']:{'width':32,'hex':'0x00000001'}},event_index=4),
                dict(ident,type='leave',event_index=5)]
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'capture'; path.write_text('\n'.join(json.dumps(e) for e in events))
            out=normalize_probe_capture(path,'binary',self.plan,self.structure,self.cfg)
        self.assertIn('state_write_probe',out['records'][0]['quality']['missing'])
        self.assertEqual(len(out['unpaired_events']),1)
if __name__=='__main__': unittest.main()
