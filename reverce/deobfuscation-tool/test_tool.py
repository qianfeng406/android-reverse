import json
import hashlib
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path
from cli import legacy, write, read
from model_adapter import ReplayAdapter
from normalize_capture import normalize
from static_export import classify, build_cfg

TOOL = Path(__file__).resolve().parent
FIXTURE = TOOL / 'tests/fixtures/lesson_score'
from host_collect import ensure_typing_compat
import typing

class Tests(unittest.TestCase):
    def test_legacy_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'log'; p.write_text('RUN 1: input=2\nRUN 1 BLOCK 1: +0x10\nEND 1: input=2 result=7\n')
            data=legacy(p,'a'*64); r=data['runs'][0]
            self.assertIsNone(r['thread_id']); self.assertIsNone(r['events'][0]['end']); self.assertIn('call_events',data['missing_fields'])
    def test_version(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); write(p,'binary_manifest','a'*64,{'sha256':'a'*64,'filename':'x'})
            obj=json.loads((p/'binary_manifest.json').read_text()); obj['schema_version']=2; (p/'binary_manifest.json').write_text(json.dumps(obj))
            with self.assertRaises(ValueError): read(p,'binary_manifest')
    def test_replay(self):
        with tempfile.TemporaryDirectory() as d:
            req={'schema_version':1,'evidence_refs':['insn:0x10']}; prop={'schema_version':1,'kind':'candidate','supporting_refs':['insn:0x10']}; p=Path(d)/'p'; p.write_text(json.dumps({'request':req,'proposal':prop}))
            self.assertEqual(ReplayAdapter(p).propose(req),prop)
            with self.assertRaises(ValueError): ReplayAdapter(p).propose({'schema_version':1,'evidence_refs':[]})
    def test_invocation_isolation(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'c'; rows=[{'type':'enter','run_id':'r','thread_id':1,'invocation_id':1,'input':3,'module':'a.so'}, {'type':'block','run_id':'r','thread_id':1,'invocation_id':2,'event_index':1,'raw':[]}]; p.write_text('\n'.join(map(json.dumps,rows)))
            with self.assertRaises(ValueError): normalize(p,'a'*64,'a.so')
class HostCompatibilityTests(unittest.TestCase):
    def test_typing_names_filled_only_if_missing(self):
        names=('NotRequired','ParamSpec'); original={name:getattr(typing,name,None) for name in names}; present={name:hasattr(typing,name) for name in names}
        sentinel=object()
        try:
            typing.NotRequired=sentinel
            if hasattr(typing,'ParamSpec'): del typing.ParamSpec
            ensure_typing_compat()
            self.assertIs(typing.NotRequired,sentinel)
            self.assertTrue(hasattr(typing,'ParamSpec'))
        finally:
            for name in names:
                if present[name]: setattr(typing,name,original[name])
                elif hasattr(typing,name): delattr(typing,name)

class StaticTests(unittest.TestCase):
    def test_bit_branch_target(self):
        self.assertEqual(classify({'mnemonic':'tbz','operands':'w8, #3, #0x1804'})[1],0x1804)
        self.assertEqual(classify({'mnemonic':'tbnz','operands':'x2, #0x1f, #0x1234'})[1],0x1234)
    def test_call_edges(self):
        items=[{'module_offset':hex(0x1000+i*4),'mnemonic':op,'operands':arg} for i,(op,arg) in enumerate([('bl','#0x2000'),('blr','x8'),('ret','')])]
        blocks=build_cfg(items)
        self.assertEqual([e['kind'] for e in blocks[0]['successors']],['call','call_return'])
        self.assertEqual([e['kind'] for e in blocks[1]['successors']],['call_unresolved','call_return'])

class EndToEnd(unittest.TestCase):
    def test_capture_merge_replay_config(self):
        binary=FIXTURE/'libflatten_fla_android.so'; cli=TOOL/'cli.py'
        if not binary.exists(): self.skipTest('local sample unavailable')
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); out=d/'artifacts'; config=d/'custom.toml'; config.write_text('[model]\nprovider = "replay"\n',encoding='utf-8')
            def run(*args,success=True):
                result=subprocess.run([sys.executable,str(cli),'--config',str(config),*map(str,args)],capture_output=True,text=True)
                self.assertEqual(result.returncode == 0,success,result.stderr); return result
            run('init','--binary',binary,'--output',out)
            bid=hashlib.sha256(binary.read_bytes()).hexdigest()
            def capture(run_id,thread):
                common={'run_id':run_id,'thread_id':thread,'invocation_id':1}
                rows=[dict(common,type='enter',input=3,module='a.so'),dict(common,type='block',event_index=1,raw=['block','0x10','0x20'],start={'module':'a.so','module_offset':'0x10'},end={'module':'a.so','module_offset':'0x20'}),dict(common,type='call',event_index=2,raw=['call','0x10','0x50',0],location={'module':'a.so','module_offset':'0x10'},target={'module':'external.so','module_offset':'0x50'}),dict(common,type='ret',event_index=3,raw=['ret','0x50','0x14',0],location={'module':'external.so','module_offset':'0x50'},target={'module':'a.so','module_offset':'0x14'}),dict(common,type='leave',return_value=7)]
                path=d/(run_id+str(thread)+'.jsonl'); path.write_text('\n'.join(map(json.dumps,rows))+'\n',encoding='utf-8'); return path
            first=capture('one',1); second=capture('two',2); duplicate=capture('one',9)
            run('import-capture','--binary',binary,'--module','a.so','--capture',first,'--output',out)
            run('import-capture','--binary',binary,'--module','a.so','--capture',second,'--output',out,'--merge')
            run('import-capture','--binary',binary,'--module','a.so','--capture',duplicate,'--output',out,'--merge',success=False)
            data=json.loads((out/'raw_trace.json').read_text())['data']; self.assertEqual(len(data['runs']),2)
            self.assertEqual(set(data['source_sha256s']),{hashlib.sha256(p.read_bytes()).hexdigest() for p in (first,second)})
            events=data['runs'][0]['events']; self.assertEqual([e['event_index'] for e in events],[1,2,3]); self.assertEqual(events[0]['start']['binary_id'],bid); self.assertEqual(events[0]['end']['binary_id'],bid)
            self.assertNotIn('binary_id',events[1]['target']); self.assertIn(hashlib.sha256(first.read_bytes()).hexdigest(),events[0]['evidence'][0])
            request={'schema_version':1,'binary_id':bid,'evidence_refs':['insn:0x10']}; proposal={'schema_version':1,'kind':'candidate','supporting_refs':['insn:0x10']}
            req=d/'request.json'; saved=d/'saved.json'; req.write_text(json.dumps(request)); saved.write_text(json.dumps({'request':request,'proposal':proposal}))
            run('replay','--request',req,'--saved',saved,'--output',out)
            self.assertEqual(json.loads((out/'model_proposal.json').read_text())['data']['proposal'],proposal)

    def test_real_sample_and_resume(self):
        binary=FIXTURE/'libflatten_fla_android.so'; listing=FIXTURE/'lesson_score_trace_disasm.txt'; log=FIXTURE/'lesson_score_trace_raw.log'; cli=TOOL/'cli.py'
        if not all(p.exists() for p in (binary,listing,log)): self.skipTest('local sample unavailable')
        with tempfile.TemporaryDirectory() as d:
            def run(*args, success=True):
                result=subprocess.run([sys.executable,str(cli),*map(str,args)],capture_output=True,text=True)
                self.assertEqual(result.returncode == 0,success,result.stderr)
                return result
            run('init','--binary',binary,'--output',d)
            run('stage','--from-stage','1','--output',d,success=False)
            truncated=Path(d)/'truncated.txt'; lines=listing.read_text(encoding='utf-8').splitlines(); truncated.write_text('\n'.join(lines[:-1]),encoding='utf-8')
            run('static','--binary',binary,'--disasm',truncated,'--function','lesson_score','--output',d,success=False)
            run('static','--binary',binary,'--disasm',listing,'--function','lesson_score','--output',d)
            run('import-legacy','--binary',binary,'--log',log,'--output',d)
            run('stage','--from-stage','1','--output',d)
            cfg=json.loads((Path(d)/'static_cfg.json').read_text())['data']['blocks']; blocks={x['start']:x for x in cfg}
            self.assertIn('0x1620',blocks)
            for source,target in [('0x18f8','0x1620'),('0x17e0','0x18f8'),('0x1620','0x1804')]:
                self.assertIn(target,[e['target'] for e in blocks[source]['successors']])
            self.assertEqual(blocks['0x1620']['end_exclusive'],'0x1638')  # conditional at 0x1634
            trace=json.loads((Path(d)/'raw_trace.json').read_text()); self.assertEqual(len(trace['data']['runs']),7)
            trace['data']['runs'][0]['events'][0]['start']['module_offset']='garbage'; (Path(d)/'raw_trace.json').write_text(json.dumps(trace))
            run('stage','--from-stage','1','--output',d,success=False)
if __name__ == '__main__': unittest.main()
