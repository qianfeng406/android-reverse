import hashlib, os, tempfile, subprocess, re
from pathlib import Path
from io import BytesIO
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from static_export import build_cfg
from probe import digest

def sha(b): return hashlib.sha256(b).hexdigest()
def apply_plan(binary_path, plan, output_path, instruction_table, cfg, structure):
    original = Path(binary_path).read_bytes(); original_hash = sha(original)
    if Path(binary_path).resolve() == Path(output_path).resolve(): raise ValueError('output must differ from original')
    if plan.get('binary_id') != original_hash: raise ValueError('binary hash mismatch')
    if plan.get('strategy') != 'arm64_direct_edges_v1' or plan.get('unresolved') or not plan.get('entries'): raise ValueError('incomplete plan')
    for k, obj in [('instruction_table',instruction_table),('static_cfg',cfg),('structure_candidates',structure)]:
        if plan.get('input_hashes',{}).get(k) != digest(obj): raise ValueError('input hash mismatch: '+k)
    if any(x.get('status') != 'ready' or not x.get('audit',{}).get('passed') for x in plan['entries']): raise ValueError('entry not ready')
    elf=ELFFile(BytesIO(original))
    if elf['e_machine'] != 'EM_AARCH64': raise ValueError('not ARM64')
    sections=[s for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS' and s['sh_flags'] & 4]
    def offset(addr):
        matches=[s for s in sections if s['sh_addr'] <= addr and addr+4 <= s['sh_addr']+s['sh_size']]
        if len(matches)!=1: raise ValueError('ambiguous or unmapped address')
        s=matches[0]; return s['sh_offset']+addr-s['sh_addr']
    buf=bytearray(original); patches=[]; sites=set()
    for entry in plan['entries']:
        for p in entry['patches']:
            a=int(p['site'],16); off=offset(a); old=bytes.fromhex(p['old_bytes']); new=bytes.fromhex(p['new_bytes'])
            if a%4 or len(old)!=4 or len(new)!=4 or off in sites or original[off:off+4]!=old: raise ValueError('invalid, overlapping, or stale patch')
            sites.add(off); buf[off:off+4]=new; patches.append((a,off,old,new,p))
    items=instruction_table['instructions']; start=int(items[0]['module_offset'],16); end=int(items[-1]['module_offset'],16)+4
    start_off=offset(start); end_off=offset(end-4)+4
    if end_off-start_off != end-start or any(int(x['module_offset'],16) != start+4*i or original[offset(start+4*i):offset(start+4*i)+4].hex() != x['bytes'] for i,x in enumerate(items)): raise ValueError('instruction table does not match ELF')
    code=bytes(buf[start_off:end_off]); decoded=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(code,start))
    if len(decoded)!=len(items): raise ValueError('disassembly incomplete')
    byaddr={i.address:i for i in decoded}
    for a,off,old,new,p in patches:
        i=byaddr.get(a); expected='b' if p['kind']=='b' else 'b.'+str(p.get('condition'))
        if i is None or i.mnemonic!=expected or int(i.op_str.lstrip('#'),0)!=int(p['target'],16): raise ValueError('branch does not match plan')
    newitems=[{'module_offset':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes':i.bytes.hex(),'evidence':['insn:'+hex(i.address)]} for i in decoded]
    newcfg={'function':plan['function'],'blocks':build_cfg(newitems)}
    candidate=next((c for c in structure.get('candidates',[]) if c.get('hub')==structure.get('selected_candidate')), {})
    dispatch={int(x,16) for x in candidate.get('dispatcher_blocks',[])}
    blocks={int(b['start'],16):b for b in newcfg['blocks']}; todo=[start]; seen=set()
    while todo:
        a=todo.pop()
        if a in seen or a not in blocks: continue
        seen.add(a); todo.extend(int(e['target'],16) for e in blocks[a]['successors'] if e.get('in_function') and e.get('target') and e['kind']!='call')
    reachable=sum(any(int(b['start'],16)<=a<int(b['end_exclusive'],16) for b in newcfg['blocks'] if int(b['start'],16) in seen) for a in dispatch)
    undo=bytearray(buf)
    for a,off,old,new,p in patches: undo[off:off+4]=old
    rollback=sha(undo)==original_hash
    if not rollback or sha(Path(binary_path).read_bytes())!=original_hash: raise ValueError('rollback or original hash mismatch')
    out=Path(output_path); out.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=out.parent,prefix='.patch-')
    try:
        with os.fdopen(fd,'wb') as f: f.write(buf); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,out)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return {'original_sha256':original_hash,'patched_sha256':sha(buf),'patched_instruction_table':{'function':plan['function'],'instructions':newitems},'patched_cfg':newcfg,'static_checks':{'patch_count':len(patches),'reachable_dispatcher_blocks':reachable},'rollback_ok':rollback,'repaired_binary_path':str(out)}

def verify_behavior(runner_spec, original_path, patched_path):
    if not runner_spec or not runner_spec.get('command') or not runner_spec.get('inputs'): return {'status':'not_run','reason':'runner or inputs unavailable','cases':[]}
    cases=[]
    try:
        for value in runner_spec['inputs']:
            results=[]
            for binary in (runner_spec.get('original_binary', original_path), runner_spec.get('patched_binary', patched_path)):
                command=[str(x).replace('{binary}',str(binary)).replace('{input}',str(value)) for x in runner_spec['command']]
                p=subprocess.run(command,capture_output=True,text=True,timeout=runner_spec.get('timeout',30))
                matches=re.findall(r'^RESULT:\s*(-?\d+)\s*$',p.stdout,re.MULTILINE)
                results.append({'return_value':int(matches[0]) if len(matches)==1 else None,'exit_code':p.returncode,'stderr':p.stderr,'stdout':p.stdout})
            valid=all(x['exit_code']==0 and x['return_value'] is not None for x in results)
            cases.append({'input':value,'original':results[0],'patched':results[1],'match':valid and all(results[0][k]==results[1][k] for k in ('return_value','exit_code','stderr'))})
    except (OSError, subprocess.TimeoutExpired) as exc: return {'status':'not_run','reason':str(exc),'cases':cases,'runner_spec':runner_spec}
    return {'status':'passed' if all(c['match'] for c in cases) else 'failed','cases':cases,'runner_spec':runner_spec}
