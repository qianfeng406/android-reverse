import hashlib, os, tempfile, subprocess, re
from pathlib import Path
from io import BytesIO
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from static_export import build_cfg
from probe import digest
from cleanup_analysis import analyze as analyze_cleanup
from infer import canonical_slot

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
    # Validate the first layer before any cleanup can replace its bytes.
    edge_decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    for a,off,old,new,p in patches:
        ins=list(edge_decoder.disasm(new,a))
        expected='b' if p['kind']=='b' else 'b.'+str(p.get('condition'))
        if len(ins)!=1 or ins[0].mnemonic!=expected or int(ins[0].op_str.lstrip('#'),0)!=int(p['target'],16):
            raise ValueError('branch does not match plan')
    edge_buf=bytes(buf)
    cleanup=plan.get('cleanup', {'version': 1, 'entries': []})
    if cleanup.get('version') != 1: raise ValueError('unsupported cleanup version')
    # Re-run proof as validation only; no unplanned patch is synthesized here.
    edge_start=int(instruction_table['instructions'][0]['module_offset'],16)
    edge_end=int(instruction_table['instructions'][-1]['module_offset'],16)+4
    edge_ds=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(edge_buf[offset(edge_start):offset(edge_end-4)+4],edge_start))
    edge_items=[{'module_offset':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes':i.bytes.hex()} for i in edge_ds]
    selected=next((c for c in structure.get('candidates',[]) if c.get('hub')==structure.get('selected_candidate')), {})
    state=canonical_slot(selected['state_slot']) if selected.get('state_slot') else None
    proven,_=analyze_cleanup(edge_items,state)
    proven_sites={(p['site'],p['kind'],p['old_bytes'],p['new_bytes']) for p in proven}
    requested={(p['site'],p['kind'],p['old_bytes'],p['new_bytes']) for p in cleanup.get('entries',[]) if p.get('kind') in ('dead_state_store','dead_register_write')}
    if requested and requested != proven_sites: raise ValueError('incomplete dependent cleanup proof')
    cleanup_patches=[]
    planned={p['site']:p for p in cleanup.get('entries',[])}
    if len(planned)!=len(cleanup.get('entries',[])): raise ValueError('duplicate cleanup site')
    inverse={'eq':'ne','ne':'eq','hs':'lo','lo':'hs','cs':'cc','cc':'cs','mi':'pl','pl':'mi','vs':'vc','vc':'vs','hi':'ls','ls':'hi','ge':'lt','lt':'ge','gt':'le','le':'gt'}
    for p in cleanup.get('entries', []):
        a=int(p['site'],16); off=offset(a); old=bytes.fromhex(p['old_bytes']); new=bytes.fromhex(p['new_bytes'])
        if a%4 or len(old)!=4 or len(new)!=4 or bytes(buf[off:off+4])!=old: raise ValueError('invalid or stale cleanup patch')
        if any(x[1]==off for x in cleanup_patches): raise ValueError('overlapping cleanup patch')
        # Recheck the semantic proof encoded in this version of the plan.
        decoded_old=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(old,a))
        kind=p.get('kind')
        if len(decoded_old)!=1: raise ValueError('invalid cleanup instruction')
        ins=decoded_old[0]
        if kind=='nop':
            if new.hex()!='1f2003d5' or ins.mnemonic!='b' or int(ins.op_str.lstrip('#'),0)!=a+4: raise ValueError('invalid cleanup semantics')
        elif kind in ('dead_state_store','dead_register_write'):
            if (p['site'],kind,p['old_bytes'],p['new_bytes']) not in proven_sites: raise ValueError('unproven cleanup')
        elif kind=='invert_cond':
            pair=planned.get(p.get('paired_site')); nd=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(new,a))
            if not pair or pair.get('kind')!='trampoline_nop' or pair.get('paired_site')!=p['site'] or int(pair['site'],16)!=a+4 or not ins.mnemonic.startswith('b.') or int(ins.op_str.lstrip('#'),0)!=a+8: raise ValueError('invalid trampoline pair')
            old_pair=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(bytes.fromhex(pair['old_bytes']),a+4))
            if len(old_pair)!=1 or old_pair[0].mnemonic!='b' or len(nd)!=1 or nd[0].mnemonic!='b.'+inverse.get(ins.mnemonic[2:],'?') or nd[0].op_str!=old_pair[0].op_str: raise ValueError('invalid inverted branch')
            # Require the trampoline to have no other reachable predecessor.
            start0=int(instruction_table['instructions'][0]['module_offset'],16)
            ds=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(edge_buf[offset(start0):offset(int(instruction_table['instructions'][-1]['module_offset'],16))+4],start0))
            graph=build_cfg([{'module_offset':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ds]); bm={b['start']:b for b in graph}; seen=set(); todo=[hex(start0)]
            while todo:
                n=todo.pop()
                if n in seen or n not in bm: continue
                seen.add(n)
                if any(e['kind'] in ('call','call_unresolved','indirect_unresolved') for e in bm[n]['successors']): raise ValueError('unknown reachable control flow')
                todo.extend(e['target'] for e in bm[n]['successors'] if e.get('in_function'))
            preds=[n for n in seen for e in bm[n]['successors'] if e.get('in_function') and e['target']==hex(a+4)]
            owner=[n for n in seen if int(n,16)<=a<int(bm[n]['end_exclusive'],16)]
            if len(owner)!=1 or preds!=owner or hex(a+4) not in bm or int(bm[hex(a+4)]['end_exclusive'],16)!=a+8: raise ValueError('trampoline has other entry')
        elif kind=='trampoline_nop':
            pair=planned.get(p.get('paired_site'))
            if new.hex()!='1f2003d5' or not pair or pair.get('kind')!='invert_cond' or pair.get('paired_site')!=p['site']: raise ValueError('invalid trampoline nop')
        else: raise ValueError('unknown cleanup kind')
        buf[off:off+4]=new; cleanup_patches.append((a,off,old,new,p))
    items=instruction_table['instructions']; start=int(items[0]['module_offset'],16); end=int(items[-1]['module_offset'],16)+4
    start_off=offset(start); end_off=offset(end-4)+4
    if end_off-start_off != end-start or any(int(x['module_offset'],16) != start+4*i or original[offset(start+4*i):offset(start+4*i)+4].hex() != x['bytes'] for i,x in enumerate(items)): raise ValueError('instruction table does not match ELF')
    code=bytes(buf[start_off:end_off]); decoded=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(code,start))
    if len(decoded)!=len(items): raise ValueError('disassembly incomplete')
    byaddr={i.address:i for i in decoded}
    cleanup_sites={a for a,_,_,_,_ in cleanup_patches}
    for a,off,old,new,p in patches:
        if a in cleanup_sites: continue
        i=byaddr.get(a); expected='b' if p['kind']=='b' else 'b.'+str(p.get('condition'))
        if i is None or i.mnemonic!=expected or int(i.op_str.lstrip('#'),0)!=int(p['target'],16): raise ValueError('branch does not match plan')
    newitems=[{'module_offset':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes':i.bytes.hex(),'evidence':['insn:'+hex(i.address)]} for i in decoded]
    newcfg={'function':plan['function'],'blocks':build_cfg(newitems)}
    def metrics(code_bytes):
        ds=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(code_bytes,start))
        xs=[{'module_offset':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes':i.bytes.hex()} for i in ds]
        bs=build_cfg(xs); mapping={b['start']:b for b in bs}; seen_nodes=set(); pending=[hex(start)]
        while pending:
            n=pending.pop()
            if n in seen_nodes or n not in mapping: continue
            seen_nodes.add(n)
            pending.extend(e['target'] for e in mapping[n]['successors'] if e.get('in_function') and e.get('kind')!='call')
        live=[i for i in xs if any(int(b['start'],16)<=int(i['module_offset'],16)<int(b['end_exclusive'],16) for b in bs if b['start'] in seen_nodes)]
        reads=writes=0
        if state and re.fullmatch(r'sp\+(?:0x)?[0-9a-f]+',state):
            state_off=int(state[3:],16)
            for i in live:
                m=re.fullmatch(r'([wx]\d+|[wx]zr), \[sp(?:, #(0x[0-9a-f]+|[0-9]+))?\]',i['operands'])
                if not m or i['mnemonic'] not in ('ldr','ldur','str','stur'): continue
                off=int(m.group(2),0) if m.group(2) else 0; width=8 if m.group(1).startswith('x') else 4
                if off < state_off+4 and state_off < off+width:
                    if i['mnemonic'] in ('ldr','ldur'): reads+=1
                    else: writes+=1
        return {'total_blocks':len(bs),'reachable_blocks':len(seen_nodes), 'reachable_non_nop_instructions':sum(i['mnemonic']!='nop' for i in live), 'reachable_state_slot_reads':reads, 'reachable_state_slot_writes':writes}

    before_cleanup=metrics(edge_buf[start_off:end_off]); after_cleanup=metrics(code)
    candidate=next((c for c in structure.get('candidates',[]) if c.get('hub')==structure.get('selected_candidate')), {})
    dispatch={int(x,16) for x in candidate.get('dispatcher_blocks',[])}
    blocks={int(b['start'],16):b for b in newcfg['blocks']}; todo=[start]; seen=set()
    while todo:
        a=todo.pop()
        if a in seen or a not in blocks: continue
        seen.add(a); todo.extend(int(e['target'],16) for e in blocks[a]['successors'] if e.get('in_function') and e.get('target') and e['kind']!='call')
    reachable=sum(any(int(b['start'],16)<=a<int(b['end_exclusive'],16) for b in newcfg['blocks'] if int(b['start'],16) in seen) for a in dispatch)
    # The display graph only redirects single-entry NOP-only nodes. The CFG
    # and its metrics above always describe the actual bytes and block leaders.
    nodes={hex(a):{'start':hex(a),'end_exclusive':blocks[a]['end_exclusive'],
                  'instructions':[x for x in newitems if a<=int(x['module_offset'],16)<int(blocks[a]['end_exclusive'],16)]}
           for a in sorted(seen)}
    edges=[{'source':hex(a),'target':e['target'],'kind':e['kind']} for a in sorted(seen)
           for e in blocks[a]['successors'] if e.get('in_function') and int(e['target'],16) in seen and e['kind']!='call']
    reachable_graph={'nodes':list(nodes.values()),'edges':edges}
    display_nodes=dict(nodes); display_edges=[dict(e) for e in edges]; folded=[]
    while True:
        found=None
        for n,node in display_nodes.items():
            inc=[e for e in display_edges if e['target']==n]; out=[e for e in display_edges if e['source']==n]
            if n != hex(start) and node['instructions'] and all(i['mnemonic']=='nop' for i in node['instructions']) and len(inc)==1 and len(out)==1 and inc[0]['source']!=n and out[0]['target']!=n:
                found=(n,inc[0],out[0]); break
        if not found: break
        n,inc,out=found; inc['target']=out['target']; display_edges.remove(out); del display_nodes[n]
        folded.append({'node':n,'redirected_source':inc['source'],'target':inc['target']})
    display_graph={'kind':'display_only_nop_nodes_folded','nodes':list(display_nodes.values()),'edges':display_edges,'folded_nodes':folded}
    for a,off,old,new,p in cleanup_patches:
        expected = 'b.'+p['condition'] if p['kind']=='invert_cond' else 'nop'
        if byaddr.get(a) is None or byaddr[a].mnemonic != expected: raise ValueError('cleanup decode mismatch')
    undo=bytearray(buf)
    for a,off,old,new,p in reversed(cleanup_patches): undo[off:off+4]=old
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
    return {'original_sha256':original_hash,'patched_sha256':sha(buf),'patched_instruction_table':{'function':plan['function'],'instructions':newitems},'patched_cfg':newcfg,'reachable_graph':reachable_graph,'display_graph':display_graph,'static_checks':{'patch_count':len(patches),'cleanup_patch_count':len(cleanup_patches),'before_cleanup':before_cleanup,'after_cleanup':after_cleanup,'reachable_dispatcher_blocks':reachable},'rollback_ok':rollback,'repaired_binary_path':str(out)}

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
