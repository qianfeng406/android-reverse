"""Conservative proofs for state-slot stores and dead pure register writes."""
import re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from static_export import build_cfg

NOP='1f2003d5'
ALL={'x'+str(i) for i in range(31)} | {'nzcv','sp'}
PURE={'mov','movk','csel'}
KNOWN=PURE | {'add','sub','subs','cmp','tst','eor','asr','ldr','ldur','str','stur','b','ret','nop'}

def reg(x):
    return 'x'+x[1:] if re.fullmatch(r'[wx]\d+',x) else x

def analyze(items, state):
    """Return justified candidates and skipped candidate explanations, on edge CFG."""
    eng=Cs(CS_ARCH_ARM64,CS_MODE_ARM); eng.detail=True
    ds={int(i['module_offset'],16):next(eng.disasm(bytes.fromhex(i['bytes']),int(i['module_offset'],16))) for i in items}
    graph=build_cfg(items); bm={int(b['start'],16):b for b in graph}; todo=[min(ds)]; reach=set(); bad=False
    while todo:
        n=todo.pop()
        if n in reach: continue
        if n not in bm: bad=True; continue
        reach.add(n)
        for e in bm[n]['successors']:
            if e['kind'] in ('call','call_unresolved','indirect_unresolved'): bad=True
            elif e.get('in_function'): todo.append(int(e['target'],16))
            elif e.get('kind') not in ('return',): bad=True
    liveaddrs={a for n in reach for a in range(n,int(bm[n]['end_exclusive'],16),4)}
    succ={}
    for a in liveaddrs:
        b=next(bm[n] for n in reach if n<=a<int(bm[n]['end_exclusive'],16))
        succ[a]=([a+4] if a+4<int(b['end_exclusive'],16) else [int(e['target'],16) for e in b['successors'] if e.get('in_function') and e['kind']!='call'])
    unresolved=[]; removed=set(); store_sites=[]; slot=None
    try:
        if not state or not re.fullmatch(r'sp\+(?:0x)?[0-9a-f]+',state): raise ValueError('state_slot_not_proven')
        slot=int(state[3:],16); width=4
        first=min(ds); sp_adjust=[]; accesses=[]
        for a,d in ds.items():
            reads,writes=d.regs_access(); rn={reg(d.reg_name(x)) for x in reads}; wn={reg(d.reg_name(x)) for x in writes}
            if 'sp' in wn:
                if d.mnemonic not in ('sub','add') or not re.fullmatch(r'sp, sp, #0x[0-9a-f]+|sp, sp, #[0-9]+',d.op_str): raise ValueError('unknown_sp_adjustment')
                sp_adjust.append(a)
            if 'sp' in rn and (d.mnemonic not in ('sub','add','ldr','ldur','str','stur') or (d.mnemonic in ('sub','add') and not d.op_str.startswith('sp, sp, #'))): raise ValueError('stack_address_escape')
            if a in liveaddrs and d.mnemonic not in KNOWN and not d.mnemonic.startswith('b.'): raise ValueError('unknown_instruction_effect')
            if '[' in d.op_str:
                m=re.fullmatch(r'([wx]\d+|[wx]zr), \[sp(?:, #(?:0x[0-9a-f]+|[0-9]+))?\]',d.op_str)
                if d.mnemonic not in ('ldr','ldur','str','stur') or not m: raise ValueError('unknown_memory_access')
                off=re.search(r'#(0x[0-9a-f]+|[0-9]+)',d.op_str); off=int(off.group(1),0) if off else 0
                w=8 if m.group(1).startswith('x') else 4
                accesses.append((a,d.mnemonic,off,w))
        if not sp_adjust or sp_adjust[0]!=first or ds[first].mnemonic!='sub': raise ValueError('nonfixed_stack_frame')
        for a in sp_adjust[1:]:
            if ds[a].mnemonic!='add' or ds[a].op_str.replace('add','') != ds[first].op_str or a+4 not in ds or ds[a+4].mnemonic!='ret': raise ValueError('nonfixed_stack_frame')
        if bad or any(first in v for v in succ.values()): raise ValueError('unknown_control_flow')
        frame=int(ds[first].op_str.split('#')[1],0)
        if slot < 0 or slot+width > frame: raise ValueError('state_outside_stack_frame')
        for a,op,off,w in accesses:
            if a in liveaddrs and op in ('ldr','ldur') and off<slot+width and slot<off+w: raise ValueError('reachable_state_alias_read')
            if a in liveaddrs and op in ('str','stur') and off==slot and w==width: store_sites.append(a)
        removed.update(store_sites)
    except (ValueError,AttributeError) as exc:
        if slot is None: unresolved.append({'reason':str(exc)})
        for a in sorted(liveaddrs):
            d=ds[a]
            if d.mnemonic in ('str','stur') and slot is not None and '[' in d.op_str and slot == int((re.search(r'#(0x[0-9a-f]+|[0-9]+)',d.op_str) or [None,'0'])[1],0):
                unresolved.append({'site':hex(a),'reason':str(exc)})
    # Backwards may-liveness; unknown operations and exits are barriers.
    selected=[]
    while True:
        livein={a:set() for a in liveaddrs}; liveout={a:set() for a in liveaddrs}
        changed=True
        while changed:
            changed=False
            for a in sorted(liveaddrs,reverse=True):
                d=ds[a]; out=set().union(*(livein.get(x,ALL) for x in succ[a])) if succ[a] else ({'x0'} | {'x'+str(i) for i in range(19,31)})
                if bad: out |= ALL
                if a in removed: r=w=set()
                elif d.mnemonic not in KNOWN and not d.mnemonic.startswith('b.'): r=ALL; w=set()
                else:
                    rr,ww=d.regs_access(); r={reg(d.reg_name(x)) for x in rr}; w={reg(d.reg_name(x)) for x in ww}
                    if d.mnemonic=='movk': r.add(reg(d.op_str.split(',')[0]))
                    if d.mnemonic in ('csel',) or d.mnemonic.startswith('b.'): r.add('nzcv')
                    if d.mnemonic in ('cmp','tst','subs'): w.add('nzcv')
                inn=r | (out-w)
                if inn!=livein[a] or out!=liveout[a]: livein[a]=inn; liveout[a]=out; changed=True
        newly=[]
        for a in sorted(liveaddrs-removed):
            d=ds[a]
            if d.mnemonic not in PURE: continue
            dest=reg(d.op_str.split(',')[0])
            if re.fullmatch(r'x\d+',dest) and dest not in liveout[a]: newly.append(a)
        if not newly: break
        selected.extend(newly); removed.update(newly)
    entries=[]
    for a in sorted(removed):
        d=ds[a]; kind='dead_state_store' if a in store_sites else 'dead_register_write'
        entries.append({'site':hex(a),'old_bytes':bytes(d.bytes).hex(),'new_bytes':NOP,'kind':kind,
                        'reason':'state slot has no reachable overlapping reads and stack frame is fixed' if a in store_sites else 'pure register destination dead on all reachable successors'})
    for a in sorted(liveaddrs-removed):
        if ds[a].mnemonic in PURE: unresolved.append({'site':hex(a),'reason':'register_destination_live_or_unproven'})
    return entries,unresolved
