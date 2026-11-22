rpc.exports = { configure(moduleName, symbol, runId, plan) {
  const mod = Process.getModuleByName(moduleName), entry = mod.getExportByName(symbol);
  const sites = {}; for (const p of plan.probes) (sites[p.site] ||= []).push(p);
  const sources = new Set(plan.sources.map(s => s.source_block)); let next = 0; const active = new Map();
  Interceptor.attach(entry, {
    onEnter(args) {
      this.tid=this.threadId; this.id=++next; this.index=0; this.counts={}; this.current={}; this.firstTargetBlock=true;
      if (active.has(this.tid)) {active.get(this.tid).emit({type:'error',reason:'nested invocation interrupted capture'}); this.skipped=true; send({type:'error',reason:'nested invocation',run_id:runId,thread_id:this.tid,invocation_id:this.id,event_index:1,plan_id:plan.plan_id}); return;}
      const call=this;
      function emit(e) {send(Object.assign(e,{run_id:runId,thread_id:call.tid,invocation_id:call.id,event_index:++call.index,plan_id:plan.plan_id}));}
      call.emit=emit; active.set(this.tid,call);
      emit({type:'enter',module:moduleName});
      Stalker.follow(this.tid,{transform(iterator) {
        let ins, first=true;
        while ((ins=iterator.next())!==null) {
          const address=ins.address, owner=Process.findModuleByAddress(address);
          const offset=owner && owner.name===moduleName ? address.sub(mod.base).toString() : null;
          if (first) { first=false; iterator.putCallout(function () {
            const o=Process.findModuleByAddress(address); const a=o ? {module:o.name,module_offset:address.sub(o.base).toString()} : {absolute:address.toString()};
            let source=offset;
            if (call.firstTargetBlock && offset && !sources.has(offset)) {const entrySource=plan.sources.find(s => s.entry && ptr(offset).compare(ptr(s.source_block)) >= 0 && ptr(offset).compare(ptr(s.end_exclusive)) < 0); if (entrySource) source=entrySource.source_block;}
            if (offset) call.firstTargetBlock=false;
            if (source && sources.has(source)) {call.counts[source]=(call.counts[source]||0)+1; call.current[source]=call.counts[source];}
            emit({type:'block',start:a});
          }); }
          for (const p of (sites[offset] || [])) iterator.putCallout(function (ctx) {
            const values={}; for (const r of p.registers) {const x=ctx[r[0]==='w'?'x'+r.slice(1):r]; const width=r[0]==='w'?32:64; let h=x.toString().replace(/^0x/,''); if(width===32) h=h.slice(-8); values[r]={width:width,hex:'0x'+h.padStart(width/4,'0')};}
            const item={type:'probe',site:p.site,role:p.role,source_block:p.source_block,source_ordinal:call.current[p.source_block],values:values};
            if (p.role === 'dispatcher_read') {
              const address=ctx.sp.add(parseInt(p.location.slice(3),16)); item.memory_address=address.toString();
              try {item.values[p.location]={width:32,hex:'0x'+address.readU32().toString(16).padStart(8,'0')};}
              catch (e) {item.read_error=String(e);}
            }
            emit(item);
          });
          if (ins.mnemonic === 'bl' || ins.mnemonic === 'blr') iterator.putCallout(function () { emit({type:'call',site:offset,reason:'unsupported call boundary'}); });
          iterator.keep();
        }
      }});
    },
    onLeave(retval) {if(this.skipped)return; Stalker.unfollow(this.tid); Stalker.flush(); active.delete(this.tid); send({type:'leave',run_id:runId,thread_id:this.tid,invocation_id:this.id,event_index:++this.index,plan_id:plan.plan_id});}
  });
}};
