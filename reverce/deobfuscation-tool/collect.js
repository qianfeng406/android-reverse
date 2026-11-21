// Capture every Stalker event, including excursions outside the target module.
rpc.exports = { configure(moduleName, symbol, runId) {
  const mod = Process.getModuleByName(moduleName), entry = mod.getExportByName(symbol);
  let next = 0; const active = new Set();
  function address(p) {
    const owner = Process.findModuleByAddress(ptr(p));
    return owner ? {module: owner.name, module_offset: ptr(p).sub(owner.base).toString()} : {absolute: ptr(p).toString()};
  }
  Interceptor.attach(entry, {
    onEnter(args) {
      this.tid = this.threadId; this.id = ++next; this.index = 0; this.input = args[0].toInt32();
      if (active.has(this.tid)) { send({type:'error', reason:'nested invocation on followed thread', run_id:runId, thread_id:this.tid, invocation_id:this.id}); this.skipped = true; return; }
      active.add(this.tid); const call = this;
      send({type:'enter', run_id:runId, thread_id:this.tid, invocation_id:this.id, input:this.input, module:moduleName});
      Stalker.follow(this.tid, {events:{block:true, call:true, ret:true}, onReceive(raw) {
        for (const event of Stalker.parse(raw, {annotate:true, stringify:true})) {
          let item = {type:event[0], run_id:runId, thread_id:call.tid, invocation_id:call.id, event_index:++call.index, raw:event};
          if (event[0] === 'block') {item.start = address(event[1]); item.end = address(event[2]);}
          if (event[0] === 'call' || event[0] === 'ret') {item.location = address(event[1]); item.target = address(event[2]); item.depth = event[3];}
          send(item);
        }
      }});
    },
    onLeave(retval) {
      if (this.skipped) return;
      Stalker.unfollow(this.tid); Stalker.flush(); active.delete(this.tid);
      send({type:'leave', run_id:runId, thread_id:this.tid, invocation_id:this.id, return_value:retval.toInt32()});
    }
  });
}};
