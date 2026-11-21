"""Static ARM64 export from a saved llvm-objdump listing."""
import re
from pathlib import Path

def classify(x):
    op = x['mnemonic']; target = None
    if op == 'b' or op == 'bl' or op.startswith('b.') or op in ('cbz','cbnz','tbz','tbnz'):
        operand = x['operands'].split(',')[-1].strip()
        match = re.match(r'^#?(?:0x)?([0-9a-fA-F]+)(?:\s|$|<)', operand)
        if match: target = int(match.group(1), 16)
    return op, target

def export(path, binary_id, function, binary):
    lines = Path(path).read_text(encoding='utf-8').splitlines()
    label = re.compile(r'^\s*([0-9a-fA-F]+) <([^>]+)>:')
    insn = re.compile(r'^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+){0,4}([a-zA-Z][\w.]*)\s*(.*)$')
    active = False; items = []
    for n, line in enumerate(lines, 1):
        m = label.match(line)
        if m:
            if active: break
            active = m.group(2) == function
            continue
        m = insn.match(line) if active else None
        if m:
            address = int(m.group(1), 16)
            items.append({'module_offset': hex(address), 'mnemonic': m.group(2).lower(), 'operands': m.group(3).strip(), 'evidence': ['disasm:line:%d' % n]})
    if not items: raise ValueError('function not found in disassembly: ' + function)
    addresses = [int(x['module_offset'], 16) for x in items]
    if any(b != a + 4 for a, b in zip(addresses, addresses[1:])): raise ValueError('non-contiguous ARM64 instruction listing')
    # Verify instruction text against the exact ELF bytes; no trust in a stale listing.
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    with open(binary, 'rb') as f:
        elf = ELFFile(f)
        if elf['e_machine'] != 'EM_AARCH64': raise ValueError('binary is not ARM64')
        symbols = []
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
                symbols.extend((sym['st_value'], sym['st_size']) for sym in sec.iter_symbols() if sym.name == function and sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0)
        symbols = set(symbols)
        if len(symbols) != 1: raise ValueError('missing or ambiguous sized ELF function symbol: ' + function)
        symbol_start, symbol_size = next(iter(symbols))
        if addresses[0] != symbol_start or addresses[-1] + 4 != symbol_start + symbol_size: raise ValueError('listing does not cover complete ELF function symbol')
        section = next((sec for sec in elf.iter_sections() if sec['sh_addr'] <= addresses[0] and addresses[-1] + 4 <= sec['sh_addr'] + sec['sh_size']), None)
        if section is None: raise ValueError('instructions outside ELF sections')
        code = section.data()[addresses[0]-section['sh_addr']:addresses[-1]+4-section['sh_addr']]
    decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, addresses[0]))
    if len(decoded) != len(items): raise ValueError('ELF disassembly length mismatch')
    for item, instruction in zip(items, decoded):
        if item['mnemonic'] != instruction.mnemonic: raise ValueError('disassembly mismatch at ' + item['module_offset'])
        item['bytes'] = instruction.bytes.hex()
        item['operands'] = instruction.op_str
    blocks = build_cfg(items)
    return {'function': function, 'instructions': items}, {'function': function, 'blocks': blocks}



def build_cfg(items):
    addresses = [int(x['module_offset'], 16) for x in items]
    leaders = {addresses[0]}; end = addresses[-1] + 4
    for i, x in enumerate(items):
        op, target = classify(x)
        if target in addresses: leaders.add(target)
        if (op == 'b' or op.startswith('b.') or op in ('cbz','cbnz','tbz','tbnz','ret','br','bl','blr')) and i+1 < len(items): leaders.add(addresses[i+1])
    starts = sorted(leaders); blocks = []
    for i, start in enumerate(starts):
        stop = starts[i+1] if i+1 < len(starts) else end
        last = items[(stop-addresses[0])//4-1]; op, target = classify(last); successors = []
        if target is not None: successors.append({'target': hex(target), 'kind': 'call' if op == 'bl' else 'branch', 'in_function': target in leaders})
        if op == 'blr' or (op == 'bl' and target is None): successors.append({'target': None, 'kind': 'call_unresolved', 'in_function': None})
        if op not in ('b','ret','br') and stop < end: successors.append({'target': hex(stop), 'kind': 'call_return' if op in ('bl','blr') else 'fallthrough', 'in_function': True})
        if op == 'br': successors.append({'target': None, 'kind': 'indirect_unresolved', 'in_function': None})
        blocks.append({'start': hex(start), 'end_exclusive': hex(stop), 'successors': successors, 'evidence': ['insn:' + last['module_offset']]})
    return blocks
