import unittest
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from static_export import export
from apply_verify import sha
from cleanup_analysis import analyze

class CleanupProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        f=Path(__file__).parent/'tests/fixtures/lesson_score'
        binary=f/'libflatten_fla_android.so'
        table,_=export(f/'lesson_score_trace_disasm.txt',sha(binary.read_bytes()),'lesson_score',binary)
        cls.bytes={x['module_offset']:x['bytes'] for x in table['instructions']}
    def code(self, addresses):
        engine=Cs(CS_ARCH_ARM64,CS_MODE_ARM); out=[]
        for n,src in enumerate(addresses):
            a=0x1000+n*4; raw=bytes.fromhex(self.bytes[src]); d=next(engine.disasm(raw,a))
            out.append({'module_offset':hex(a),'bytes':raw.hex(),'mnemonic':d.mnemonic,'operands':d.op_str})
        return out
    def test_state_store_and_dead_chain(self):
        items=self.code(['0x15fc','0x1614','0x1618','0x161c','0x18f0','0x18f4'])
        entries,_=analyze(items,'sp+0x4')
        self.assertEqual([x['kind'] for x in entries],['dead_register_write','dead_register_write','dead_state_store'])
    def test_alias_read_retains_store_and_chain(self):
        items=self.code(['0x15fc','0x1614','0x1618','0x161c','0x1620','0x18f0','0x18f4'])
        entries,skipped=analyze(items,'sp+0x4')
        self.assertFalse(any(x['kind']=='dead_state_store' for x in entries))
        self.assertTrue(any(x['reason']=='reachable_state_alias_read' for x in skipped))
    def test_wide_alias_read_blocks_store(self):
        items=self.code(['0x15fc','0x1614','0x1618','0x161c','0x1620','0x18f0','0x18f4'])
        raw=bytes.fromhex('e80340f9')  # ldr x8, [sp], overlapping bytes 4..7
        d=next(Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(raw,0x1010))
        items[4].update(bytes=raw.hex(),mnemonic=d.mnemonic,operands=d.op_str)
        entries,skipped=analyze(items,'sp+0x4')
        self.assertFalse(any(x['kind']=='dead_state_store' for x in entries))
        self.assertTrue(any(x['reason']=='reachable_state_alias_read' for x in skipped))

    def test_return_value_live(self):
        items=self.code(['0x15fc','0x18ec','0x18f0','0x18f4'])
        entries,_=analyze(items,'sp+0x4')
        self.assertEqual(entries,[])

if __name__=='__main__': unittest.main()
