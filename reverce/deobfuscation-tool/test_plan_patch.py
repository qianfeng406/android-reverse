import unittest
from arm64_patch import encode_b, encode_b_cond

class BranchEncodingTests(unittest.TestCase):
    def test_encodings(self):
        self.assertEqual(encode_b(0x1000, 0x1004), '01000014')
        self.assertEqual(encode_b_cond(0x1000, 0x1004, 'eq'), '20000054')
        self.assertEqual(encode_b(0x1004, 0x1000), 'ffffff17')

    def test_invalid(self):
        for call in (lambda: encode_b(0, 1), lambda: encode_b(0, 1 << 27),
                     lambda: encode_b_cond(0, 1 << 20, 'eq'),
                     lambda: encode_b_cond(0, 4, 'al')):
            with self.assertRaises(ValueError):
                call()

class FixturePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import json
        from pathlib import Path
        cls.root = Path(__file__).parent
        import subprocess, sys, tempfile, hashlib
        from infer import infer_rules
        fixture = cls.root / 'tests/fixtures/lesson_score'
        binary = fixture / 'libflatten_fla_android.so'
        with tempfile.TemporaryDirectory() as directory:
            def run(*args):
                subprocess.run([sys.executable, str(cls.root / 'cli.py'), *map(str, args)],
                               check=True, capture_output=True, text=True)
            run('init', '--binary', binary, '--output', directory)
            run('static', '--binary', binary, '--disasm', fixture / 'lesson_score_trace_disasm.txt',
                '--function', 'lesson_score', '--output', directory)
            run('import-legacy', '--binary', binary, '--log', fixture / 'lesson_score_trace_raw.log', '--output', directory)
            run('discover', '--output', directory)
            path = Path(directory)
            cls.data = {n: json.loads((path / (n + '.json')).read_text())['data']
                        for n in ('instruction_table', 'static_cfg', 'structure_candidates')}
        binary_id = hashlib.sha256(binary.read_bytes()).hexdigest()
        obs = {'function': 'lesson_score', 'plan_id': 'test', 'records': []}
        cls.data['transition_rules'], cls.data['unresolved_rules'] = infer_rules(
            cls.data['instruction_table'], cls.data['static_cfg'], cls.data['structure_candidates'], obs, binary_id)

    def plan(self, data):
        from plan_patch import plan_patches
        r = data['transition_rules']
        return plan_patches(self.root / 'tests/fixtures/lesson_score/libflatten_fla_android.so',
                            data['instruction_table'], data['static_cfg'], data['structure_candidates'],
                            r, data['unresolved_rules'], r['binary_id'])

    def test_fixture_ready(self):
        p = self.plan(self.data)
        self.assertEqual(len(p['entries']), 13)
        self.assertEqual(p['unresolved'], [])

    def test_rule_conflict_rejected(self):
        import copy
        d = copy.deepcopy(self.data)
        d['transition_rules']['rules'].append(copy.deepcopy(d['transition_rules']['rules'][0]))
        p = self.plan(d)
        self.assertNotIn('0x15fc', [e['source_block'] for e in p['entries']])
        self.assertTrue(any(x['reason'] == 'conflicting_source_rules' for x in p['unresolved']))

    def test_changed_bytes_rejected(self):
        import copy
        from probe import digest
        d = copy.deepcopy(self.data)
        d['instruction_table']['instructions'][0]['bytes'] = '00000000'
        d['transition_rules']['input_hashes']['instruction_table'] = digest(d['instruction_table'])
        p = self.plan(d)
        self.assertEqual(p['entries'], [])
        self.assertTrue(any('instruction_bytes_mismatch' in x['reason'] for x in p['unresolved']))

    def mutated_binary_plan(self, address, raw):
        import copy, tempfile, hashlib
        from pathlib import Path
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        from elftools.elf.elffile import ELFFile
        from probe import digest
        from plan_patch import plan_patches
        data = copy.deepcopy(self.data)
        original = self.root / 'tests/fixtures/lesson_score/libflatten_fla_android.so'
        image = bytearray(original.read_bytes())
        with original.open('rb') as f:
            elf = ELFFile(f)
            seg = next(x for x in elf.iter_segments() if x['p_type'] == 'PT_LOAD' and x['p_vaddr'] <= address < x['p_vaddr'] + x['p_filesz'])
            offset = seg['p_offset'] + address - seg['p_vaddr']
        image[offset:offset+4] = raw
        ins = next(x for x in data['instruction_table']['instructions'] if int(x['module_offset'],16) == address)
        decoded = next(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(raw, address))
        ins.update(bytes=raw.hex(), mnemonic=decoded.mnemonic, operands=decoded.op_str)
        rules = data['transition_rules']
        rules['input_hashes']['instruction_table'] = digest(data['instruction_table'])
        rules['binary_id'] = hashlib.sha256(image).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'mutated.so'; binary.write_bytes(image)
            return plan_patches(binary, data['instruction_table'], data['static_cfg'],
                                data['structure_candidates'], rules, data['unresolved_rules'], rules['binary_id'])

    def test_dispatch_call_rejected(self):
        p = self.mutated_binary_plan(0x1624, bytes.fromhex('00000094'))
        self.assertEqual(p['entries'], [])
        self.assertTrue(any('unsupported_instruction' in x['reason'] for x in p['unresolved']))

    def test_target_live_flags_rejected(self):
        p = self.mutated_binary_plan(0x1760, bytes.fromhex('00000054'))
        self.assertNotIn('0x15fc', [x['source_block'] for x in p['entries']])
        self.assertTrue(any(x.get('source_block') == '0x15fc' and 'live_in' in x['reason'] for x in p['unresolved']))

    def test_dispatch_unknown_write_rejected(self):
        p = self.mutated_binary_plan(0x1624, bytes.fromhex('080000b9'))
        self.assertEqual(p['entries'], [])
        self.assertTrue(any('unsupported_store' in x['reason'] for x in p['unresolved']))

    def test_target_live_register_rejected(self):
        p = self.mutated_binary_plan(0x1760, bytes.fromhex('e003082a'))
        self.assertNotIn('0x15fc', [x['source_block'] for x in p['entries']])
        self.assertTrue(any(x.get('source_block') == '0x15fc' and 'live_in' in x['reason'] for x in p['unresolved']))
