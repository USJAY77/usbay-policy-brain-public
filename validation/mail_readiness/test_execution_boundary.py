"""Pure tests only. No local seccomp installation or executable startup."""
import copy
import struct
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import execution_boundary as e


def elf(path=b'/lib64/ld-linux-x86-64.so.2\0',count=1):
    data=bytearray(1024)
    data[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI',data,16,3,62,1)
    struct.pack_into('<Q',data,32,64)
    struct.pack_into('<HHH',data,52,64,56,count)
    for i in range(count):
        offset=64+56*i
        struct.pack_into('<I',data,offset,3)
        struct.pack_into('<Q',data,offset+8,512)
        struct.pack_into('<Q',data,offset+32,len(path))
    data[512:512+len(path)]=path
    return bytes(data)


class ElfTests(unittest.TestCase):
    def test_exact_interpreter(self):
        self.assertEqual(e.elf_interpreter(elf()),'/lib64/ld-linux-x86-64.so.2')

    def test_truncated_or_unknown_format(self):
        for data in (b'',b'x'*64,elf()[:63]):
            with self.subTest(size=len(data)),self.assertRaises(RuntimeError):e.elf_interpreter(data)

    def test_wrong_architecture_rejected(self):
        data=bytearray(elf());struct.pack_into('<H',data,18,183)
        with self.assertRaises(RuntimeError):e.elf_interpreter(bytes(data))

    def test_wrong_endianness_rejected(self):
        data=bytearray(elf());data[5]=2
        with self.assertRaises(RuntimeError):e.elf_interpreter(bytes(data))

    def test_duplicate_interpreters_rejected(self):
        with self.assertRaises(RuntimeError):e.elf_interpreter(elf(count=2))

    def test_missing_interpreter_rejected(self):
        data=bytearray(elf());struct.pack_into('<I',data,64,1)
        with self.assertRaises(RuntimeError):e.elf_interpreter(bytes(data))
        self.assertIsNone(e.elf_interpreter(bytes(data),required=False))

    def test_table_bounds_rejected(self):
        data=bytearray(elf());struct.pack_into('<Q',data,32,1000)
        with self.assertRaises(RuntimeError):e.elf_interpreter(bytes(data))

    def test_bad_interpreter_bounds_rejected(self):
        data=bytearray(elf());struct.pack_into('<Q',data,72,1020)
        with self.assertRaises(RuntimeError):e.elf_interpreter(bytes(data))

    def test_bad_paths_rejected(self):
        for path in (b'relative\0',b'/tmp/loader\0',b'/lib64/../tmp/loader\0',b'/lib64//loader\0',b'/lib64/lo\0ader\0',b'/lib64/loader'):
            with self.subTest(path=path),self.assertRaises(RuntimeError):e.elf_interpreter(elf(path))

    def test_invalid_entry_size_rejected(self):
        data=bytearray(elf());struct.pack_into('<H',data,54,55)
        with self.assertRaises(RuntimeError):e.elf_interpreter(bytes(data))


class BindingTests(unittest.TestCase):
    def setUp(self):
        item={'path':'/usr/bin/python3.12','sha256':'a'*64,'device':1,'inode':2,'size':1024,'mode':0o755}
        self.value={'schema':'usbay.synthetic_runtime_binding.v1','python':item,'loader':dict(item,path='/usr/lib/loader'),'interpreter_path':'/lib64/loader'}

    def test_exact_binding(self):
        self.assertTrue(e.runtime_binding_pass(self.value,copy.deepcopy(self.value)))

    def test_changed_runtime_is_not_equivalent(self):
        for name in ('python','loader'):
            other=copy.deepcopy(self.value);other[name]['sha256']='b'*64
            self.assertFalse(e.runtime_binding_pass(self.value,other))

    def test_inode_substitution_rejected(self):
        other=copy.deepcopy(self.value);other['loader']['inode']=3
        self.assertFalse(e.runtime_binding_pass(self.value,other))

    def test_missing_or_extra_binding_fields_rejected(self):
        other=copy.deepcopy(self.value);other['loader']['extra']=True
        self.assertFalse(e.runtime_binding_pass(self.value,other))
        other=copy.deepcopy(self.value);del other['python']
        self.assertFalse(e.runtime_binding_pass(self.value,other))

    def test_boolean_ids_rejected_even_on_both_sides(self):
        other=copy.deepcopy(self.value);other['python']['inode']=True
        self.assertFalse(e.runtime_binding_pass(other,other))

    def test_bad_digest_rejected(self):
        other=copy.deepcopy(self.value);other['loader']['sha256']='UNKNOWN'
        self.assertFalse(e.runtime_binding_pass(other,other))

    def test_loader_cannot_have_recursive_interpreter(self):
        item={'path':'/usr/bin/python3.12'}
        with patch.object(e,'runtime_file',side_effect=[(item,elf()),({'path':'/usr/lib/loader'},elf())]):
            with self.assertRaisesRegex(RuntimeError,'RECURSIVE'):e.executable_binding('/usr/bin/python3')


class NoExecTests(unittest.TestCase):
    def evaluate(self,arch,number):
        pc=0;value=0;program=e.no_exec_instructions()
        for _ in range(32):
            op,jt,jf,k=program[pc]
            if op==32:value={4:arch,0:number}[k];pc+=1
            elif op==21:pc+=1+(jt if value==k else jf)
            elif op==53:pc+=1+(jt if value>=k else jf)
            elif op==6:return k
            else:self.fail('Unexpected instruction')
        self.fail('No terminal result')

    def test_both_exec_syscalls_denied(self):
        for nr in (59,322):self.assertEqual(self.evaluate(0xc000003e,nr),0x50001)

    def test_alternate_abi_denied(self):
        self.assertEqual(self.evaluate(0xc000003e,0x40000000|59),0x50001)

    def test_other_architecture_killed(self):
        self.assertEqual(self.evaluate(0x40000003,11),0x80000000)

    def test_existing_nonexec_filter_remains_responsible(self):
        self.assertEqual(self.evaluate(0xc000003e,1),0x7fff0000)
        self.assertEqual(self.evaluate(0xc000003e,41),0x7fff0000)

    def test_no_new_privs_install_failure_is_hard(self):
        with self.assertRaisesRegex(RuntimeError,'NO_NEW_PRIVS_FAILED'):
            e.install_no_exec(SimpleNamespace(prctl=lambda *args:1))

    def test_filter_install_failure_is_hard(self):
        def prctl(op,*args):return -1 if op==22 else 0
        with self.assertRaisesRegex(RuntimeError,'NO_EXEC_FILTER_FAILED'):e.install_no_exec(SimpleNamespace(prctl=prctl))

    def test_filter_readback_required(self):
        with self.assertRaisesRegex(RuntimeError,'NOT_PROVEN'):
            e.install_no_exec(SimpleNamespace(prctl=lambda *args:0))

    def test_exact_gate_evidence(self):
        v={'installed':True,'no_new_privs':True,'seccomp_mode':2,'architecture':'x86_64'}
        self.assertTrue(e.fresh_exec_gate_pass(v))
        for k,val in (('installed',1),('no_new_privs',False),('seccomp_mode',True),('architecture','unknown')):
            other=dict(v);other[k]=val
            self.assertFalse(e.fresh_exec_gate_pass(other))


class RuntimeAliasTests(unittest.TestCase):
    def test_known_aliases_preserve_layout(self):
        self.assertEqual(e.runtime_alias_target('/lib','usr/lib'),'usr/lib')
        self.assertEqual(e.runtime_alias_target('/lib64','/usr/lib64'),'/usr/lib64')

    def test_unknown_aliases_cannot_escape_root(self):
        for host,target in (('/lib','../../tmp'),('/lib64','/tmp'),('/usr','/lib'),('/lib','usr/lib64')):
            with self.subTest(host=host,target=target),self.assertRaises(RuntimeError):e.runtime_alias_target(host,target)
