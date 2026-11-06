"""Synthetic-only fixed ELF startup and inherited no-exec boundary."""
import ctypes
import hashlib
import os
from pathlib import Path
import re
import stat
import struct

MAX_ELF_BYTES = 64 * 1024 * 1024


def elf_interpreter(data, required=True):
    if type(data) is not bytes or not 64 <= len(data) <= MAX_ELF_BYTES:
        raise RuntimeError('ELF_INVALID')
    if data[:7] != b'\x7fELF\x02\x01\x01':
        raise RuntimeError('ELF_FORMAT_UNSUPPORTED')
    kind, machine, version = struct.unpack_from('<HHI', data, 16)
    offset = struct.unpack_from('<Q', data, 32)[0]
    header_size, entry_size, count = struct.unpack_from('<HHH', data, 52)
    if kind not in (2,3) or machine != 62 or version != 1 or header_size != 64:
        raise RuntimeError('ELF_FORMAT_UNSUPPORTED')
    if entry_size != 56 or not 1 <= count <= 128 or offset < 64 or offset + count * 56 > len(data):
        raise RuntimeError('ELF_HEADERS_INVALID')
    found = []
    for index in range(count):
        entry = offset + index * 56
        if struct.unpack_from('<I', data, entry)[0] != 3:
            continue
        start = struct.unpack_from('<Q', data, entry + 8)[0]
        size = struct.unpack_from('<Q', data, entry + 32)[0]
        if not 2 <= size <= 256 or start < offset + count * 56 or start + size > len(data):
            raise RuntimeError('ELF_INTERPRETER_INVALID')
        raw = data[start:start+size]
        if raw[-1:] != b'\0' or b'\0' in raw[:-1]:
            raise RuntimeError('ELF_INTERPRETER_INVALID')
        try:
            name = raw[:-1].decode('ascii')
        except UnicodeError:
            raise RuntimeError('ELF_INTERPRETER_INVALID') from None
        if (not re.fullmatch(r'/(?:lib|lib64|usr/lib|usr/lib64)/[A-Za-z0-9_./+-]+', name)
                or '..' in name.split('/') or '//' in name):
            raise RuntimeError('ELF_INTERPRETER_INVALID')
        found.append(name)
    if len(found) > 1 or required and len(found) != 1:
        raise RuntimeError('ELF_INTERPRETER_COUNT_INVALID')
    return found[0] if found else None


def runtime_file(path, host_owner):
    original = Path(path)
    canonical = original.resolve(strict=True)
    fd = os.open(canonical, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or st.st_mode & 0o6022
                or host_owner and st.st_uid != 0 or not 64 <= st.st_size <= MAX_ELF_BYTES):
            raise RuntimeError('RUNTIME_FILE_UNSAFE')
        chunks = []
        remaining = MAX_ELF_BYTES + 1
        while remaining:
            block = os.read(fd, min(1048576,remaining))
            if not block:break
            chunks.append(block);remaining -= len(block)
        data = b''.join(chunks)
        after = os.fstat(fd)
        fields = lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mode,value.st_mtime_ns,value.st_ctime_ns)
        if len(data) != st.st_size or fields(st) != fields(after) or original.resolve(strict=True) != canonical:
            raise RuntimeError('RUNTIME_FILE_CHANGED')
        info = {'path':str(canonical), 'sha256':hashlib.sha256(data).hexdigest(),
                'device':st.st_dev,'inode':st.st_ino,'size':st.st_size,'mode':stat.S_IMODE(st.st_mode)}
        return info,data
    finally:os.close(fd)


def executable_binding(executable, host_owner=True):
    if type(host_owner) is not bool:
        raise RuntimeError('RUNTIME_OWNER_MODE_INVALID')
    python, data = runtime_file(executable,host_owner)
    if not re.fullmatch(r'/usr/bin/python3(?:\.[0-9]+)?', python['path']):
        raise RuntimeError('PYTHON_EXECUTABLE_UNSUPPORTED')
    interpreter = elf_interpreter(data)
    loader, data = runtime_file(interpreter,host_owner)
    if not loader['path'].startswith(('/usr/lib/','/usr/lib64/','/lib/','/lib64/')):
        raise RuntimeError('ELF_INTERPRETER_INVALID')
    if elf_interpreter(data,required=False) is not None:
        raise RuntimeError('RECURSIVE_ELF_INTERPRETER')
    return {'schema':'usbay.synthetic_runtime_binding.v1','python':python,'loader':loader,'interpreter_path':interpreter}


def runtime_binding_pass(expected, observed):
    def valid(value):
        if type(value) is not dict or set(value) != {'schema','python','loader','interpreter_path'}:
            return False
        if value['schema'] != 'usbay.synthetic_runtime_binding.v1' or type(value['interpreter_path']) is not str:
            return False
        for name in ('python','loader'):
            item = value[name]
            if type(item) is not dict or set(item) != {'path','sha256','device','inode','size','mode'}:
                return False
            if type(item['path']) is not str or not item['path'].startswith('/'):
                return False
            if type(item['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',item['sha256']):
                return False
            if any(type(item[k]) is not int or item[k]<0 for k in ('device','inode','size','mode')):
                return False
        return True
    return valid(expected) and valid(observed) and expected == observed


def no_exec_instructions():
    # AUDIT_ARCH_X86_64, reject alternate ABI, execve and execveat.
    return [(32,0,0,4),(21,1,0,0xc000003e),(6,0,0,0x80000000),
            (32,0,0,0),(53,0,1,0x40000000),(6,0,0,0x50001),
            (21,0,1,59),(6,0,0,0x50001),(21,0,1,322),(6,0,0,0x50001),
            (6,0,0,0x7fff0000)]


def install_no_exec(libc=None):
    if os.uname().machine != 'x86_64':
        raise RuntimeError('UNSUPPORTED_SECCOMP_ARCH')
    libc = libc if libc is not None else ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0):
        raise RuntimeError('NO_NEW_PRIVS_FAILED')
    class Filter(ctypes.Structure):
        _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
    instructions=no_exec_instructions()
    filters=(Filter*len(instructions))(*(Filter(*item) for item in instructions))
    program=Program(len(instructions),filters)
    if libc.prctl(22,2,ctypes.byref(program),0,0):
        raise RuntimeError('NO_EXEC_FILTER_FAILED')
    if libc.prctl(39,0,0,0,0)!=1 or libc.prctl(21,0,0,0,0)!=2:
        raise RuntimeError('NO_EXEC_FILTER_NOT_PROVEN')
    return {'installed':True,'no_new_privs':True,'seccomp_mode':2,'architecture':'x86_64'}


def fresh_exec_gate_pass(value):
    return (type(value) is dict and set(value)=={'installed','no_new_privs','seccomp_mode','architecture'}
            and value['installed'] is True and value['no_new_privs'] is True
            and type(value['seccomp_mode']) is int and value['seccomp_mode']==2
            and value['architecture']=='x86_64')


def runtime_alias_target(host, target):
    expected={'/lib':'usr/lib','/lib64':'usr/lib64'}
    if host not in expected or target not in (expected[host],'/'+expected[host]):
        raise RuntimeError('RUNTIME_ALIAS_UNSUPPORTED')
    return target
