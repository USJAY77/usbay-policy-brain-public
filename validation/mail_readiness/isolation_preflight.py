"""Synthetic CI isolation preflight. Never runs application tests or grants authority."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_contract import controls_pass, failure_summary, namespace_launch_prefix

PYTHON = str(Path(sys.executable).resolve())
GIT = '/usr/bin/git'
SETUP_STAGE = 'NAMESPACE_LAUNCH'
CONTROLLER_SOURCE_SHA256 = '16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c'

def kernel_restrictions():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def call(number, *args):
        result = libc.syscall(number, *args)
        if result < 0:
            raise OSError(ctypes.get_errno(), 'SANDBOX_KERNEL_CALL_FAILED')
        return result
    if libc.prctl(38, 1, 0, 0, 0):
        raise RuntimeError('NO_NEW_PRIVS_FAILED')
    abi = call(444, 0, 0, 1)
    attr = ctypes.create_string_buffer(struct.pack('=Q', 1))
    fd = call(444, ctypes.byref(attr), 8, 0)
    try:
        for executable in (PYTHON, GIT):
            parent = os.open(executable, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = ctypes.create_string_buffer(struct.pack('=Qi', 1, parent))
                call(445, fd, 1, ctypes.byref(rule), 0)
            finally:
                os.close(parent)
        call(446, fd, 0)
    finally:
        os.close(fd)
    if os.uname().machine != 'x86_64':
        raise RuntimeError('UNSUPPORTED_SECCOMP_ARCH')
    instructions = [(32, 0, 0, 4), (21, 1, 0, 3221225534), (6, 0, 0, 2147483648), (32, 0, 0, 0), (53, 0, 1, 1073741824), (6, 0, 0, 327681)]
    denied = [41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 53, 54, 55, 101, 155, 161, 165, 166, 272, 304, 308, 321, 428, 429, 430, 431, 432, 442]
    for number in denied:
        instructions.extend([(21, 0, 1, number), (6, 0, 0, 327681)])
    instructions.append((6, 0, 0, 2147418112))

    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]

    class Program(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
    filters = (Filter * len(instructions))(*(Filter(*i) for i in instructions))
    program = Program(len(instructions), filters)
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise RuntimeError('SECCOMP_FAILED')
    return abi


def inside(temporary):
    global SETUP_STAGE
    base = Path(temporary).resolve(strict=True)
    root = base / 'root'
    if not PYTHON.startswith('/usr/') or os.uname().machine != 'x86_64':
        raise RuntimeError('UNSUPPORTED_RUNTIME_LAYOUT')
    def mount(*args):
        subprocess.run(['/usr/bin/mount', *map(str, args)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    SETUP_STAGE = 'MOUNT_NAMESPACE_PRIVATE'
    mount('--make-rprivate', '/')
    SETUP_STAGE = 'RUNTIME_BIND'
    for host in ('/usr', '/lib', '/lib64'):
        if not Path(host).exists():
            continue
        target = root / host.lstrip('/')
        mount('--bind', host, target)
        mount('-o', 'remount,bind,ro,nosuid,nodev', target)
    SETUP_STAGE = 'SOURCE_BIND'
    mount('--bind', base / 'source', root / 'source')
    mount('-o', 'remount,bind,ro,nosuid,nodev', root / 'source')
    SETUP_STAGE = 'DEVICE_BIND'
    for name in ('null', 'urandom'):
        mount('--bind', '/dev/' + name, root / 'dev' / name)
    SETUP_STAGE = 'CHROOT'
    os.chdir(root)
    os.chroot('.')
    os.chdir('/source')
    os.closerange(3, os.sysconf('SC_OPEN_MAX'))
    os.close(0)
    if os.open('/dev/null', os.O_RDONLY) != 0:
        raise RuntimeError('STDIN_SANITIZATION_FAILED')
    SETUP_STAGE = 'DROP_CAPABILITIES'
    libc = ctypes.CDLL(None, use_errno=True)
    for cap in range(41):
        if libc.prctl(24, cap, 0, 0, 0):
            raise RuntimeError('DROP_BOUNDING_CAPABILITY_FAILED')
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint), ('permitted', ctypes.c_uint), ('inheritable', ctypes.c_uint)]
    if libc.capset(ctypes.byref(Header(0x20080522, 0)), ctypes.byref((Data * 2)())):
        raise RuntimeError('DROP_CAPABILITIES_FAILED')
    SETUP_STAGE = 'KERNEL_RESTRICTIONS'
    abi = kernel_restrictions()
    os.environ.clear()
    os.environ.update(PATH='/usr/bin', HOME='/tmp', TMPDIR='/tmp',
                      PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    probe = r"""
import ctypes, errno, json, os, pathlib, socket, subprocess, sys
controls = {}
def denied(name, operation, allowed_errors):
    try:
        operation()
    except OSError as error:
        controls[name] = error.errno in allowed_errors
    else:
        controls[name] = False
access_denied = {errno.EPERM, errno.EACCES, errno.EROFS}
controls['source_read_allowed'] = pathlib.Path('/source/synthetic.py').read_bytes() == b'# Synthetic source canary.\n'
runtime_file = pathlib.Path(pathlib.__file__)
if not runtime_file.is_file():
    raise RuntimeError('RUNTIME_READ_CANARY_MISSING')
runtime_file.read_bytes()
denied('source_write_denied', lambda: open('/source/synthetic.py', 'a'), access_denied)
denied('runtime_write_denied', lambda: open(runtime_file, 'a'), access_denied)
denied('host_file_read_denied', lambda: open(sys.argv[1], 'rb'), access_denied | {errno.ENOENT})
denied('host_process_metadata_denied', lambda: open('/proc/1/environ', 'rb'), access_denied | {errno.ENOENT})
denied('network_denied', lambda: socket.socket(), {errno.EPERM, errno.EACCES})
denied('shell_exec_denied', lambda: subprocess.run(['/usr/bin/dash', '-c', 'exit 0'], check=True), {errno.EPERM, errno.EACCES})
denied('chroot_denied', lambda: os.chroot('/'), {errno.EPERM, errno.EACCES})
libc = ctypes.CDLL(None, use_errno=True)
controls['namespace_escape_denied'] = libc.unshare(0x20000) == -1
pathlib.Path('/tmp/synthetic').write_bytes(b'synthetic-only')
controls['scratch_write_allowed'] = pathlib.Path('/tmp/synthetic').read_bytes() == b'synthetic-only'
print(json.dumps(controls, sort_keys=True))
"""
    if not Path('/usr/bin/dash').is_file():
        raise RuntimeError('NEGATIVE_EXECUTABLE_NOT_PRESENT')
    SETUP_STAGE = 'FRESH_CHILD_CONTROLS'
    child = subprocess.run([PYTHON, '-I', '-B', '-c', probe, str(base / 'outside-canary')],
                           capture_output=True, text=True, timeout=15, check=True)
    controls = json.loads(child.stdout)
    print(json.dumps({'controls': controls, 'landlock_abi': abi}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inside')
    parser.add_argument('--privileged-namespace-bootstrap', action='store_true')
    parser.add_argument('--expected-head')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.inside:
        try:
            inside(args.inside)
            return 0
        except BaseException as error:
            print(json.dumps({'stage':SETUP_STAGE, 'error': type(error).__name__, 'errno': getattr(error, 'errno', None)}))
            return 2
    if args.output is None:
        parser.error('--output is required')
    report = {'schema':'usbay.synthetic_isolation_preflight.v1', 'status':'FAILED',
              'application_tests_run':False, 'application_execution_enabled':False,
              'production_ready':False, 'source_verified':False,
              'controller_source_sha256':CONTROLLER_SOURCE_SHA256,
              'python':sys.version.split()[0], 'controls':{},
              'limits':['Bounded synthetic controls only; not an exhaustive sandbox proof.',
                        'Not wired to the 475-case mail suite or the replay/fork suite.']}
    report['namespace_bootstrap_mode'] = ('explicit_ephemeral_ci_sudo' if args.privileged_namespace_bootstrap else 'unprivileged_user_namespace')
    exit_code = 2
    try:
        if not re.fullmatch('[0-9a-f]{40}', args.expected_head or ''):
            raise RuntimeError('EXPECTED_HEAD_REQUIRED')
        repository = Path(__file__).resolve().parents[2]
        actual = subprocess.check_output([GIT, 'rev-parse', 'HEAD'], cwd=repository,
                                         text=True, stderr=subprocess.DEVNULL, timeout=5).strip()
        if actual != args.expected_head:
            raise RuntimeError('SOURCE_HEAD_MISMATCH')
        report.update(source_verified=True, head=actual)
        if os.uname().machine != 'x86_64':
            raise RuntimeError('UNSUPPORTED_ARCHITECTURE')
        with tempfile.TemporaryDirectory(prefix='usbay-synthetic-preflight-') as name:
            base = Path(name)
            for relative in ('root/usr', 'root/lib', 'root/lib64', 'root/source',
                             'root/tmp', 'root/proc', 'root/dev', 'source'):
                (base / relative).mkdir(parents=True)
            (base / 'source/synthetic.py').write_text('# Synthetic source canary.\n')
            (base / 'outside-canary').write_bytes(b'synthetic-only')
            for device in ('null', 'urandom'):
                (base / 'root/dev' / device).touch()
            env = {'PATH':'/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE':'1'}
            child = subprocess.run([*namespace_launch_prefix(args.privileged_namespace_bootstrap), '--user', '--map-root-user', '--net',
                                    '--mount', '--pid', '--fork', PYTHON, '-I', '-B',
                                    str(Path(__file__).resolve()), '--inside', str(base)],
                                   env=env, capture_output=True, text=True, timeout=60)
            report['child_exit'] = child.returncode
            if child.returncode != 0:
                report['reason'] = 'ISOLATION_SETUP_OR_CHILD_FAILED'
                report['failure'] = failure_summary(child.stdout, child.stderr)
            else:
                payload = json.loads(child.stdout)
                report['controls'] = payload.get('controls')
                report['landlock_abi'] = payload.get('landlock_abi')
                if controls_pass(report['controls']):
                    report['status'] = 'SYNTHETIC_CONTROL_SET_PASSED'
                    exit_code = 0
                else:
                    report['reason'] = 'CONTROL_SET_INCOMPLETE_OR_FAILED'
    except BaseException as error:
        report['reason'] = (str(error) if isinstance(error, RuntimeError)
                            else 'PREFLIGHT_CONTROLLER_ERROR')
        report['error_type'] = type(error).__name__
        report['errno'] = getattr(error, 'errno', None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
