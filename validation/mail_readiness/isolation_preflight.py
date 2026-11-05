"""Fixed synthetic CI controls and optional offline mail cases; no product authority."""
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
from execution_boundary import executable_binding, runtime_binding_pass, fresh_exec_gate_pass, runtime_alias_target
from result_contract import controls_pass, failure_summary, namespace_launch_prefix, namespace_mapping_args, supported_unshare_version, namespace_identity_pass, fresh_identity_pass
from offline_mail_contract import stage_source, canonical, result_pass, result_structure_pass, bounded_result

PYTHON = str(Path(sys.executable).resolve())
GIT = '/usr/bin/git'
SETUP_STAGE = 'NAMESPACE_LAUNCH'
CONTROLLER_SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def kernel_restrictions(loader):
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
        for executable in (PYTHON, loader):
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


def inside(temporary, host_uid, host_gid, offline_mail=False, expected_head=None):
    global SETUP_STAGE
    SETUP_STAGE = 'NAMESPACE_IDENTITY'
    if any(type(value) is not int or not 1 <= value <= 2147483647 for value in (host_uid, host_gid)):
        raise RuntimeError('CI_OWNER_ID_INVALID')
    # Supplementary groups were cleared before unshare; the fixed mapping guard must deny setgroups before gid_map.
    if os.getgroups():
        raise RuntimeError('SUPPLEMENTARY_GROUPS_NOT_EMPTY')
    os.setresgid(0, 0, 0)
    identity = {
        'uids': list(os.getresuid()), 'gids': list(os.getresgid()), 'groups': os.getgroups(),
        'uid_map': [[int(x) for x in line.split()] for line in Path('/proc/self/uid_map').read_text().splitlines()],
        'gid_map': [[int(x) for x in line.split()] for line in Path('/proc/self/gid_map').read_text().splitlines()],
        'setgroups_denied': Path('/proc/self/setgroups').read_text().strip() == 'deny',
    }
    if not namespace_identity_pass(identity, host_uid, host_gid):
        raise RuntimeError('NAMESPACE_IDENTITY_MISMATCH')
    SETUP_STAGE = 'SOURCE_OWNER_BINDING'
    base = Path(temporary).resolve(strict=True)
    if base.stat().st_uid != os.geteuid() or base.stat().st_gid != os.getegid() or os.geteuid() != 0:
        raise RuntimeError('SOURCE_OWNER_BINDING_MISMATCH')
    SETUP_STAGE = 'RUNTIME_BINDING'
    expected_runtime = json.loads((base / 'runtime-binding.json').read_bytes())
    execution_source = Path(__file__).with_name('execution_boundary.py').read_text()
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
        if Path(host).is_symlink():
            alias = runtime_alias_target(host,os.readlink(host))
            target.rmdir()
            target.symlink_to(alias)
            continue
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
    SETUP_STAGE = 'RUNTIME_BINDING'
    observed_runtime = executable_binding(PYTHON, host_owner=False)
    if not runtime_binding_pass(expected_runtime, observed_runtime):
        raise RuntimeError('RUNTIME_BINDING_MISMATCH')
    loader = observed_runtime['loader']['path']
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
    abi = kernel_restrictions(loader)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin', HOME='/tmp', TMPDIR='/tmp',
                      PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    probe = r"""
import ctypes, errno, json, os, pathlib, socket, subprocess, sys
fresh_exec_gate = install_no_exec()
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
denied('loader_shell_exec_denied', lambda: subprocess.run([sys.argv[2], '/usr/bin/dash', '-c', 'exit 0'], check=True), {errno.EPERM})
libc = ctypes.CDLL(None,use_errno=True)
libc.syscall.restype = ctypes.c_long
argv = (ctypes.c_char_p * 4)(b'/usr/bin/dash', b'-c', b'exit 0', None)
envp = (ctypes.c_char_p * 1)(None)
ctypes.set_errno(0)
controls['execve_denied'] = libc.syscall(59, ctypes.c_char_p(b'/usr/bin/dash'), argv, envp) == -1 and ctypes.get_errno() == errno.EPERM
ctypes.set_errno(0)
controls['execveat_denied'] = libc.syscall(322, ctypes.c_long(-100), ctypes.c_char_p(b'/usr/bin/dash'), argv, envp, 0) == -1 and ctypes.get_errno() == errno.EPERM
denied('chroot_denied', lambda: os.chroot('/'), {errno.EPERM, errno.EACCES})
libc = ctypes.CDLL(None, use_errno=True)
controls['namespace_escape_denied'] = libc.unshare(0x20000) == -1
pathlib.Path('/tmp/synthetic').write_bytes(b'synthetic-only')
controls['scratch_write_allowed'] = pathlib.Path('/tmp/synthetic').read_bytes() == b'synthetic-only'
try:
    os.setgroups([])
except PermissionError as error:
    setgroups_denied = error.errno == errno.EPERM
else:
    setgroups_denied = False
fresh_identity = {'uids':list(os.getresuid()), 'gids':list(os.getresgid()),
                  'groups':os.getgroups(), 'setgroups_denied':setgroups_denied}
offline_mail_result = None
if sys.argv[3] == 'offline-mail-v1':
    sys.path.insert(0, '/source')
    from offline_mail_contract import preconditions_pass, verify_payload
    if not preconditions_pass(controls, fresh_identity, fresh_exec_gate):
        raise RuntimeError('OFFLINE_MAIL_PRECONDITIONS_FAILED')
    binding = verify_payload(pathlib.Path('/source'), sys.argv[4])
    from offline_mail_cases import run
    offline_mail_result = run(binding)
    if verify_payload(pathlib.Path('/source'), sys.argv[4]) != binding:
        raise RuntimeError('OFFLINE_MAIL_SOURCE_BINDING_MISMATCH')
print(json.dumps({'controls':controls, 'fresh_identity':fresh_identity, 'fresh_exec_gate':fresh_exec_gate,
                  'offline_mail':offline_mail_result}, sort_keys=True))
"""
    if not Path('/usr/bin/dash').is_file():
        raise RuntimeError('NEGATIVE_EXECUTABLE_NOT_PRESENT')
    SETUP_STAGE = 'FRESH_CHILD_CONTROLS'
    child = subprocess.run([PYTHON, '-I', '-B', '-c', execution_source + '\n' + probe, str(base / 'outside-canary'), loader,
                            'offline-mail-v1' if offline_mail else 'controls-only', expected_head or ''],
                           capture_output=True, text=True, timeout=15, check=True)
    payload = json.loads(child.stdout)
    print(json.dumps({'controls': payload['controls'], 'landlock_abi': abi,
                      'namespace_identity':identity, 'fresh_identity':payload['fresh_identity'],
                      'runtime_binding':observed_runtime, 'fresh_exec_gate':payload['fresh_exec_gate'],
                      'offline_mail':payload['offline_mail']}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inside')
    parser.add_argument('--inside-host-uid', type=int)
    parser.add_argument('--inside-host-gid', type=int)
    parser.add_argument('--privileged-namespace-bootstrap', action='store_true')
    parser.add_argument('--expected-head')
    parser.add_argument('--offline-mail', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.inside:
        try:
            inside(args.inside, args.inside_host_uid, args.inside_host_gid, args.offline_mail, args.expected_head)
            return 0
        except BaseException as error:
            print(json.dumps({'stage':SETUP_STAGE, 'error': type(error).__name__, 'errno': getattr(error, 'errno', None)}))
            return 2
    if args.output is None:
        parser.error('--output is required')
    report = {'schema':'usbay.synthetic_isolation_preflight.v2', 'status':'FAILED',
              'application_tests_run':False, 'application_execution_enabled':False,
              'production_ready':False, 'source_verified':False,
              'controller_source_sha256':CONTROLLER_SOURCE_SHA256,
              'python':sys.version.split()[0], 'controls':{},
              'limits':['Bounded synthetic controls and optional fixed offline cases; not an exhaustive sandbox proof.',
                        'Not the 475-case suite, Gitless/startup tests, replay/fork suite or production readiness.']}
    report['application_execution_enabled'] = args.offline_mail
    report['application_execution_scope'] = 'fixed_synthetic_offline_mail_only' if args.offline_mail else 'none'
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
        expected_runtime = executable_binding(PYTHON, host_owner=True)
        report['runtime_binding'] = expected_runtime
        if os.uname().machine != 'x86_64':
            raise RuntimeError('UNSUPPORTED_ARCHITECTURE')
        owner_uid, owner_gid = os.geteuid(), os.getegid()
        mapping = namespace_mapping_args(args.privileged_namespace_bootstrap, owner_uid, owner_gid)
        if args.privileged_namespace_bootstrap:
            version = subprocess.check_output(['/usr/bin/unshare', '--version'], text=True, stderr=subprocess.DEVNULL, timeout=5)
            if not supported_unshare_version(version):
                raise RuntimeError('UNSHARE_VERSION_UNSUPPORTED')
            report['unshare_version'] = version.strip().rsplit(' ', 1)[1]
            report['namespace_mapping'] = {'host_uid':owner_uid, 'host_gid':owner_gid, 'inner_uid':0, 'inner_gid':0, 'count':1}
            report['mapping_helpers_present'] = {'uid':shutil.which('newuidmap', path='/usr/bin:/bin') is not None, 'gid':shutil.which('newgidmap', path='/usr/bin:/bin') is not None}
        with tempfile.TemporaryDirectory(prefix='usbay-synthetic-preflight-') as name:
            base = Path(name)
            for relative in ('root/usr', 'root/lib', 'root/lib64', 'root/source',
                             'root/tmp', 'root/proc', 'root/dev', 'source'):
                (base / relative).mkdir(parents=True)
            (base / 'runtime-binding.json').write_text(json.dumps(expected_runtime, sort_keys=True))
            (base / 'runtime-binding.json').chmod(0o600)
            (base / 'source/synthetic.py').write_text('# Synthetic source canary.\n')
            if args.offline_mail:
                expected_mail = stage_source(repository, actual, base / 'source')
                report['offline_mail_source_binding'] = hashlib.sha256(canonical(expected_mail)).hexdigest()
            (base / 'outside-canary').write_bytes(b'synthetic-only')
            for device in ('null', 'urandom'):
                (base / 'root/dev' / device).touch()
            env = {'PATH':'/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE':'1'}
            if args.privileged_namespace_bootstrap:
                argv = ['/usr/bin/sudo', '--non-interactive', '--', '/usr/bin/python3', '-I', '-B',
                        str(Path(__file__).resolve().with_name('runner_bootstrap.py')),
                        '--expected-head', actual, '--uid', str(owner_uid), '--gid', str(owner_gid),
                        '--temporary', str(base)]
                if args.offline_mail:
                    argv.append('--offline-mail')
            else:
                argv = [*namespace_launch_prefix(False), *mapping, '--net', '--mount', '--pid', '--fork',
                        PYTHON, '-I', '-B', str(Path(__file__).resolve()), '--inside', str(base),
                        '--inside-host-uid', str(owner_uid), '--inside-host-gid', str(owner_gid)]
                if args.offline_mail:
                    argv.extend(['--offline-mail', '--expected-head', actual])
            child = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=65)
            report['child_exit'] = child.returncode
            if child.returncode != 0:
                report['reason'] = 'ISOLATION_SETUP_OR_CHILD_FAILED'
                report['failure'] = failure_summary(child.stdout, child.stderr)
            else:
                payload = json.loads(child.stdout)
                report['controls'] = payload.get('controls')
                report['landlock_abi'] = payload.get('landlock_abi')
                report['fresh_exec_gate'] = payload.get('fresh_exec_gate')
                report['runtime_binding_verified'] = runtime_binding_pass(expected_runtime, payload.get('runtime_binding'))
                report['namespace_identity'] = payload.get('namespace_identity')
                report['fresh_identity'] = payload.get('fresh_identity')
                report['mapping_policy_restored'] = payload.get('mapping_policy_restored', False)
                mail = payload.get('offline_mail')
                mail_passed = args.offline_mail and result_pass(mail, report['offline_mail_source_binding'])
                mail_execution_proven = args.offline_mail and result_structure_pass(mail, report['offline_mail_source_binding'])
                report['offline_mail_validation_passed'] = mail_passed
                report['offline_mail'] = bounded_result(mail)
                report['application_tests_run'] = mail_execution_proven
                report['application_test_execution_evidence'] = ('COMPLETE' if mail_execution_proven else
                                                               'UNKNOWN' if args.offline_mail else 'NOT_REQUESTED')
                if (controls_pass(report['controls'])
                        and fresh_exec_gate_pass(report['fresh_exec_gate'])
                        and report['runtime_binding_verified'] is True
                        and namespace_identity_pass(report['namespace_identity'], owner_uid, owner_gid)
                        and fresh_identity_pass(report['fresh_identity'])
                        and report['mapping_policy_restored'] is True):
                    if args.offline_mail and not mail_passed:
                        report['reason'] = 'OFFLINE_MAIL_CASE_SET_INCOMPLETE_OR_FAILED'
                    else:
                        report['status'] = 'FIXED_OFFLINE_MAIL_CASES_PASSED' if args.offline_mail else 'SYNTHETIC_CONTROL_SET_PASSED'
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
