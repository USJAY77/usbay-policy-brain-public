"""Non-authorizing completeness checks for synthetic validation evidence."""
REQUIRED_CONTROLS = frozenset({
    'source_read_allowed', 'source_write_denied', 'runtime_write_denied', 'host_file_read_denied',
    'host_process_metadata_denied', 'network_denied', 'shell_exec_denied',
    'chroot_denied', 'namespace_escape_denied', 'scratch_write_allowed',
})


def controls_pass(controls):
    return (type(controls) is dict and set(controls) == REQUIRED_CONTROLS
            and all(type(value) is bool and value for value in controls.values()))


def suite_pass(expected, groups, controller_exit):
    """Require complete, disjoint collection AND successful terminal reports.

    This is a future harness integration contract, not permission to run tests.
    """
    if type(controller_exit) is not int or controller_exit != 0:
        return False
    if not isinstance(expected, (list, tuple)) or not expected:
        return False
    if any(type(node) is not str or not node for node in expected):
        return False
    if len(set(expected)) != len(expected) or type(groups) is not list or not groups:
        return False
    wanted, seen = set(expected), set()
    for group in groups:
        if type(group) is not dict or type(group.get('exit')) is not int or group['exit'] != 0:
            return False
        ids, reports = group.get('collected_ids'), group.get('reports')
        subtests = group.get('subtests')
        if type(ids) is not list or not ids or any(type(node) is not str for node in ids):
            return False
        if len(set(ids)) != len(ids) or seen.intersection(ids) or not set(ids).issubset(wanted):
            return False
        if type(reports) is not dict or set(reports) != set(ids):
            return False
        if any(type(report) is not dict or report.get('outcome') != 'passed'
               or report.get('phase') != 'call' for report in reports.values()):
            return False
        if type(subtests) is not dict or set(subtests) - {'passed', 'failed', 'skipped'}:
            return False
        if any(type(count) is not int or count < 0 for count in subtests.values()):
            return False
        if subtests.get('failed', 0) or subtests.get('skipped', 0):
            return False
        seen.update(ids)
    return seen == wanted


FAILURE_STAGES = frozenset({'SOURCE_OWNER_BINDING', 'NAMESPACE_LAUNCH', 'MOUNT_NAMESPACE_PRIVATE',
    'RUNTIME_BIND', 'SOURCE_BIND', 'DEVICE_BIND', 'CHROOT', 'DROP_CAPABILITIES',
    'KERNEL_RESTRICTIONS', 'FRESH_CHILD_CONTROLS'})
FAILURE_TYPES = frozenset({'PermissionError', 'OSError', 'RuntimeError',
                          'CalledProcessError', 'TimeoutExpired'})
ERROR_CATEGORIES = ('Operation not permitted', 'Permission denied',
                    'No such file or directory', 'Read-only file system',
                    'unshare failed', 'write failed')


def failure_summary(stdout, stderr):
    import json
    payload = {}
    if type(stdout) is str and len(stdout) <= 16384:
        try:
            decoded = json.loads(stdout)
            if type(decoded) is dict:
                payload = decoded
        except (ValueError, TypeError):
            pass
    stage = payload.get('stage')
    error = payload.get('error')
    code = payload.get('errno')
    safe_stderr = stderr[:16384] if type(stderr) is str else ''
    return {
        'stage': stage if type(stage) is str and stage in FAILURE_STAGES else 'UNKNOWN',
        'error_type': error if type(error) is str and error in FAILURE_TYPES else 'UNKNOWN',
        'errno': code if type(code) is int else None,
        'stderr_categories': [item for item in ERROR_CATEGORIES if item in safe_stderr],
    }



def namespace_launch_prefix(privileged):
    """Fixed argv for an explicitly selected CI mode; not an authority grant."""
    if type(privileged) is not bool:
        raise ValueError('BOOTSTRAP_MODE_INVALID')
    if privileged:
        return ['/usr/bin/sudo', '--non-interactive', '--', '/usr/bin/unshare']
    return ['/usr/bin/unshare']



def namespace_mapping_args(privileged, uid, gid):
    if type(privileged) is not bool:
        raise ValueError('BOOTSTRAP_MODE_INVALID')
    if not privileged:
        return ['--user', '--map-root-user']
    if any(type(value) is not int or not 1 <= value <= 2147483647 for value in (uid, gid)):
        raise ValueError('CI_OWNER_ID_INVALID')
    return ['--user', f'--map-users=0:{uid}:1', f'--map-groups=0:{gid}:1',
            '--setgroups=deny', '--setuid=0', '--setgid=0']


def supported_unshare_version(text):
    import re
    if type(text) is not str or len(text) > 256:
        return False
    match = re.fullmatch(r'unshare from util-linux (2)\.([0-9]+)(?:\.[0-9]+)?(?:[\s]+)?', text)
    return bool(match and int(match.group(2)) >= 39)
