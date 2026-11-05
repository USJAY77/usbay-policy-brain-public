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


FAILURE_STAGES = frozenset({'EPHEMERAL_MAPPING_BOOTSTRAP', 'NAMESPACE_IDENTITY', 'SOURCE_OWNER_BINDING', 'NAMESPACE_LAUNCH', 'MOUNT_NAMESPACE_PRIVATE',
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
    launcher_codes = payload.get('launcher_categories', [])
    permitted_codes = {'UID_MAP_HELPER_ERROR','GID_MAP_HELPER_ERROR','ID_RANGE_NOT_ALLOWED',
                       'SETGROUPS_FAILED','SETUID_FAILED','SETGID_FAILED', 'UNSHARE_FAILED','PERMISSION_DENIED',
                       'OPERATION_NOT_PERMITTED','WRITE_FAILED','SETGROUPS_PATH','UID_MAP_PATH','GID_MAP_PATH',
                       'EXEC_FAILED','FILE_NOT_FOUND','MODULE_NOT_FOUND','IMPORT_FAILED','PYTHON_STARTUP_FAILED',
                       'PYTHON_FILE_OPEN_FAILED','MOUNT_FAILED','MOUNT_PROPAGATION_FAILED','FORK_FAILED',
                       'ARGUMENT_INVALID','MAPPING_INVALID','OPTION_UNRECOGNIZED'}
    if type(launcher_codes) is not list:
        launcher_codes = []
    bootstrap_reason = payload.get('bootstrap_reason')
    allowed_reasons = {
        'CI_OWNER_ID_INVALID','MAPPING_POLICY_INVALID','MAPPING_POLICY_AMBIGUOUS',
        'MAPPING_POLICY_FILE_UNSAFE','MAPPING_POLICY_CHANGED','MAPPING_POLICY_WRITE_FAILED',
        'MAPPING_POLICY_RESTORE_FAILED','EXPECTED_HEAD_REQUIRED','SOURCE_OWNER_BINDING_MISMATCH',
        'SOURCE_HEAD_MISMATCH','SOURCE_FILE_UNSAFE','SOURCE_BYTES_MISMATCH','BOOTSTRAP_ROOT_REQUIRED',
        'BOOTSTRAP_CALLER_MISMATCH','TEMPORARY_PATH_INVALID','TEMPORARY_OWNER_MISMATCH',
        'BOOTSTRAP_LOCK_UNSAFE','SUPPLEMENTARY_GROUPS_NOT_EMPTY','BOOTSTRAP_RESULT_INVALID','BOOTSTRAP_ERROR'}
    return {
        'mapping_policy_restored': payload.get('mapping_policy_restored') is True,
        'launcher_exit': payload.get('launcher_exit') if type(payload.get('launcher_exit')) is int and -255 <= payload['launcher_exit'] <= 255 else None,
        'bootstrap_reason':bootstrap_reason if type(bootstrap_reason) is str and bootstrap_reason in allowed_reasons else 'UNKNOWN',
        'stage': stage if type(stage) is str and stage in FAILURE_STAGES else 'UNKNOWN',
        'error_type': error if type(error) is str and error in FAILURE_TYPES else 'UNKNOWN',
        'errno': code if type(code) is int else None,
        'stderr_categories': [item for item in ERROR_CATEGORIES if item in safe_stderr],
        'launcher_categories': [name for name, matched in (
            ('UID_MAP_HELPER_ERROR', 'newuidmap' in safe_stderr),
            ('GID_MAP_HELPER_ERROR', 'newgidmap' in safe_stderr),
            ('ID_RANGE_NOT_ALLOWED', 'not allowed' in safe_stderr and ('uid range' in safe_stderr or 'gid range' in safe_stderr)),
            ('SETGROUPS_FAILED', 'setgroups failed' in safe_stderr),
            ('SETUID_FAILED', 'setuid failed' in safe_stderr),
            ('SETGID_FAILED', 'setgid failed' in safe_stderr),
            ('MAPPING_ARGUMENT_INVALID', 'invalid mapping' in safe_stderr),
            ('OPTION_UNRECOGNIZED', 'unrecognized option' in safe_stderr),
        ) if matched] + sorted({x for x in launcher_codes if type(x) is str and x in permitted_codes}),
    }



def namespace_launch_prefix(privileged):
    """Fixed argv for an explicitly selected CI mode; not an authority grant."""
    if type(privileged) is not bool:
        raise ValueError('BOOTSTRAP_MODE_INVALID')
    if privileged:
        raise ValueError('USE_EPHEMERAL_MAPPING_BOOTSTRAP')
    return ['/usr/bin/unshare']



def namespace_mapping_args(privileged, uid, gid):
    if type(privileged) is not bool:
        raise ValueError('BOOTSTRAP_MODE_INVALID')
    if not privileged:
        return ['--user', '--map-root-user']
    if any(type(value) is not int or not 1 <= value <= 2147483647 for value in (uid, gid)):
        raise ValueError('CI_OWNER_ID_INVALID')
    return ['--user', f'--map-users=0:{uid}:1', f'--map-groups=0:{gid}:1',
            '--setgroups=deny', '--setuid=0']


def supported_unshare_version(text):
    import re
    if type(text) is not str or len(text) > 256:
        return False
    match = re.fullmatch(r'unshare from util-linux (2)\.([0-9]+)(?:\.[0-9]+)?(?:[\s]+)?', text)
    return bool(match and int(match.group(2)) >= 39)


def fresh_identity_pass(value):
    if type(value) is not dict or set(value) != {'uids', 'gids', 'groups', 'setgroups_denied'}:
        return False
    return (all(type(value.get(k)) is list and len(value[k]) == 3
                and all(type(x) is int and x == 0 for x in value[k]) for k in ('uids','gids'))
            and type(value['groups']) is list and value['groups'] == []
            and value['setgroups_denied'] is True)


def namespace_identity_pass(value, uid, gid):
    if any(type(x) is not int or not 1 <= x <= 2147483647 for x in (uid,gid)):
        return False
    if type(value) is not dict or set(value) != {'uids','gids','groups','setgroups_denied','uid_map','gid_map'}:
        return False
    for name, host in (('uid_map', uid), ('gid_map', gid)):
        mapping = value[name]
        if (type(mapping) is not list or len(mapping) != 1 or type(mapping[0]) is not list
                or len(mapping[0]) != 3 or any(type(x) is not int for x in mapping[0])
                or mapping != [[0, host, 1]]):
            return False
    return fresh_identity_pass({k:value[k] for k in ('uids','gids','groups','setgroups_denied')})
