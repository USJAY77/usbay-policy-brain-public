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
