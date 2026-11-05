import copy
import unittest

from result_contract import REQUIRED_CONTROLS, controls_pass, suite_pass, failure_summary, namespace_launch_prefix, namespace_mapping_args, supported_unshare_version


class ResultContractTests(unittest.TestCase):
    def setUp(self):
        self.group = {'exit': 0, 'collected_ids': ['synthetic::a'],
                      'reports': {'synthetic::a': {'outcome': 'passed', 'phase': 'call'}},
                      'subtests': {'passed': 2}}

    def test_exact_positive_control_set(self):
        self.assertTrue(controls_pass(dict.fromkeys(REQUIRED_CONTROLS, True)))

    def test_empty_control_set_is_not_success(self):
        self.assertFalse(controls_pass({}))

    def test_missing_control_is_not_success(self):
        controls = dict.fromkeys(REQUIRED_CONTROLS, True)
        controls.pop('network_denied')
        self.assertFalse(controls_pass(controls))

    def test_non_boolean_control_is_not_success(self):
        controls = dict.fromkeys(REQUIRED_CONTROLS, True)
        controls['network_denied'] = 1
        self.assertFalse(controls_pass(controls))

    def test_failed_control_is_not_success(self):
        controls = dict.fromkeys(REQUIRED_CONTROLS, True)
        controls['shell_exec_denied'] = False
        self.assertFalse(controls_pass(controls))

    def test_complete_passing_group(self):
        self.assertTrue(suite_pass(['synthetic::a'], [self.group], 0))

    def test_partial_collection_fails(self):
        self.assertFalse(suite_pass(['synthetic::a', 'synthetic::b'], [self.group], 0))

    def test_missing_execution_report_fails(self):
        self.group['reports'] = {}
        self.assertFalse(suite_pass(['synthetic::a'], [self.group], 0))

    def test_group_failure_propagates(self):
        self.group['exit'] = 1
        self.assertFalse(suite_pass(['synthetic::a'], [self.group], 0))

    def test_controller_failure_propagates(self):
        self.assertFalse(suite_pass(['synthetic::a'], [self.group], 1))

    def test_duplicate_group_fails(self):
        self.assertFalse(suite_pass(['synthetic::a'], [self.group, copy.deepcopy(self.group)], 0))

    def test_duplicate_inventory_fails(self):
        self.assertFalse(suite_pass(['synthetic::a', 'synthetic::a'], [self.group], 0))

    def test_teardown_failure_fails(self):
        self.group['reports']['synthetic::a'] = {'outcome': 'failed', 'phase': 'teardown'}
        self.assertFalse(suite_pass(['synthetic::a'], [self.group], 0))

    def test_subtest_failure_fails(self):
        self.group['subtests']['failed'] = 1
        self.assertFalse(suite_pass(['synthetic::a'], [self.group], 0))

    def test_skipped_case_fails(self):
        self.group['reports']['synthetic::a']['outcome'] = 'skipped'
        self.assertFalse(suite_pass(['synthetic::a'], [self.group], 0))

    def test_unknown_inventory_fails(self):
        self.assertFalse(suite_pass([], [], 0))


class FailureSummaryTests(unittest.TestCase):
    def test_known_stage_and_errno_are_preserved(self):
        result = failure_summary('{"stage":"KERNEL_RESTRICTIONS","error":"OSError","errno":38}', '')
        self.assertEqual(result['stage'], 'KERNEL_RESTRICTIONS')
        self.assertEqual(result['errno'], 38)

    def test_raw_canary_and_unknown_fields_are_not_emitted(self):
        result = failure_summary('{"stage":"PRIVATE_CANARY","error":"PRIVATE_CANARY","errno":true,"raw":"PRIVATE_CANARY"}', 'PRIVATE_CANARY Permission denied')
        self.assertNotIn('PRIVATE_CANARY', str(result))
        self.assertIsNone(result['errno'])
        self.assertEqual(result['stderr_categories'], ['Permission denied'])

    def test_namespace_launch_error_categories_are_bounded(self):
        result = failure_summary('', 'unshare failed: Operation not permitted; PRIVATE_CANARY')
        self.assertEqual(result['stage'], 'UNKNOWN')
        self.assertEqual(result['stderr_categories'], ['Operation not permitted', 'unshare failed'])

    def test_malformed_and_oversized_output_remains_unknown(self):
        self.assertEqual(failure_summary('not-json', None)['stage'], 'UNKNOWN')
        self.assertEqual(failure_summary('x' * 16385, None)['stage'], 'UNKNOWN')


class BootstrapArgvTests(unittest.TestCase):
    def test_default_has_no_sudo(self):
        self.assertEqual(namespace_launch_prefix(False), ['/usr/bin/unshare'])

    def test_explicit_mode_has_fixed_noninteractive_command(self):
        self.assertEqual(namespace_launch_prefix(True),
                         ['/usr/bin/sudo', '--non-interactive', '--', '/usr/bin/unshare'])

    def test_integer_is_not_explicit_boolean(self):
        with self.assertRaises(ValueError):
            namespace_launch_prefix(1)

    def test_command_string_cannot_be_substituted(self):
        with self.assertRaises(ValueError):
            namespace_launch_prefix('/bin/sh')


class NamespaceMappingTests(unittest.TestCase):
    def test_maps_exactly_original_nonroot_ids(self):
        self.assertEqual(namespace_mapping_args(True, 1001, 1002),
                         ['--user', '--map-users=0:1001:1', '--map-groups=0:1002:1',
                          '--setgroups=deny', '--setuid=0', '--setgid=0'])

    def test_unprivileged_mode_is_unchanged(self):
        self.assertEqual(namespace_mapping_args(False, 1001, 1002), ['--user', '--map-root-user'])

    def test_host_root_uid_is_rejected(self):
        with self.assertRaises(ValueError): namespace_mapping_args(True, 0, 1001)

    def test_host_root_gid_is_rejected(self):
        with self.assertRaises(ValueError): namespace_mapping_args(True, 1001, 0)

    def test_boolean_id_is_rejected(self):
        with self.assertRaises(ValueError): namespace_mapping_args(True, True, 1001)

    def test_wildcard_or_string_id_is_rejected(self):
        with self.assertRaises(ValueError): namespace_mapping_args(True, '*', 1001)

    def test_supported_version(self):
        self.assertTrue(supported_unshare_version('unshare from util-linux 2.39.3\n'))

    def test_old_version_is_rejected(self):
        self.assertFalse(supported_unshare_version('unshare from util-linux 2.38.1'))

    def test_unknown_major_is_rejected(self):
        self.assertFalse(supported_unshare_version('unshare from util-linux 3.0'))

    def test_arbitrary_version_text_is_rejected(self):
        self.assertFalse(supported_unshare_version('PRIVATE_CANARY'))


if __name__ == '__main__':
    unittest.main()
