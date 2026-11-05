import copy
import unittest

from result_contract import REQUIRED_CONTROLS, controls_pass, suite_pass


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


if __name__ == '__main__':
    unittest.main()
