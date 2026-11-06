"""Pure contract and disposable inert-source tests; never import application code."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import offline_mail_contract as contract
from result_contract import REQUIRED_CONTROLS


class GateTests(unittest.TestCase):
    def setUp(self):
        self.controls = dict.fromkeys(REQUIRED_CONTROLS, True)
        self.identity = dict(uids=[0, 0, 0], gids=[0, 0, 0], groups=[], setgroups_denied=True)
        self.gate = dict(installed=True, no_new_privs=True, seccomp_mode=2, architecture='x86_64')

    def test_gate_requires_complete_positive_native_evidence(self):
        # Use the actual existing execution-gate contract shape.
        from execution_boundary import fresh_exec_gate_pass
        self.assertTrue(fresh_exec_gate_pass(self.gate))
        self.assertTrue(contract.preconditions_pass(self.controls, self.identity, self.gate))

    def test_missing_or_failed_control_never_passes(self):
        for name in REQUIRED_CONTROLS:
            controls = self.controls.copy()
            controls.pop(name)
            self.assertFalse(contract.preconditions_pass(controls, self.identity, self.gate))
            controls[name] = False
            self.assertFalse(contract.preconditions_pass(controls, self.identity, self.gate))

    def test_root_mapping_is_not_sufficient_without_empty_groups(self):
        identity = self.identity | {'groups': [1001]}
        self.assertFalse(contract.preconditions_pass(self.controls, identity, self.gate))

    def test_exec_gate_cannot_be_replaced_with_truthy_claim(self):
        self.assertFalse(contract.preconditions_pass(self.controls, self.identity, True))
        gate = self.gate | {'no_new_privs': 1}
        self.assertFalse(contract.preconditions_pass(self.controls, self.identity, gate))


class SourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='usbay-inert-source-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.head = 'a' * 40
        self.sources = {name: b'# Inert source fixture; never imported.\n' for name in contract.SOURCE_MAP}
        (self.root / 'synthetic.py').write_bytes(b'# Synthetic source canary.\n')
        with patch.object(contract, 'committed_sources', return_value=self.sources):
            self.binding = contract.stage_source(Path('/unused'), self.head, self.root)

    def write_binding(self, data):
        (self.root / 'offline-mail-binding.json').write_bytes(contract.canonical(data))

    def test_exact_source_set_and_head_pass(self):
        self.assertEqual(contract.verify_payload(self.root, self.head),
                         hashlib.sha256(contract.canonical(self.binding)).hexdigest())

    def test_different_head_fails(self):
        with self.assertRaises(RuntimeError):
            contract.verify_payload(self.root, 'b' * 40)

    def test_changed_source_bytes_fail(self):
        (self.root / next(iter(contract.SOURCE_MAP))).write_bytes(b'# Changed inert fixture.\n')
        with self.assertRaises(RuntimeError):
            contract.verify_payload(self.root, self.head)

    def test_extra_file_fails(self):
        (self.root / 'unexpected.py').write_bytes(b'# Inert.\n')
        with self.assertRaises(RuntimeError):
            contract.verify_payload(self.root, self.head)

    def test_missing_file_fails(self):
        (self.root / next(iter(contract.SOURCE_MAP))).unlink()
        with self.assertRaises(RuntimeError):
            contract.verify_payload(self.root, self.head)

    def test_symlink_substitution_fails(self):
        path = self.root / next(iter(contract.SOURCE_MAP))
        path.unlink()
        path.symlink_to('../synthetic.py')
        with self.assertRaises(RuntimeError):
            contract.verify_payload(self.root, self.head)

    def test_duplicate_json_fields_fail(self):
        raw = contract.canonical(self.binding)
        raw = b'{"schema":"unexpected",' + raw[1:]
        (self.root / 'offline-mail-binding.json').write_bytes(raw)
        with self.assertRaises(RuntimeError):
            contract.verify_payload(self.root, self.head)

    def test_changed_or_extra_case_selection_fails(self):
        data = copy.deepcopy(self.binding)
        data['cases'].append('unapproved_case')
        self.write_binding(data)
        with self.assertRaises(RuntimeError):
            contract.verify_payload(self.root, self.head)

    def test_privileged_staging_check_rejects_different_bytes(self):
        path = self.root / next(iter(contract.SOURCE_MAP))
        path.write_bytes(b'# Changed inert fixture.\n')
        with patch.object(contract, 'committed_sources', return_value=self.sources):
            with self.assertRaises(RuntimeError):
                contract.verify_staged_source(Path('/unused'), self.head, self.root, os.getuid(), os.getgid())

    def test_export_does_not_overwrite_existing_source(self):
        with patch.object(contract, 'committed_sources', return_value=self.sources):
            with self.assertRaises(FileExistsError):
                contract.stage_source(Path('/unused'), self.head, self.root)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.binding = 'c' * 64
        self.report = dict(schema=contract.SCHEMA, source_binding=self.binding,
                           reports=dict.fromkeys(contract.CASE_NAMES, 'passed'),
                           tests_run=len(contract.CASE_NAMES), execution_authorized=False)

    def test_complete_exact_report_passes(self):
        self.assertTrue(contract.result_pass(self.report, self.binding))

    def test_missing_case_and_skipped_case_fail(self):
        for outcome in (None, 'skipped', 'failed', 'error', True):
            report = copy.deepcopy(self.report)
            name = contract.CASE_NAMES[0]
            if outcome is None:
                report['reports'].pop(name)
            else:
                report['reports'][name] = outcome
            self.assertFalse(contract.result_pass(report, self.binding))

    def test_wrong_binding_or_granted_authority_fails(self):
        self.assertFalse(contract.result_pass(self.report, 'd' * 64))
        self.assertFalse(contract.result_pass(self.report | {'execution_authorized': True}, self.binding))

    def test_extra_cases_or_boolean_count_fail(self):
        report = copy.deepcopy(self.report)
        report['reports']['unapproved_case'] = 'passed'
        self.assertFalse(contract.result_pass(report, self.binding))
        self.assertFalse(contract.result_pass(self.report | {'tests_run': True}, self.binding))

    def test_complete_failure_report_proves_execution_without_passing_validation(self):
        report = copy.deepcopy(self.report)
        report['reports'][contract.CASE_NAMES[0]] = 'failed'
        self.assertTrue(contract.result_structure_pass(report, self.binding))
        self.assertFalse(contract.result_pass(report, self.binding))

    def test_driver_has_exact_fixed_case_names_without_importing_it(self):
        raw = Path(__file__).with_name('offline_mail_cases.py').read_bytes()
        tree = ast.parse(raw)
        cases = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'OfflineMailCases')
        names = {n.name for n in cases.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')}
        self.assertEqual(names, set(contract.CASE_NAMES))
        self.assertEqual(len(contract.CASE_NAMES), len(set(contract.CASE_NAMES)))

    def test_preflight_and_contract_do_not_import_application_modules(self):
        import isolation_preflight
        import runner_bootstrap
        self.assertFalse(any(n.startswith(('governance.', 'control_plane.', 'gateway.')) for n in sys.modules))

    def test_invalid_result_is_not_normalized_into_success_or_logged_raw(self):
        report = copy.deepcopy(self.report)
        report['reports'][contract.CASE_NAMES[0]] = 'PRIVATE_SYNTHETIC_CANARY'
        report['unexpected'] = 'PRIVATE_SYNTHETIC_CANARY'
        self.assertFalse(contract.result_pass(report, self.binding))
        diagnostic = contract.bounded_result(report)
        self.assertNotIn('PRIVATE_SYNTHETIC_CANARY', json.dumps(diagnostic))
        self.assertNotIn('unexpected', diagnostic)


if __name__ == '__main__':
    unittest.main()
