"""Fixed source-verifier case contract; never grants execution authority."""
import re
SCHEMA = 'usbay.runtime_artifact_validation.v1'
CASE_NAMES = (
    'test_valid_signature', 'test_untrusted_key', 'test_bad_signature',
    'test_scope_mismatch', 'test_test_producer_denied_in_production',
    'test_key_id_mismatch', 'test_missing_public_trust', 'test_conflicting_environment',
    'test_duplicate_field', 'test_nonfinite_field', 'test_extra_field',
    'test_commit_conflict', 'test_tree_conflict', 'test_digest_mismatch',
    'test_managed_set_mismatch', 'test_same_size_mutation', 'test_mode_mutation',
    'test_missing_file', 'test_file_symlink', 'test_parent_symlink',
    'test_root_symlink', 'test_unexpected_governed_file', 'test_freshness_file_mutation',
    'test_freshness_manifest_mutation', 'test_forged_seal', 'test_future_timestamp',
    'test_malformed_manifest', 'test_production_ignores_git', 'test_result_immutable',
    'test_freshness_extra_file',
)


def result_structure_pass(value, source_binding, dependency_binding):
    return (all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v)
                for v in (source_binding, dependency_binding))
            and type(value) is dict
            and set(value) == {'schema', 'source_binding', 'dependency_binding',
                               'reports', 'tests_run', 'execution_authorized'}
            and value['schema'] == SCHEMA and value['source_binding'] == source_binding
            and value['dependency_binding'] == dependency_binding
            and type(value['tests_run']) is int and value['tests_run'] == len(CASE_NAMES)
            and value['execution_authorized'] is False
            and type(value['reports']) is dict and set(value['reports']) == set(CASE_NAMES)
            and all(type(v) is str and v in {'passed', 'failed', 'error', 'skipped'}
                    for v in value['reports'].values()))


def result_pass(value, source_binding, dependency_binding):
    return bool(result_structure_pass(value, source_binding, dependency_binding)
                and all(v == 'passed' for v in value['reports'].values()))


def bounded_result(value):
    if type(value) is not dict:
        return {'reported_tests_run': None, 'reports': {}}
    count = value.get('tests_run')
    reports = value.get('reports')
    return {'reported_tests_run': count if type(count) is int and 0 <= count <= len(CASE_NAMES) else None,
            'reports': {name: reports[name] for name in CASE_NAMES
                        if type(reports) is dict and type(reports.get(name)) is str
                        and reports[name] in {'passed', 'failed', 'error', 'skipped'}}}
