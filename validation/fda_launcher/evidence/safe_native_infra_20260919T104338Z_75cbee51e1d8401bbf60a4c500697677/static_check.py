#!/usr/bin/env python3
"""Non-importing static checks for collision-safe lifecycle evidence changes."""

import ast
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
CONTAINMENT = ROOT / "validation/fda_launcher/run_containment.py"
VALIDATION = ROOT / "validation/fda_launcher/run_validation.py"
EXPECTED = {
    "run_containment": "97b73cb45f341a590e97ae375f24e35e32173e06ff0e74165420b6e7ce0da55d",
    "run_validation": "fdc354b43430ad37d41095092ced06e25448d3d44759d5c858643ef3bcb5f9e7",
}


def top_function(tree, name):
    matches = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    assert len(matches) == 1, (name, len(matches))
    return matches[0]


def main():
    containment_bytes = CONTAINMENT.read_bytes()
    validation_bytes = VALIDATION.read_bytes()
    containment_tree = ast.parse(
        containment_bytes.decode("utf-8"), filename=str(CONTAINMENT)
    )
    validation_tree = ast.parse(
        validation_bytes.decode("utf-8"), filename=str(VALIDATION)
    )
    hashes = {
        "run_containment": hashlib.sha256(containment_bytes).hexdigest(),
        "run_validation": hashlib.sha256(validation_bytes).hexdigest(),
    }
    assert hashes == EXPECTED, hashes

    functions = [
        node.name for node in validation_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    assert len(functions) == 22, len(functions)
    assert not {
        name: count for name, count in Counter(functions).items() if count != 1
    }
    main_guards = [
        node for node in validation_tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
    ]
    assert len(main_guards) == 1, len(main_guards)

    assigned_names = {
        target.id
        for node in validation_tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    assert "MISSING_EVIDENCE" not in assigned_names

    allocator = top_function(validation_tree, "create_attempt_directory")
    allocator_source = ast.unparse(allocator)
    for required in (
        "time.gmtime()",
        "uuid.uuid4().hex",
        "attempt.mkdir(parents=True, exist_ok=False)",
        "missing_cases_",
    ):
        assert required in allocator_source, required

    prepare = top_function(validation_tree, "prepare_case_files")
    assert [arg.arg for arg in prepare.args.args] == [
        "case", "evidence_dir", "nonce"
    ]
    assert "exist_ok=False" in ast.unparse(prepare)

    run_case = top_function(validation_tree, "run_case")
    assert [arg.arg for arg in run_case.args.args] == ["case", "evidence_dir"]
    assert "prepare_case_files(case, evidence_dir, nonce)" in ast.unparse(run_case)

    lifecycle_main = top_function(validation_tree, "main")
    lifecycle_source = ast.unparse(lifecycle_main)
    for required in (
        "attempt_factory(evidence_root)",
        "case_runner(case, attempt_dir)",
        "result['attempt_directory'] = recorded_attempt",
        "attempt_dir / 'raw.json'",
    ):
        assert required in lifecycle_source, required

    dispatch = top_function(validation_tree, "dispatch_argv")
    first_statement = dispatch.body[0]
    assert isinstance(first_statement, ast.Expr) and isinstance(
        first_statement.value, ast.Constant
    ), "dispatch docstring missing"
    first_executable = dispatch.body[1]
    assert isinstance(first_executable, ast.Assign)
    assert isinstance(first_executable.value, ast.Call)
    assert isinstance(first_executable.value.func, ast.Name)
    assert first_executable.value.func.id == "parse_cli"

    print(json.dumps({
        "classification": "NEW_STATIC_CHECK_FOR_CHANGED_SOURCE",
        "result": "PROVEN",
        "hashes": hashes,
        "validation_function_count": len(functions),
        "unique_top_level_functions": True,
        "single_top_level_main_guard": True,
        "fixed_active_destination_removed": True,
        "utc_uuid_exclusive_allocator": True,
        "explicit_attempt_directory_propagation": True,
        "complete_cli_parsed_before_dispatch": True,
        "limits": [
            "Static checks do not prove native containment.",
            "Static checks do not prove cgroup kill or empty-state semantics.",
            "Static checks do not authorize lifecycle execution.",
        ],
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()