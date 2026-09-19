#!/usr/bin/env python3
"""NEW reproducible static check; not a reconstruction of the historical command.

This script parses source as data with the Python standard library. It does not
import or execute either harness module. Passing proves only the listed source
shape and byte identity. It does not prove native containment, runtime cleanup,
or universal isolation from all possible side effects.
"""

import ast
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
CONTAINMENT = ROOT / "validation/fda_launcher/run_containment.py"
VALIDATION = ROOT / "validation/fda_launcher/run_validation.py"
EXPECTED_VALIDATION_SHA256 = (
    "eb71d8437867dd90749870c28794a976a3798264e301da2072b12d1e9f699266"
)
HANDLER_DEFAULTS = {
    "help_fn": "print_help",
    "state_test_fn": "checkpoint_state_self_test",
    "fault_checks_fn": "fault_checks",
    "fault_main_fn": "fault_main",
    "child_fn": "child_main",
    "worker_fn": "worker_main",
    "main_fn": "main",
}


def top_function(tree, name):
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    assert len(matches) == 1, f"expected one top-level {name}, found {len(matches)}"
    return matches[0]


def is_main_guard(node):
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def dispatch_defaults(dispatch):
    positional = list(dispatch.args.posonlyargs) + list(dispatch.args.args)
    defaults = [None] * (len(positional) - len(dispatch.args.defaults))
    defaults.extend(dispatch.args.defaults)
    values = {}
    for argument, default in zip(positional, defaults):
        if argument.arg in HANDLER_DEFAULTS:
            values[argument.arg] = default
    for argument, default in zip(dispatch.args.kwonlyargs, dispatch.args.kw_defaults):
        if argument.arg in HANDLER_DEFAULTS:
            values[argument.arg] = default
    return values


def check_explicit_handler_mapping(dispatch_test):
    nested = [
        node
        for node in dispatch_test.body
        if isinstance(node, ast.FunctionDef) and node.name == "explicit_handlers"
    ]
    assert len(nested) == 1, "explicit_handlers must be a single nested function"
    returns = [
        node.value
        for node in ast.walk(nested[0])
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
    ]
    assert len(returns) == 1, "explicit_handlers must return one literal mapping"
    mapping = {}
    for key, value in zip(returns[0].keys, returns[0].values):
        assert isinstance(key, ast.Constant) and isinstance(key.value, str)
        mapping[key.value] = value
    assert set(mapping) == set(HANDLER_DEFAULTS), (
        f"handler mapping mismatch: {sorted(mapping)}"
    )
    production_names = set(HANDLER_DEFAULTS.values())
    referenced_names = {
        node.id
        for value in mapping.values()
        for node in ast.walk(value)
        if isinstance(node, ast.Name)
    }
    assert not production_names.intersection(referenced_names), (
        "test-double mapping references a production handler"
    )
    return mapping


def check_dispatch_invocations(dispatch_test):
    calls = [
        node
        for node in ast.walk(dispatch_test)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "dispatch_argv"
    ]
    assert calls, "dispatch_self_test contains no dispatch_argv calls"
    for index, call in enumerate(calls, start=1):
        expansions = [
            keyword.value for keyword in call.keywords if keyword.arg is None
        ]
        direct = [keyword.arg for keyword in call.keywords if keyword.arg is not None]
        assert not direct, (
            f"dispatch call {index} has direct handler keywords instead of the "
            "complete explicit_handlers mapping"
        )
        assert len(expansions) == 1, (
            f"dispatch call {index} must have exactly one ** mapping"
        )
        expansion = expansions[0]
        assert (
            isinstance(expansion, ast.Call)
            and isinstance(expansion.func, ast.Name)
            and expansion.func.id == "explicit_handlers"
        ), f"dispatch call {index} does not expand explicit_handlers"
    return len(calls)


def main():
    containment_bytes = CONTAINMENT.read_bytes()
    validation_bytes = VALIDATION.read_bytes()
    containment_tree = ast.parse(
        containment_bytes.decode("utf-8"), filename=str(CONTAINMENT)
    )
    validation_tree = ast.parse(
        validation_bytes.decode("utf-8"), filename=str(VALIDATION)
    )

    validation_hash = hashlib.sha256(validation_bytes).hexdigest()
    assert validation_hash == EXPECTED_VALIDATION_SHA256, validation_hash

    validation_functions = [
        node.name
        for node in validation_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    counts = Counter(validation_functions)
    duplicates = sorted(name for name, count in counts.items() if count != 1)
    assert len(validation_functions) == 19, len(validation_functions)
    assert not duplicates, duplicates
    main_guards = [node for node in validation_tree.body if is_main_guard(node)]
    assert len(main_guards) == 1, len(main_guards)

    dispatch = top_function(containment_tree, "dispatch_argv")
    defaults = dispatch_defaults(dispatch)
    assert set(defaults) == set(HANDLER_DEFAULTS), sorted(defaults)
    for argument, production_name in HANDLER_DEFAULTS.items():
        default = defaults[argument]
        assert isinstance(default, ast.Name), argument
        assert default.id == production_name, (argument, ast.dump(default))

    dispatch_test = top_function(containment_tree, "dispatch_self_test")
    check_explicit_handler_mapping(dispatch_test)
    dispatch_calls = check_dispatch_invocations(dispatch_test)

    result = {
        "classification": "NEW_REPRODUCIBLE_STATIC_CHECK",
        "result": "PROVEN",
        "containment_parses": True,
        "validation_parses": True,
        "validation_sha256": validation_hash,
        "validation_top_level_main_blocks": len(main_guards),
        "validation_top_level_function_count": len(validation_functions),
        "validation_top_level_function_names_unique": True,
        "dispatch_self_test_invocation_count": dispatch_calls,
        "all_dispatch_test_invocations_expand_complete_handler_mapping": True,
        "production_defaults_match_production_handlers": True,
        "production_defaults_separate_from_test_doubles": True,
        "limits": [
            "AST checks do not prove native containment.",
            "AST checks do not prove runtime cleanup behavior.",
            "AST checks do not prove universal isolation from every possible side effect.",
        ],
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()