from pathlib import Path

import pytest

from scripts.verify_production_readiness import (
    PRODUCTION_READINESS_WORKFLOW,
    check_workflow_dependency_bootstrap,
)

pytestmark = pytest.mark.governance
ROOT = Path(__file__).resolve().parents[1]


def test_current_workflow_satisfies_python_bootstrap_guard():
    assert "WORKFLOW_PYTHON_SETUP_MISSING" not in check_workflow_dependency_bootstrap(ROOT)


@pytest.mark.parametrize("version", ["v5", "v6", "v999"])
def test_disallowed_python_bootstrap_versions_remain_blocked(tmp_path, version):
    workflow = tmp_path / PRODUCTION_READINESS_WORKFLOW
    workflow.parent.mkdir(parents=True)
    workflow.write_text(f"jobs:\n  check:\n    steps:\n      - uses: actions/setup-python@{version}\n")
    assert "WORKFLOW_PYTHON_SETUP_MISSING" in check_workflow_dependency_bootstrap(tmp_path)


def test_absent_python_setup_remains_blocked(tmp_path):
    workflow = tmp_path / PRODUCTION_READINESS_WORKFLOW
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: missing setup\n")
    assert "WORKFLOW_PYTHON_SETUP_MISSING" in check_workflow_dependency_bootstrap(tmp_path)
