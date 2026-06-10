from runtime.computer_use.integration_matrix import REQUIRED_COMPONENTS, build_integration_matrix


def test_integration_matrix_ready_when_all_components_present() -> None:
    matrix = build_integration_matrix({component: True for component in REQUIRED_COMPONENTS})

    assert matrix["readiness"] == "READY"
    assert matrix["missing_components"] == []


def test_integration_matrix_blocks_missing_component() -> None:
    matrix = build_integration_matrix({"runtime_controller": True})

    assert matrix["readiness"] == "BLOCKED"
    assert "decision_engine" in matrix["missing_components"]

