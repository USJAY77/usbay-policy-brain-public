from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb012_governance_control_registry.py"
spec = importlib.util.spec_from_file_location("pb012_governance_control_registry", SCRIPT)
assert spec and spec.loader
pb012 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pb012)


def _write(path: Path, content: str = "controlled\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _copy_controls() -> list[dict]:
    return json.loads(json.dumps(pb012.REGISTERED_CONTROLS))


def _write_control_files(project_root: Path, controls: list[dict]) -> None:
    for control in controls:
        for relative_path in control["definition_paths"]:
            _write(project_root / relative_path, f"{control['control_id']}:{relative_path}\n")


def test_registry_manifest_and_self_attestation_are_generated(tmp_path: Path) -> None:
    controls = _copy_controls()
    _write_control_files(tmp_path, controls)
    output = tmp_path / "pb012"

    errors = pb012.generate(tmp_path, output, controls)
    verify_errors = pb012.verify(tmp_path, output, controls)

    assert errors == []
    assert verify_errors == []
    registry = json.loads((output / "governance_control_registry.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "governance_control_manifest.json").read_text(encoding="utf-8"))
    attestation = json.loads((output / "governance_self_attestation.json").read_text(encoding="utf-8"))
    assert registry["control_count"] == 7
    assert manifest["decision"] == "VERIFIED"
    assert attestation["decision"] == "VERIFIED"
    assert attestation["aws_access_performed"] is False
    assert attestation["postgresql_access_performed"] is False
    assert attestation["tsa_access_performed"] is False
    assert attestation["external_network_access_performed"] is False


def test_missing_control_is_detected_and_fails_closed(tmp_path: Path) -> None:
    controls = _copy_controls()
    controls = controls[:-1]
    _write_control_files(tmp_path, controls)
    output = tmp_path / "pb012"

    errors = pb012.generate(tmp_path, output, controls)

    assert "PB012_REGISTERED_CONTROL_MISSING:PB-011" in errors
    assert "PB012_CONTROL_COUNT_MISMATCH" in errors
    attestation = json.loads((output / "governance_self_attestation.json").read_text(encoding="utf-8"))
    assert attestation["decision"] == "BLOCKED"
    assert attestation["missing_control_detected"] is True


def test_duplicate_control_identifier_is_detected_and_fails_closed(tmp_path: Path) -> None:
    controls = _copy_controls()
    controls[-1]["control_id"] = "PB-010"
    _write_control_files(tmp_path, controls)
    output = tmp_path / "pb012"

    errors = pb012.generate(tmp_path, output, controls)

    assert "PB012_DUPLICATE_CONTROL_IDENTIFIER:PB-010" in errors
    assert "PB012_REGISTERED_CONTROL_MISSING:PB-011" in errors
    attestation = json.loads((output / "governance_self_attestation.json").read_text(encoding="utf-8"))
    assert attestation["duplicate_control_detected"] is True


def test_missing_registered_artifact_is_detected_and_fails_closed(tmp_path: Path) -> None:
    controls = _copy_controls()
    _write_control_files(tmp_path, controls)
    missing_path = tmp_path / controls[0]["definition_paths"][0]
    missing_path.unlink()
    output = tmp_path / "pb012"

    errors = pb012.generate(tmp_path, output, controls)

    assert any(error.startswith("PB012_REGISTERED_CONTROL_ARTIFACT_MISSING:PB-005:") for error in errors)
    attestation = json.loads((output / "governance_self_attestation.json").read_text(encoding="utf-8"))
    assert attestation["decision"] == "BLOCKED"


def test_unauthorized_control_modification_is_detected_and_fails_closed(tmp_path: Path) -> None:
    controls = _copy_controls()
    _write_control_files(tmp_path, controls)
    output = tmp_path / "pb012"
    assert pb012.generate(tmp_path, output, controls) == []
    changed_path = tmp_path / controls[1]["definition_paths"][0]
    _write(changed_path, "tampered\n")

    errors = pb012.verify(tmp_path, output, controls)

    assert any(error.startswith("PB012_CONTROL_DEFINITION_HASH_CHANGED:PB-006:") for error in errors)
    attestation = json.loads((output / "governance_self_attestation.json").read_text(encoding="utf-8"))
    assert attestation["decision"] == "BLOCKED"
    assert attestation["unauthorized_control_modification_detected"] is True


def test_registry_hash_mismatch_is_detected_and_fails_closed(tmp_path: Path) -> None:
    controls = _copy_controls()
    _write_control_files(tmp_path, controls)
    output = tmp_path / "pb012"
    assert pb012.generate(tmp_path, output, controls) == []
    registry_path = output / "governance_control_registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["controls"][0]["title"] = "tampered"
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    errors = pb012.verify(tmp_path, output, controls)

    assert "PB012_REGISTRY_HASH_MISMATCH" in errors
    attestation = json.loads((output / "governance_self_attestation.json").read_text(encoding="utf-8"))
    assert attestation["registry_hash_mismatch_detected"] is True
