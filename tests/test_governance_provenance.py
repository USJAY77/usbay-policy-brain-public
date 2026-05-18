from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.generate_governance_provenance import build_provenance, canonical_json, main, sha256_file


ROOT = Path(__file__).resolve().parents[1]
TIMESTAMP = "2026-05-18T00:00:00Z"


def _fixture(tmp_path: Path, evidence_text: str = "PRODUCTION_READINESS_FAST_CONTRACT=true\n") -> tuple[Path, Path]:
    governance = tmp_path / "governance"
    workflow = tmp_path / ".github" / "workflows" / "production-readiness.yml"
    evidence = tmp_path / "evidence" / "production-readiness-guard-output.txt"
    governance.mkdir(parents=True, exist_ok=True)
    workflow.parent.mkdir(parents=True, exist_ok=True)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    (governance / "production_readiness_lanes.json").write_text(
        (ROOT / "governance" / "production_readiness_lanes.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    workflow.write_text("name: production-readiness\n", encoding="utf-8")
    evidence.write_text(evidence_text, encoding="utf-8")
    return workflow, evidence


def _provenance(tmp_path: Path, evidence_text: str = "PRODUCTION_READINESS_FAST_CONTRACT=true\n") -> dict:
    workflow, evidence = _fixture(tmp_path, evidence_text=evidence_text)
    return build_provenance(
        root=tmp_path,
        lane="fast-contract",
        workflow_name="production-readiness",
        workflow_path=workflow,
        evidence_path=evidence,
        validation_result="PASS",
        timestamp_utc=TIMESTAMP,
        commit_sha="a" * 40,
    )


def test_provenance_hash_generation_is_deterministic(tmp_path: Path) -> None:
    first = _provenance(tmp_path)
    second = _provenance(tmp_path)

    assert first["provenance_payload_hash"] == second["provenance_payload_hash"]
    assert first["signature"] == second["signature"]
    assert first["provenance_fingerprint"] == second["provenance_fingerprint"]
    assert canonical_json(first) == canonical_json(second)


def test_modified_evidence_changes_hashes(tmp_path: Path) -> None:
    first = _provenance(tmp_path, "PRODUCTION_READINESS_FAST_CONTRACT=true\n")
    second = _provenance(tmp_path, "PRODUCTION_READINESS_FAST_CONTRACT=false\n")

    assert first["evidence_hash"] != second["evidence_hash"]
    assert first["provenance_fingerprint"] != second["provenance_fingerprint"]


def test_missing_evidence_fails_closed(tmp_path: Path) -> None:
    workflow, evidence = _fixture(tmp_path)
    evidence.unlink()

    with pytest.raises(SystemExit, match="GOVERNANCE_PROVENANCE_EVIDENCE_MISSING"):
        build_provenance(
            root=tmp_path,
            lane="fast-contract",
            workflow_name="production-readiness",
            workflow_path=workflow,
            evidence_path=evidence,
            validation_result="PASS",
            timestamp_utc=TIMESTAMP,
            commit_sha="a" * 40,
        )


def test_schema_contains_required_provenance_fields() -> None:
    schema = json.loads((ROOT / "governance" / "governance_provenance_schema.json").read_text(encoding="utf-8"))

    assert schema["schema"] == "usbay.governance_provenance_schema.v1"
    for field in (
        "provenance_version",
        "governance_lane",
        "workflow_name",
        "workflow_sha",
        "commit_sha",
        "policy_hash",
        "orchestration_hash",
        "evidence_hash",
        "timestamp_utc",
        "validation_result",
        "signer_mode",
        "signature",
        "signature_algorithm",
    ):
        assert field in schema["required"]


def test_lane_provenance_correctness(tmp_path: Path) -> None:
    provenance = _provenance(tmp_path)

    assert provenance["provenance_version"] == "usbay.governance_provenance.v1"
    assert provenance["governance_lane"] == "fast-contract"
    assert provenance["workflow_name"] == "production-readiness"
    assert provenance["signer_mode"] == "hash-only-local"
    assert provenance["signature_algorithm"] == "sha256-detached-hash"
    assert provenance["validation_result"] == "PASS"


def test_cli_writes_hash_only_local_provenance(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    workflow, evidence = _fixture(tmp_path)
    output = tmp_path / "evidence" / "governance-provenance.json"

    result = main(
        [
            "--root",
            str(tmp_path),
            "--workflow-path",
            str(workflow),
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--timestamp-utc",
            TIMESTAMP,
            "--commit-sha",
            "a" * 40,
        ]
    )
    stdout = capsys.readouterr().out
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert result == 0
    assert "GOVERNANCE_PROVENANCE_CREATED=true" in stdout
    assert payload["signer_mode"] == "hash-only-local"
    assert payload["evidence_hash"] == sha256_file(evidence)
    assert "PRIVATE KEY" not in output.read_text(encoding="utf-8")
