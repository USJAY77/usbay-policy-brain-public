import json
from pathlib import Path

from memory.governed_memory import GovernedMemory


def test_remember_and_recall(tmp_path: Path):
    mem = GovernedMemory("test-device", memory_dir=str(tmp_path / "store"))
    mem.remember_decision(
        action="deploy",
        decision="DENY",
        risk="HIGH",
        audit_id="audit-001",
        ai_explanation="Blocked by policy.",
    )
    history = mem.recall_history("deploy")
    assert len(history) == 1
    assert history[0]["action"] == "deploy"
    assert history[0]["decision"] == "DENY"


def test_full_audit_search(tmp_path: Path):
    mem = GovernedMemory("test-device", memory_dir=str(tmp_path / "store"))
    mem.remember_decision(
        action="device_attestation",
        decision="ALLOW",
        risk="LOW",
        audit_id="audit-xyz",
        ai_explanation="Attestation passed.",
    )
    results = mem.full_audit_search("attestation")
    assert len(results) == 1
    assert results[0]["action"] == "device_attestation"


def test_verify_memory_integrity(tmp_path: Path):
    mem = GovernedMemory("test-device", memory_dir=str(tmp_path / "store"))
    mem.remember_decision(
        action="deploy",
        decision="DENY",
        risk="HIGH",
        audit_id="audit-001",
    )
    result = mem.verify_memory_integrity()
    assert result["valid"] is True
    assert result["invalid_indexes"] == []


def test_integrity_detects_tamper(tmp_path: Path):
    mem = GovernedMemory("test-device", memory_dir=str(tmp_path / "store"))
    mem.remember_decision(
        action="deploy",
        decision="DENY",
        risk="HIGH",
        audit_id="audit-001",
    )

    memory_file = tmp_path / "store" / "test-device.jsonl"
    lines = memory_file.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["decision"] = "ALLOW"
    lines[0] = json.dumps(record)
    memory_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = mem.verify_memory_integrity()
    assert result["valid"] is False
    assert 0 in result["invalid_indexes"]
raise Exception('force failure')
