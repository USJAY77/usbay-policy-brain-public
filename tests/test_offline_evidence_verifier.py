from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from demo.governance_demo_flow import build_demo_state, write_evidence_pack
from scripts.verify_evidence_bundle import verify_bundle, write_reports
from scripts.verify_governance_evidence_pack import verify_pack
from tests.provenance_helpers import install_runtime_authority
from tests.test_audit_exporter import isolated_anchor_keys


ROOT = Path(__file__).resolve().parents[1]


def _decision(**overrides):
    decision = {
        "node_id": "node-1",
        "tenant_id": "t1",
        "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
        "policy_hash": "policy-hash-1",
        "consensus_result": "ALLOW",
        "nonce_hash": "nonce-hash-1",
        "request_hash": "request-hash-1",
        "consensus_evidence_bundle": {
            "node_ids": ["node-1", "node-2", "node-3"],
            "timestamps": {"node-1": 1, "node-2": 1, "node-3": 1},
            "policy_hash": "policy-hash-1",
            "tenant_id": "t1",
            "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
            "consensus_result": "allow",
            "attestation_evidence": [
                {
                    "logical_node_id": "node-1",
                    "node_id": "attested-node-1",
                    "node_role": "primary",
                    "tenant_id": "t1",
                    "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
                    "provider_mode": "mock_local",
                    "hardware_backed": False,
                    "attestation_hash": "attestation-hash-1",
                    "attestation_timestamp": 1,
                }
            ],
            "attestation_evidence_hash": "attestation-evidence-hash-1",
            "sha256_evidence_hash": "evidence-hash-1",
            "consensus_signature": "consensus-signature-1",
        },
    }
    decision.update(overrides)
    return decision


def _bundle(
    tmp_path: Path,
    monkeypatch,
    *,
    install_provenance: bool = True,
    provenance_authority=None,
) -> Path:
    if install_provenance:
        authority = install_runtime_authority(monkeypatch, tmp_path)
    else:
        authority = provenance_authority
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision())
    bundle_dir = tmp_path / "bundle"
    export_evidence_bundle(ledger, bundle_dir, provenance_authority=authority)
    return bundle_dir


def _copy_bundle(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst)
    return dst


def _audit_records(bundle: Path):
    return [
        json.loads(line)
        for line in (bundle / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_audit_records(bundle: Path, records) -> None:
    (bundle / "audit.jsonl").write_text(
        "\n".join(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records) + "\n",
        encoding="utf-8",
    )


def test_valid_evidence_bundle_passes_and_writes_reports(tmp_path, monkeypatch) -> None:
    bundle = _bundle(tmp_path, monkeypatch)
    report = verify_bundle(bundle)
    output_dir = tmp_path / "reports"
    write_reports(report, output_dir)

    assert report["result"] == "PASS"
    assert report["failed_control_ids"] == []
    assert (output_dir / "verification_result.json").exists()
    assert (output_dir / "human_readable_report.txt").read_text(encoding="utf-8").startswith("USBAY Evidence Verification: PASS")


def test_export_verification_path_uses_canonical_ci_validator(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    authority = install_runtime_authority(monkeypatch, tmp_path)
    bundle = _bundle(tmp_path, monkeypatch, install_provenance=False, provenance_authority=authority)

    report = verify_bundle(bundle)

    assert report["result"] == "PASS"
    context = report["evidence_summary"]["deployment_provenance"]["provenance_context"]
    assert context == authority.context_dict()


def test_missing_audit_jsonl_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _copy_bundle(_bundle(tmp_path, monkeypatch), tmp_path / "mutated")
    (bundle / "audit.jsonl").unlink()

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert "REQUIRED_FILE_MISSING:audit.jsonl" in report["failed_control_ids"]


def test_tampered_ledger_sha256_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _copy_bundle(_bundle(tmp_path, monkeypatch), tmp_path / "mutated")
    (bundle / "ledger.sha256").write_text("0" * 64 + "\n", encoding="utf-8")

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert "LEDGER_SHA256" in report["failed_control_ids"]


def test_broken_hash_chain_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _copy_bundle(_bundle(tmp_path, monkeypatch), tmp_path / "mutated")
    records = _audit_records(bundle)
    records[0]["previous_event_hash"] = "broken"
    _write_audit_records(bundle, records)

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert any(control.startswith("HASH_CHAIN_CONTINUITY") for control in report["failed_control_ids"])


def test_bad_signature_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _copy_bundle(_bundle(tmp_path, monkeypatch), tmp_path / "mutated")
    signatures = json.loads((bundle / "signatures.json").read_text(encoding="utf-8"))
    first_key = next(iter(signatures))
    signatures[first_key]["signature"] = "invalid"
    (bundle / "signatures.json").write_text(json.dumps(signatures, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert any(control.startswith("SIGNATURE_INVALID") for control in report["failed_control_ids"])


def test_bad_rfc3161_message_imprint_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _copy_bundle(_bundle(tmp_path, monkeypatch), tmp_path / "mutated")
    verification = json.loads((bundle / "timestamp_verification.json").read_text(encoding="utf-8"))
    verification["message_imprint"] = "0" * 64
    (bundle / "timestamp_verification.json").write_text(json.dumps(verification, sort_keys=True), encoding="utf-8")

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert "RFC3161_MESSAGE_IMPRINT" in report["failed_control_ids"]


def test_missing_tsa_chain_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _copy_bundle(_bundle(tmp_path, monkeypatch), tmp_path / "mutated")
    (bundle / "tsa_certificate_chain.pem").write_text("", encoding="utf-8")

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert "TSA_CERTIFICATE_CHAIN" in report["failed_control_ids"]


def test_wrong_policy_oid_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _copy_bundle(_bundle(tmp_path, monkeypatch), tmp_path / "mutated")
    (bundle / "tsa_policy_oid.txt").write_text("1.2.3.4.5\n", encoding="utf-8")

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert "TSA_POLICY_OID" in report["failed_control_ids"]


def test_secret_leakage_in_export_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _copy_bundle(_bundle(tmp_path, monkeypatch), tmp_path / "mutated")
    with (bundle / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"raw_nonce":"do-not-leak"}\n')

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert "NO_SECRET_LEAKAGE" in report["failed_control_ids"]


def test_verifier_never_mutates_input_files(tmp_path, monkeypatch) -> None:
    bundle = _bundle(tmp_path, monkeypatch)
    before = {
        path.name: path.read_bytes()
        for path in bundle.iterdir()
        if path.is_file()
    }
    report = verify_bundle(bundle)
    write_reports(report, tmp_path / "reports")
    after = {
        path.name: path.read_bytes()
        for path in bundle.iterdir()
        if path.is_file()
    }

    assert report["result"] == "PASS"
    assert before == after


def _governance_pack(tmp_path: Path) -> Path:
    pack_dir = tmp_path / "governance-pack"
    write_evidence_pack(build_demo_state(), pack_dir)
    return pack_dir


def test_governance_evidence_pack_offline_verifier_passes(tmp_path: Path) -> None:
    pack_dir = _governance_pack(tmp_path)

    report = verify_pack(pack_dir)

    assert report["result"] == "PASS"
    assert report["event_count"] == 3
    assert len(report["latest_event_hash"]) == 64
    assert len(report["signer_fingerprint"]) == 64


def test_governance_evidence_pack_cli_passes_without_runtime(tmp_path: Path) -> None:
    pack_dir = _governance_pack(tmp_path)

    result = subprocess.run(
        [sys.executable, "scripts/verify_governance_evidence_pack.py", str(pack_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "VERIFY_PASS" in result.stdout
    assert not any(marker in result.stdout + result.stderr for marker in ("PRIVATE " + "KEY", "ghp" + "_", "github" + "_pat_"))


def test_governance_evidence_pack_missing_file_fails(tmp_path: Path) -> None:
    pack_dir = _governance_pack(tmp_path)
    (pack_dir / "gate_history.json").unlink()

    result = subprocess.run(
        [sys.executable, "scripts/verify_governance_evidence_pack.py", str(pack_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "VERIFY_FAIL REQUIRED_FILE_MISSING:gate_history.json" in result.stdout


def test_governance_evidence_pack_tampered_historical_event_fails(tmp_path: Path) -> None:
    pack_dir = _governance_pack(tmp_path)
    gate_history_path = pack_dir / "gate_history.json"
    gate_history = json.loads(gate_history_path.read_text(encoding="utf-8"))
    gate_history["events"][0]["decision"] = "PASS"
    gate_history_path.write_text(json.dumps(gate_history, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/verify_governance_evidence_pack.py", str(pack_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "VERIFY_FAIL EVENT_HASH_MISMATCH:0" in result.stdout


def test_governance_evidence_pack_broken_previous_hash_fails(tmp_path: Path) -> None:
    pack_dir = _governance_pack(tmp_path)
    gate_history_path = pack_dir / "gate_history.json"
    gate_history = json.loads(gate_history_path.read_text(encoding="utf-8"))
    gate_history["events"][1]["previous_event_hash"] = "broken"
    gate_history_path.write_text(json.dumps(gate_history, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/verify_governance_evidence_pack.py", str(pack_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "VERIFY_FAIL PREVIOUS_EVENT_HASH_INVALID:1" in result.stdout


def test_governance_evidence_pack_rejects_secret_markers(tmp_path: Path) -> None:
    pack_dir = _governance_pack(tmp_path)
    chain_summary_path = pack_dir / "chain_summary.json"
    chain_summary = json.loads(chain_summary_path.read_text(encoding="utf-8"))
    chain_summary["diagnostic"] = "ghp" + "_unsafe_marker"
    chain_summary_path.write_text(json.dumps(chain_summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/verify_governance_evidence_pack.py", str(pack_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "VERIFY_FAIL SECRET_MARKER_DETECTED" in result.stdout
    assert "ghp" + "_" not in result.stdout
