from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.hidden_trust_assumption_scanner import (
    HIDDEN_TRUST_SCANNER_ERROR_CODES,
    HIDDEN_TRUST_SCANNER_SCHEMA,
    assert_hidden_trust_scanner_safe,
    explain_hidden_trust_assumption,
    hidden_trust_scan_summary,
    load_hidden_trust_error_registry,
    redacted_hidden_trust_payload,
    scan_hidden_trust_assumptions,
)

ROOT = Path(__file__).resolve().parents[1]


def _metadata(**overrides) -> dict:
    payload = {
        "schema": HIDDEN_TRUST_SCANNER_SCHEMA,
        "signed": True,
        "policy_hash": "a" * 64,
        "signature_hash": "b" * 64,
        "generated_at_utc": "2026-05-15T00:00:00Z",
        "scan_scope": "unit-test-scope",
    }
    payload.update(overrides)
    return payload


def _scan(tmp_path: Path, name: str, text: str):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return scan_hidden_trust_assumptions(
        tmp_path,
        metadata=_metadata(),
        scan_paths=[path],
        now_utc="2026-05-15T00:01:00Z",
    )


def test_clean_local_read_only_scan_passes(tmp_path: Path) -> None:
    result = _scan(tmp_path, "safe.py", "decision = 'DENY'\nfail_closed = True\n")

    assert result.valid is True
    assert result.findings == ()
    assert result.merge_gate == "PASS"
    assert result.scanner_mode == "LOCAL_READ_ONLY"


def test_detects_fallback_allow_and_required_output_fields(tmp_path: Path) -> None:
    result = _scan(tmp_path, "unsafe.py", "decision = fallback_allow()\n")

    assert result.valid is False
    assert result.merge_gate == "BLOCK"
    finding = result.findings[0].to_dict()
    for field in (
        "risk",
        "mechanism",
        "gap",
        "audit_evidence",
        "human_impact",
        "affected_files",
        "finding_severity",
        "merge_gate",
    ):
        assert finding[field]
    assert finding["code"] == "HIDDEN_TRUST_FALLBACK_ALLOW"
    assert "fallback_allow" not in json.dumps(finding)


def test_detects_stale_authority_reuse(tmp_path: Path) -> None:
    result = _scan(tmp_path, "authority.py", "cached_authority = runtime_authority\n")

    assert result.valid is False
    assert "HIDDEN_TRUST_STALE_AUTHORITY_REUSE" in {finding.code for finding in result.findings}


def test_detects_cached_approval_without_freshness(tmp_path: Path) -> None:
    result = _scan(tmp_path, "approval.py", "cached_approval = load_approval()\n")

    assert result.valid is False
    assert "HIDDEN_TRUST_CACHED_APPROVAL_WITHOUT_FRESHNESS" in {finding.code for finding in result.findings}


def test_detects_replayable_trust_state(tmp_path: Path) -> None:
    result = _scan(tmp_path, "replay.py", "trust_state_cache = {}\n")

    assert result.valid is False
    assert "HIDDEN_TRUST_REPLAYABLE_STATE" in {finding.code for finding in result.findings}


def test_detects_mutable_tracked_registry_usage(tmp_path: Path) -> None:
    result = _scan(tmp_path, "registry.py", "Path('audit/key_registry.json').write_text('{}')\n")

    assert result.valid is False
    assert "HIDDEN_TRUST_MUTABLE_TRACKED_REGISTRY" in {finding.code for finding in result.findings}


def test_detects_runtime_policy_bypass(tmp_path: Path) -> None:
    result = _scan(tmp_path, "bypass.py", "skip_governance = True\n")

    assert result.valid is False
    assert "HIDDEN_TRUST_RUNTIME_POLICY_BYPASS" in {finding.code for finding in result.findings}


def test_detects_subprocess_trust_leakage(tmp_path: Path) -> None:
    result = _scan(tmp_path, "subprocess.py", "subprocess.run(['tool', approval_token])\n")

    assert result.valid is False
    assert "HIDDEN_TRUST_SUBPROCESS_LEAKAGE" in {finding.code for finding in result.findings}


def test_detects_unsigned_metadata(tmp_path: Path) -> None:
    result = _scan(tmp_path, "metadata.py", "unsigned_metadata = load_metadata()\n")

    assert result.valid is False
    assert "HIDDEN_TRUST_UNSIGNED_METADATA" in {finding.code for finding in result.findings}


def test_detects_missing_human_approval_boundary(tmp_path: Path) -> None:
    result = _scan(tmp_path, "approval_boundary.py", "risk_level='critical'; requires_human_approval=False\n")

    assert result.valid is False
    assert "HIDDEN_TRUST_MISSING_HUMAN_APPROVAL" in {finding.code for finding in result.findings}


def test_missing_metadata_fails_closed(tmp_path: Path) -> None:
    result = scan_hidden_trust_assumptions(tmp_path, metadata={}, now_utc="2026-05-15T00:01:00Z")

    assert result.valid is False
    assert "HIDDEN_TRUST_INPUT_MALFORMED" in result.errors
    assert "HIDDEN_TRUST_INPUT_UNSIGNED" in result.errors
    assert result.merge_gate == "BLOCK"


def test_stale_metadata_fails_closed(tmp_path: Path) -> None:
    result = scan_hidden_trust_assumptions(
        tmp_path,
        metadata=_metadata(generated_at_utc="2026-05-13T00:00:00Z"),
        now_utc="2026-05-15T00:01:00Z",
    )

    assert result.valid is False
    assert "HIDDEN_TRUST_INPUT_STALE" in result.errors


def test_unsafe_diagnostics_fail_closed() -> None:
    try:
        assert_hidden_trust_scanner_safe({"diagnostics": {"approval_contents": "do-not-log"}})
    except Exception as exc:
        assert str(exc) == "HIDDEN_TRUST_DIAGNOSTICS_UNSAFE"
    else:
        raise AssertionError("unsafe scanner diagnostics were accepted")


def test_error_registry_complete() -> None:
    registry = load_hidden_trust_error_registry(ROOT)

    assert set(HIDDEN_TRUST_SCANNER_ERROR_CODES).issubset(registry)
    assert explain_hidden_trust_assumption(ROOT, "HIDDEN_TRUST_FALLBACK_ALLOW")["fail_closed_reason"]


def test_cli_scan_redacts_output(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.py"
    metadata = tmp_path / "metadata.json"
    source.write_text("default_allow = True\n", encoding="utf-8")
    metadata.write_text(json.dumps(_metadata(), sort_keys=True), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "scan-hidden-trust-assumptions",
            "--root",
            str(tmp_path),
            "--scanner-metadata",
            str(metadata),
            "--scan-path",
            str(source),
            "--validation-timestamp",
            "2026-05-15T00:01:00Z",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "HIDDEN_TRUST_FALLBACK_ALLOW" in completed.stdout
    assert "default_allow" not in completed.stdout
    assert "PRIVATE KEY" not in completed.stdout
    summary = hidden_trust_scan_summary(
        scan_hidden_trust_assumptions(tmp_path, metadata=_metadata(), scan_paths=[source], now_utc="2026-05-15T00:01:00Z")
    )
    assert_hidden_trust_scanner_safe(redacted_hidden_trust_payload(summary))
