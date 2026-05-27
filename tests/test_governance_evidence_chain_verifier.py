"""Tests for governance/evidence_chain_verifier.py and the
/api/governance/evidence route.

Covers the four required scenarios:
  1. valid signed evidence  -> VERIFIED
  2. missing evidence       -> MISSING (fail-closed, 404)
  3. malformed evidence     -> UNVERIFIED (fail-closed, 503)
  4. signature mismatch     -> UNVERIFIED (fail-closed, 503)

Does not regenerate dashboard artifacts, does not fabricate VERIFIED
state, does not weaken signature validation.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
from governance.evidence_chain_verifier import (
    STATE_MISSING,
    STATE_UNVERIFIED,
    STATE_VERIFIED,
    verify_governance_evidence,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_POLICY = REPO_ROOT / "governance" / "ci_evidence_trust_policy.json"
REAL_SIG = REPO_ROOT / "governance" / "ci_evidence_trust_policy.sig"
REAL_AUTHORITY = REPO_ROOT / "governance" / "ci_evidence_trust_policy_authority.json"
REAL_AUDIT = REPO_ROOT / "governance" / "ci_evidence_trust_policy_audit.jsonl"


def _stage_real_artifacts(tmp_path: Path) -> Path:
    gov_dir = tmp_path / "governance"
    gov_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REAL_POLICY, gov_dir / REAL_POLICY.name)
    shutil.copy2(REAL_SIG, gov_dir / REAL_SIG.name)
    shutil.copy2(REAL_AUTHORITY, gov_dir / REAL_AUTHORITY.name)
    shutil.copy2(REAL_AUDIT, gov_dir / REAL_AUDIT.name)
    return tmp_path


def test_valid_signed_evidence_returns_verified():
    result = verify_governance_evidence(str(REPO_ROOT))
    assert result.state == STATE_VERIFIED, result.reason_codes
    assert "GOVERNANCE_EVIDENCE_SIGNATURE_VERIFIED" in result.reason_codes
    assert result.signer_id == "ci-evidence-trust-policy-authority"
    assert result.policy_version == "ci-evidence-trust-v1"
    assert isinstance(result.policy_hash, str) and len(result.policy_hash) == 64
    sources = result.provenance_source
    for name in ("policy", "signature", "authority", "audit_log"):
        assert sources[name]["present"] is True
        assert "sha256" in sources[name]


def test_missing_evidence_returns_missing_fail_closed(tmp_path):
    result = verify_governance_evidence(str(tmp_path))
    assert result.state == STATE_MISSING
    assert any(code.startswith("GOVERNANCE_EVIDENCE_MISSING:") for code in result.reason_codes)
    for name in ("policy", "signature", "authority", "audit_log"):
        assert result.provenance_source[name]["present"] is False


def test_malformed_evidence_returns_unverified(tmp_path):
    _stage_real_artifacts(tmp_path)
    (tmp_path / "governance" / REAL_POLICY.name).write_text("{ not valid json", encoding="utf-8")

    result = verify_governance_evidence(str(tmp_path))
    assert result.state == STATE_UNVERIFIED
    assert "GOVERNANCE_EVIDENCE_POLICY_MALFORMED" in result.reason_codes


def test_signature_mismatch_returns_unverified(tmp_path):
    _stage_real_artifacts(tmp_path)
    policy_path = tmp_path / "governance" / REAL_POLICY.name
    policy_obj = json.loads(policy_path.read_text(encoding="utf-8"))
    policy_obj["policy_version"] = "TAMPERED-" + str(policy_obj.get("policy_version", ""))
    policy_path.write_text(json.dumps(policy_obj, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    result = verify_governance_evidence(str(tmp_path))
    assert result.state == STATE_UNVERIFIED
    # Either the declared hash no longer matches the canonical bytes,
    # or the signature itself fails to verify against the new bytes.
    assert (
        "GOVERNANCE_EVIDENCE_POLICY_HASH_MISMATCH" in result.reason_codes
        or "GOVERNANCE_EVIDENCE_SIGNATURE_INVALID" in result.reason_codes
    )


def test_revoked_signer_returns_unverified(tmp_path):
    _stage_real_artifacts(tmp_path)
    authority_path = tmp_path / "governance" / REAL_AUTHORITY.name
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    fingerprints = [s["public_key_fingerprint"] for s in authority["allowed_policy_signers"]]
    authority["revoked_policy_signer_fingerprints"] = fingerprints
    authority_path.write_text(json.dumps(authority, sort_keys=True), encoding="utf-8")

    result = verify_governance_evidence(str(tmp_path))
    assert result.state == STATE_UNVERIFIED
    assert "GOVERNANCE_EVIDENCE_SIGNER_REVOKED" in result.reason_codes


@pytest.fixture
def client():
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def test_route_returns_verified_against_real_artifacts(client):
    res = client.get("/api/governance/evidence")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["state"] == STATE_VERIFIED
    assert body["signer_id"] == "ci-evidence-trust-policy-authority"
    assert body["policy_version"] == "ci-evidence-trust-v1"
    assert body["provenance_source"]["policy"]["present"] is True
    # No PEMs, no raw signatures in the response body.
    text = res.text
    assert "BEGIN PUBLIC KEY" not in text
    assert "BEGIN PRIVATE KEY" not in text
    assert "ed25519:" not in text
