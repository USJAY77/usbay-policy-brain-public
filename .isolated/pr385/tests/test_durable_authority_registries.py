from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from governance.durable_authority_registries import (
    ACTIVATION,
    ATTESTATION,
    CHALLENGE,
    EXPIRED,
    HUMAN_APPROVAL,
    IDENTITY,
    MALFORMED,
    MISSING,
    MISMATCH,
    REVOKED,
    UNKNOWN,
    VALID,
    VERIFIER,
    AuthorityRegistryError,
    DurableAuthorityRegistry,
    resolve_human_approval,
)


NOW = "2026-08-08T10:00:00Z"
ISSUED = "2026-08-08T09:00:00Z"
EFFECTIVE = "2026-08-08T09:30:00Z"
EXPIRES = "2026-08-08T11:00:00Z"
EXPIRED_AT = "2026-08-08T09:30:00Z"
FUTURE = "2026-08-08T10:30:00Z"

TENANT = "sha256:" + ("1" * 64)
OTHER_TENANT = "sha256:" + ("2" * 64)
ENVIRONMENT = "sha256:" + ("3" * 64)
OTHER_ENVIRONMENT = "sha256:" + ("4" * 64)
POLICY = "sha256:" + ("5" * 64)
OTHER_POLICY = "sha256:" + ("6" * 64)
POLICY_HASH = "sha256:" + ("7" * 64)
OTHER_POLICY_HASH = "sha256:" + ("8" * 64)
SUBJECT = "sha256:" + ("9" * 64)
OTHER_SUBJECT = "sha256:" + ("a" * 64)
VERIFIER_REF = "sha256:" + ("b" * 64)
OTHER_VERIFIER = "sha256:" + ("c" * 64)
PROVENANCE = "sha256:" + ("d" * 64)


DOMAIN_REFS = {
    HUMAN_APPROVAL: "sha256:" + ("e" * 64),
    ACTIVATION: "sha256:" + ("f" * 64),
    CHALLENGE: "sha256:" + ("0" * 64),
    IDENTITY: "sha256:" + ("1" * 64),
    VERIFIER: "sha256:" + ("2" * 64),
    ATTESTATION: "sha256:" + ("3" * 64),
}


def _store(tmp_path: Path) -> DurableAuthorityRegistry:
    return DurableAuthorityRegistry(tmp_path / "authority.jsonl", evidence_path=tmp_path / "authority.evidence.jsonl")


def _record(domain: str, **overrides: object) -> dict:
    record = {
        "authority_reference": DOMAIN_REFS[domain],
        "tenant_reference": TENANT,
        "environment_reference": ENVIRONMENT,
        "policy_reference": POLICY if domain in {HUMAN_APPROVAL, ACTIVATION} else "",
        "policy_hash": POLICY_HASH if domain in {HUMAN_APPROVAL, ACTIVATION} else "",
        "subject_reference": SUBJECT if domain in {CHALLENGE, IDENTITY, ATTESTATION} else "",
        "verifier_reference": VERIFIER_REF if domain in {VERIFIER, ATTESTATION} else "",
        "issued_at": ISSUED,
        "effective_at": EFFECTIVE,
        "expires_at": EXPIRES,
        "revoked": False,
        "revoked_at": "",
        "revocation_reason_code": "",
        "current_status": _status_for(domain),
        "provenance_evidence_reference": PROVENANCE,
    }
    record.update(overrides)
    return record


def _status_for(domain: str) -> str:
    return {
        HUMAN_APPROVAL: "APPROVED",
        ACTIVATION: "ACTIVATED",
        CHALLENGE: "ISSUED",
        IDENTITY: "ENROLLED",
        VERIFIER: "ENROLLED",
        ATTESTATION: "PASS",
    }[domain]


def _criteria(domain: str, **overrides: object) -> dict:
    criteria = {
        "tenant_reference": TENANT,
        "environment_reference": ENVIRONMENT,
        "now": NOW,
    }
    if domain in {HUMAN_APPROVAL, ACTIVATION}:
        criteria.update({"policy_reference": POLICY, "policy_hash": POLICY_HASH})
    if domain in {CHALLENGE, IDENTITY, ATTESTATION}:
        criteria["subject_reference"] = SUBJECT
    if domain in {VERIFIER, ATTESTATION}:
        criteria["verifier_reference"] = VERIFIER_REF
    criteria.update(overrides)
    return criteria


@pytest.mark.parametrize("domain", [HUMAN_APPROVAL, ACTIVATION, CHALLENGE, IDENTITY, VERIFIER, ATTESTATION])
def test_domain_registry_create_reopen_and_resolve_valid(tmp_path: Path, domain: str) -> None:
    _store(tmp_path).create_authority(domain, _record(domain), timestamp=ISSUED)
    reopened = DurableAuthorityRegistry(tmp_path / "authority.jsonl", evidence_path=tmp_path / "authority.evidence.jsonl")

    result = reopened.resolve_authority(domain, DOMAIN_REFS[domain], **_criteria(domain)).to_dict()

    assert result["status"] == VALID
    assert result["execution_authorized"] is False
    assert result["runtime_allow"] is False
    assert result["record_hash"].startswith("sha256:")
    assert result["evidence_reference"].startswith("sha256:")


@pytest.mark.parametrize("domain", [HUMAN_APPROVAL, ACTIVATION, CHALLENGE, IDENTITY, VERIFIER, ATTESTATION])
def test_missing_malformed_unknown_and_blocked_state_fail_closed(tmp_path: Path, domain: str) -> None:
    store = _store(tmp_path)
    missing = store.resolve_authority(domain, DOMAIN_REFS[domain], **_criteria(domain))
    malformed = store.resolve_authority(domain, "not-a-hash", **_criteria(domain))
    store.create_authority(domain, _record(domain, current_status="BOGUS"), timestamp=ISSUED)
    unknown = store.resolve_authority(domain, DOMAIN_REFS[domain], **_criteria(domain))

    assert missing.status == MISSING
    assert malformed.status == MALFORMED
    assert unknown.status == UNKNOWN


@pytest.mark.parametrize("domain", [HUMAN_APPROVAL, ACTIVATION, CHALLENGE, IDENTITY, VERIFIER, ATTESTATION])
def test_revocation_persists_across_restart(tmp_path: Path, domain: str) -> None:
    store = _store(tmp_path)
    store.create_authority(domain, _record(domain), timestamp=ISSUED)
    store.revoke_authority(
        domain,
        DOMAIN_REFS[domain],
        tenant_reference=TENANT,
        environment_reference=ENVIRONMENT,
        reason_code="HUMAN_REVOKED",
        timestamp="2026-08-08T10:05:00Z",
    )

    reopened = DurableAuthorityRegistry(tmp_path / "authority.jsonl", evidence_path=tmp_path / "authority.evidence.jsonl")
    result = reopened.resolve_authority(domain, DOMAIN_REFS[domain], **_criteria(domain)).to_dict()

    assert result["status"] == REVOKED


@pytest.mark.parametrize(
    ("override", "status", "reason"),
    (
        ({"expires_at": EXPIRED_AT}, EXPIRED, "AUTHORITY_EXPIRED"),
        ({"issued_at": FUTURE}, MALFORMED, "AUTHORITY_NOT_YET_VALID"),
        ({"issued_at": "2026-08-08 09:00:00"}, MALFORMED, "AUTHORITY_ISSUED_AT_INVALID"),
        ({"expires_at": ISSUED}, EXPIRED, "AUTHORITY_EXPIRED"),
    ),
)
def test_expiry_and_timestamp_boundaries_fail_closed(tmp_path: Path, override: dict, status: str, reason: str) -> None:
    store = _store(tmp_path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL, **override), timestamp=ISSUED)

    result = store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))

    assert result["status"] == status
    assert result["reason_code"] == reason


def test_boundary_expires_at_equal_now_is_expired(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL, expires_at=NOW), timestamp=ISSUED)

    result = store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))

    assert result["status"] == EXPIRED


@pytest.mark.parametrize(
    ("criteria_override", "reason"),
    (
        ({"tenant_reference": OTHER_TENANT}, "AUTHORITY_TENANT_MISMATCH"),
        ({"environment_reference": OTHER_ENVIRONMENT}, "AUTHORITY_ENVIRONMENT_MISMATCH"),
        ({"policy_reference": OTHER_POLICY}, "AUTHORITY_POLICY_BINDING_MISMATCH"),
        ({"policy_hash": OTHER_POLICY_HASH}, "AUTHORITY_POLICY_BINDING_MISMATCH"),
        ({"subject_reference": OTHER_SUBJECT}, "AUTHORITY_SUBJECT_MISMATCH"),
    ),
)
def test_scope_and_policy_mismatch_fail_closed(tmp_path: Path, criteria_override: dict, reason: str) -> None:
    store = _store(tmp_path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL, subject_reference=SUBJECT), timestamp=ISSUED)

    result = store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL, **criteria_override))

    assert result["status"] == MISMATCH
    assert result["reason_code"] == reason


def test_verifier_mismatch_fails_closed_for_attestation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_authority(ATTESTATION, _record(ATTESTATION), timestamp=ISSUED)

    result = store.resolve_attestation(DOMAIN_REFS[ATTESTATION], **_criteria(ATTESTATION, verifier_reference=OTHER_VERIFIER))

    assert result["status"] == MISMATCH
    assert result["reason_code"] == "AUTHORITY_VERIFIER_MISMATCH"


def test_human_approval_cannot_be_ai_or_euria_self_approval(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL, ai_generated_only=True), timestamp=ISSUED)

    result = store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))

    assert result["status"] == MISMATCH
    assert result["reason_code"] == "AUTHORITY_SOURCE_NOT_HUMAN_CONTROLLED"


def test_duplicate_creation_and_stale_writer_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)

    with pytest.raises(AuthorityRegistryError, match="DUPLICATE_AUTHORITY_RECORD"):
        store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)
    with pytest.raises(AuthorityRegistryError, match="STALE_AUTHORITY_WRITER"):
        store.update_authority(
            HUMAN_APPROVAL,
            _record(HUMAN_APPROVAL, current_status="APPROVED"),
            timestamp=NOW,
            expected_latest_hash="sha256:" + ("f" * 64),
        )
    updated = store.update_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL, current_status="APPROVED"), timestamp=NOW, expected_latest_hash=first["event_hash"])
    assert updated["event_hash"].startswith("sha256:")


def test_concurrent_revoke_read_never_returns_false_valid(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)
    observed: list[str] = []

    def revoke() -> str:
        store.revoke_authority(
            HUMAN_APPROVAL,
            DOMAIN_REFS[HUMAN_APPROVAL],
            tenant_reference=TENANT,
            environment_reference=ENVIRONMENT,
            reason_code="CONCURRENT_REVOKE",
            timestamp=NOW,
        )
        return "revoked"

    def read() -> str:
        result = store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))
        observed.append(result["status"])
        return result["status"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(revoke), pool.submit(read)]
        [future.result() for future in futures]
    final = store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))

    assert final["status"] == REVOKED
    assert set(observed) <= {VALID, REVOKED}


def test_concurrent_update_read_is_deterministic_and_hash_valid(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.create_authority(IDENTITY, _record(IDENTITY), timestamp=ISSUED)
    observed: list[str] = []

    def update() -> str:
        event = store.update_authority(IDENTITY, _record(IDENTITY, current_status="ENROLLED"), timestamp=NOW, expected_latest_hash=first["event_hash"])
        return event["event_hash"]

    def read() -> str:
        result = store.resolve_identity(DOMAIN_REFS[IDENTITY], **_criteria(IDENTITY))
        observed.append(result["status"])
        return result["status"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        [future.result() for future in (pool.submit(update), pool.submit(read))]

    assert store.resolve_identity(DOMAIN_REFS[IDENTITY], **_criteria(IDENTITY))["status"] == VALID
    assert set(observed) <= {VALID}


def test_evidence_write_failure_blocks_mutation(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence-as-directory"
    evidence_dir.mkdir()
    store = DurableAuthorityRegistry(tmp_path / "authority.jsonl", evidence_path=evidence_dir)

    with pytest.raises((AuthorityRegistryError, IsADirectoryError, PermissionError, OSError)):
        store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)

    assert not (tmp_path / "authority.jsonl").exists()


def test_corrupted_registry_returns_unknown_at_lookup(tmp_path: Path) -> None:
    path = tmp_path / "authority.jsonl"
    path.write_text("{not-json}\n", encoding="utf-8")
    store = DurableAuthorityRegistry(path, evidence_path=tmp_path / "evidence.jsonl")

    result = store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))

    assert result["status"] == UNKNOWN
    assert result["reason_code"] == "AUTHORITY_REGISTRY_CORRUPT"


def test_sensitive_payload_is_rejected_and_not_logged(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(AuthorityRegistryError, match="AUTHORITY_PAYLOAD_SENSITIVE_DATA_FORBIDDEN"):
        store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL, secret="blocked"), timestamp=ISSUED)

    assert not (tmp_path / "authority.jsonl").exists()
    assert not (tmp_path / "authority.evidence.jsonl").exists()


def test_module_level_resolver_reopens_registry(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)

    result = resolve_human_approval(tmp_path / "authority.jsonl", DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))

    assert result["status"] == VALID


def test_evidence_log_is_hash_only_and_safe(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_authority(ATTESTATION, _record(ATTESTATION), timestamp=ISSUED)
    text = (tmp_path / "authority.evidence.jsonl").read_text(encoding="utf-8").lower()
    event = json.loads(text.splitlines()[0])

    assert event["execution_authorized"] is False
    assert event["runtime_allow"] is False
    assert event["evidence_hash"].startswith("sha256:")
    assert "password" not in text
    assert "secret" not in text
    assert "raw_payload" not in text
