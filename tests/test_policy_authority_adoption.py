from __future__ import annotations

import json
import multiprocessing
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

import runtime.policy_validator as policy_validator
from runtime.computer_use.ai_act_live_policy_engine import (
    load_adopted_human_policy_authority,
    revalidate_adopted_human_policy_authority,
)
from security.policy_authority_adoption_store import (
    PolicyAuthorityAdoptionError,
    adopt_current_scoped_policy_authority,
    load_adopted_policy_authority,
)
from security.policy_authority_replay_registry import SQLitePolicyAuthorityReplayRegistry
from tests.test_governance_validation import _sha_ref, _write_policy_authority_fixture


POLICY_ID = "ci_security"
TENANT = _sha_ref("tenant-t1")
OTHER_TENANT = _sha_ref("tenant-other")
ENVIRONMENT_REFERENCE = _sha_ref("environment-production")
ENVIRONMENT = "production"


def _scoped_approvals(approvals: list[dict]) -> None:
    for approval in approvals:
        approval.update(
            {
                "schema_version": "usbay.policy_authority_approval.scoped.v1",
                "policy_id": POLICY_ID,
                "tenant_reference": TENANT,
                "environment_reference": ENVIRONMENT_REFERENCE,
            }
        )


def _fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **kwargs):
    tmp_path.mkdir(parents=True, exist_ok=True)
    return _write_policy_authority_fixture(
        monkeypatch,
        tmp_path,
        approval_mutation=kwargs.pop("approval_mutation", _scoped_approvals),
        **kwargs,
    )


def _arguments(path: Path) -> dict:
    return {
        "policy_id": POLICY_ID,
        "policy_hash": policy_validator.compute_policy_hash(),
        "policy_version": "1.0",
        "tenant_reference": TENANT,
        "environment_reference": ENVIRONMENT_REFERENCE,
        "environment": ENVIRONMENT,
        "store": SQLitePolicyAuthorityReplayRegistry(path),
    }


def _adopt(path: Path):
    return adopt_current_scoped_policy_authority(**_arguments(path))


def _child_load(path: str, adoption_id: str, output) -> None:
    try:
        raw = SQLitePolicyAuthorityReplayRegistry(path).load_adoption(adoption_id)
        output.put(bool(raw))
    except Exception:
        output.put(False)


def test_scoped_inspection_and_runtime_reads_are_side_effect_free(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)
    bundle = policy_validator.inspect_scoped_policy_approval_artifacts(
        policy_id=POLICY_ID,
        policy_hash=policy_validator.compute_policy_hash(),
        policy_version="1.0",
        tenant_reference=TENANT,
        environment_reference=ENVIRONMENT_REFERENCE,
        environment=ENVIRONMENT,
    )
    assert not paths["replay_db"].exists()

    adopted = _adopt(paths["replay_db"])
    before = paths["replay_db"].read_bytes()
    loaded = load_adopted_policy_authority(
        adoption_id=adopted.adoption_id,
        now=datetime.now(timezone.utc),
        **_arguments(paths["replay_db"]),
    )
    assert loaded.tenant_reference == TENANT
    assert paths["replay_db"].read_bytes() == before
    assert bundle.approval_nonce_hashes == loaded.approval_nonce_hashes


@pytest.mark.parametrize("field,value", (("tenant_reference", OTHER_TENANT), ("environment_reference", _sha_ref("other-env")), ("environment", "staging")))
def test_signed_scope_substitution_blocks(monkeypatch, tmp_path, field, value) -> None:
    _fixture(monkeypatch, tmp_path)
    arguments = _arguments(tmp_path / "policy_authority_replay.db")
    arguments[field] = value
    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_SCOPE_MISMATCH"):
        adopt_current_scoped_policy_authority(**arguments)


def test_missing_or_global_scope_and_legacy_format_block(monkeypatch, tmp_path) -> None:
    _write_policy_authority_fixture(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_SCOPED_FORMAT_REQUIRED"):
        _adopt(tmp_path / "policy_authority_replay.db")
    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_SCOPE_INVALID"):
        adopt_current_scoped_policy_authority(**{**_arguments(tmp_path / "other.db"), "tenant_reference": "GLOBAL"})


def test_two_independent_human_approvers_remain_required(monkeypatch, tmp_path) -> None:
    _fixture(monkeypatch, tmp_path, same_approver=True)
    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_DUPLICATE_APPROVER"):
        _adopt(tmp_path / "policy_authority_replay.db")


def test_legacy_consumption_and_adoption_share_nonce_boundary(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)
    metadata = policy_validator.load_policy_metadata()
    policy_validator.validate_approval_artifacts(policy_hash=metadata["policy_hash"], policy_version=metadata["policy_version"])
    with pytest.raises(PolicyAuthorityAdoptionError, match="POLICY_ADOPTION_ADOPTION_CONFLICT"):
        _adopt(paths["replay_db"])

    other = tmp_path / "reverse"
    paths = _fixture(monkeypatch, other)
    _adopt(paths["replay_db"])
    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_REUSE_DETECTED"):
        policy_validator.validate_approval_artifacts(policy_hash=metadata["policy_hash"], policy_version=metadata["policy_version"])


def test_concurrent_legacy_and_adoption_have_exactly_one_winner(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)
    metadata = policy_validator.load_policy_metadata()

    def legacy() -> str:
        try:
            policy_validator.validate_approval_artifacts(policy_hash=metadata["policy_hash"], policy_version=metadata["policy_version"])
            return "legacy"
        except RuntimeError:
            return "blocked"

    def adoption() -> str:
        try:
            _adopt(paths["replay_db"])
            return "adoption"
        except PolicyAuthorityAdoptionError:
            return "blocked"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = [executor.submit(legacy), executor.submit(adoption)]
    values = [result.result() for result in results]
    assert values.count("blocked") == 1
    assert len({value for value in values if value != "blocked"}) == 1


def test_atomic_rollback_idempotent_retry_conflict_and_process_reopen(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)

    def fail_after_second_nonce(position: int, _nonce: str) -> None:
        if position == 2:
            raise RuntimeError("injected adoption failure")

    failing = SQLitePolicyAuthorityReplayRegistry(paths["replay_db"], after_insert=fail_after_second_nonce)
    with pytest.raises(PolicyAuthorityAdoptionError, match="POLICY_ADOPTION_PARTIAL_WRITE"):
        adopt_current_scoped_policy_authority(**{**_arguments(paths["replay_db"]), "store": failing})
    with sqlite3.connect(paths["replay_db"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM policy_authority_consumed_nonces").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM policy_authority_adoptions").fetchone()[0] == 0

    first = _adopt(paths["replay_db"])
    retry = _adopt(paths["replay_db"])
    assert retry == first

    replacement = _fixture(monkeypatch, tmp_path / "replacement")
    with pytest.raises(PolicyAuthorityAdoptionError, match="POLICY_ADOPTION_ADOPTION_CONFLICT"):
        adopt_current_scoped_policy_authority(
            **{**_arguments(paths["replay_db"]), "store": SQLitePolicyAuthorityReplayRegistry(paths["replay_db"])}
        )

    ctx = multiprocessing.get_context("fork")
    output = ctx.Queue()
    process = ctx.Process(target=_child_load, args=(str(paths["replay_db"]), first.adoption_id, output))
    process.start()
    process.join(10)
    assert process.exitcode == 0
    assert output.get(timeout=2) is True

    with sqlite3.connect(paths["replay_db"]) as connection:
        connection.execute(
            "UPDATE policy_authority_adoptions SET record_json = ? WHERE adoption_id = ?",
            (json.dumps({"schema_version": "usbay.policy_authority_adoption.v1"}), first.adoption_id),
        )
    with pytest.raises(PolicyAuthorityAdoptionError, match="RECORD_CORRUPT"):
        load_adopted_policy_authority(adoption_id=first.adoption_id, **_arguments(paths["replay_db"]))


def test_uncertain_commit_is_reconciled_from_durable_state(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)

    def report_failure_after_commit() -> None:
        raise RuntimeError("simulated lost commit acknowledgement")

    store = SQLitePolicyAuthorityReplayRegistry(paths["replay_db"], after_commit=report_failure_after_commit)
    adopted = adopt_current_scoped_policy_authority(**{**_arguments(paths["replay_db"]), "store": store})
    assert SQLitePolicyAuthorityReplayRegistry(paths["replay_db"]).load_adoption(adopted.adoption_id)


def test_deleted_adoption_record_is_detected_by_store_state_hash(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)
    adopted = _adopt(paths["replay_db"])
    with sqlite3.connect(paths["replay_db"]) as connection:
        connection.execute("DELETE FROM policy_authority_adoptions WHERE adoption_id = ?", (adopted.adoption_id,))
    with pytest.raises(PolicyAuthorityAdoptionError, match="STORE_UNAVAILABLE"):
        load_adopted_policy_authority(adoption_id=adopted.adoption_id, **_arguments(paths["replay_db"]))


def test_runtime_loader_and_revalidation_block_changed_signed_state(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)
    adopted = _adopt(paths["replay_db"])
    arguments = {
        "adoption_id": adopted.adoption_id,
        "policy_id": POLICY_ID,
        "policy_hash": policy_validator.compute_policy_hash(),
        "policy_version": "1.0",
        "tenant_reference": TENANT,
        "environment_reference": ENVIRONMENT_REFERENCE,
        "environment": ENVIRONMENT,
        "adoption_store": SQLitePolicyAuthorityReplayRegistry(paths["replay_db"]),
    }
    authority = load_adopted_human_policy_authority(**arguments)
    before = paths["replay_db"].read_bytes()
    assert revalidate_adopted_human_policy_authority(authority, **arguments) == authority
    assert paths["replay_db"].read_bytes() == before
    registry = json.loads(paths["registry_json"].read_text(encoding="utf-8"))
    registry["approvers"][0]["revoked"] = True
    paths["registry_json"].write_text(json.dumps(registry), encoding="utf-8")
    with pytest.raises(Exception):
        revalidate_adopted_human_policy_authority(authority, **arguments)


def test_missing_unavailable_and_expired_adoption_block(monkeypatch, tmp_path) -> None:
    _fixture(monkeypatch, tmp_path)
    with pytest.raises(PolicyAuthorityAdoptionError, match="POLICY_ADOPTION_MISSING"):
        load_adopted_policy_authority(adoption_id=_sha_ref("missing"), **_arguments(tmp_path / "missing.db"))
    adopted = adopt_current_scoped_policy_authority(
        **_arguments(tmp_path / "policy_authority_replay.db"),
        adopted_at="2020-01-01T00:00:00Z",
    )
    with pytest.raises(PolicyAuthorityAdoptionError, match="POLICY_ADOPTION_EXPIRED"):
        load_adopted_policy_authority(
            adoption_id=adopted.adoption_id,
            now="2100-01-01T00:00:00Z",
            **_arguments(tmp_path / "policy_authority_replay.db"),
        )


def test_locked_store_and_revoked_approval_fail_closed(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)
    blocker = sqlite3.connect(paths["replay_db"], isolation_level=None)
    SQLitePolicyAuthorityReplayRegistry(paths["replay_db"]).consume_if_unused(
        ("1" * 64, "2" * 64),
        registry_evidence_hash=_sha_ref("replay-registry"),
        consumed_at="2026-10-16T00:00:00Z",
    )
    blocker.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(PolicyAuthorityAdoptionError, match="POLICY_ADOPTION_TIMEOUT"):
            adopt_current_scoped_policy_authority(
                **{**_arguments(paths["replay_db"]), "store": SQLitePolicyAuthorityReplayRegistry(paths["replay_db"], timeout_seconds=0.01)}
            )
    finally:
        blocker.rollback()
        blocker.close()

    def revoked(approvals: list[dict]) -> None:
        _scoped_approvals(approvals)
        approvals[0]["revoked"] = True

    _fixture(monkeypatch, tmp_path / "revoked", approval_mutation=revoked)
    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_REVOKED"):
        _adopt(tmp_path / "revoked" / "policy_authority_replay.db")


def test_changed_policy_content_blocks_runtime_load(monkeypatch, tmp_path) -> None:
    paths = _fixture(monkeypatch, tmp_path)
    adopted = _adopt(paths["replay_db"])
    changed_policy = tmp_path / "changed-policy.json"
    changed_policy.write_text('{"policy_version":"1.0","scope":"ci_security","changed":true}', encoding="utf-8")
    changed_hash = tmp_path / "changed-policy.sha256"
    changed_hash.write_text(__import__("hashlib").sha256(changed_policy.read_bytes()).hexdigest(), encoding="utf-8")
    monkeypatch.setattr(policy_validator, "POLICY_JSON", changed_policy)
    monkeypatch.setattr(policy_validator, "POLICY_SHA256", changed_hash)
    with pytest.raises(Exception):
        load_adopted_policy_authority(adoption_id=adopted.adoption_id, **_arguments(paths["replay_db"]))
