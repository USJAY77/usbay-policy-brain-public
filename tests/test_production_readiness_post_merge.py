from __future__ import annotations

from pathlib import Path

from governance.production_readiness_post_merge import evaluate_post_merge_health


def test_post_merge_health_ready_and_flags_false() -> None:
    result = evaluate_post_merge_health()

    assert result.status == "READY"
    assert result.reason_codes == ()
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.release_authorized is False
    assert result.to_dict()["health_hash"].startswith("sha256:")


def test_post_merge_health_blocks_when_required_file_missing(tmp_path: Path) -> None:
    result = evaluate_post_merge_health(root=tmp_path)

    assert result.status == "BLOCKED"
    assert any(reason.startswith("POST_MERGE_PHASE1_FILE_MISSING") for reason in result.reason_codes)
    assert result.execution_allowed is False
    assert result.release_authorized is False
