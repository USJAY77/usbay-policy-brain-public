from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from governance_runtime_monitor import (
    ATTESTATION_FRESHNESS_FILE,
    RUNTIME_DRIFT_REPORT_FILE,
    RUNTIME_HEALTH_FILE,
    RuntimeGovernanceDriftError,
    RuntimeGovernanceMonitor,
    validate_runtime_governance_health,
)
from security.deployment_attestation import (
    canonical_json,
    resolve_runtime_provenance_authority,
    sign_release_manifest,
)
from tests.provenance_helpers import valid_test_release_manifest


NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _policy(tmp_path: Path, **overrides) -> Path:
    data = {
        "authority_bootstrap_max_age_seconds": 3600,
        "max_attestation_age_seconds": 3600,
        "monitor_interval_seconds": 1,
        "release_manifest_max_age_seconds": 3600,
        "require_runtime_rfc3161_timestamp": False,
        "rfc3161_timestamp_max_age_seconds": 3600,
    }
    data.update(overrides)
    path = tmp_path / "runtime_governance_policy.json"
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return path


def _release(tmp_path: Path, *, deployed_at: datetime = NOW) -> Path:
    manifest = valid_test_release_manifest()
    manifest["deployment_timestamp"] = deployed_at.isoformat().replace("+00:00", "Z")
    manifest["release_signature"] = sign_release_manifest(manifest)
    path = tmp_path / "governance_release.json"
    path.write_text(canonical_json(manifest), encoding="utf-8")
    return path


def _timestamp_verification(tmp_path: Path, *, created_at: datetime) -> Path:
    path = tmp_path / "timestamp_verification.json"
    path.write_text(
        canonical_json(
            {
                "valid": True,
                "created_at": created_at.isoformat().replace("+00:00", "Z"),
                "timestamp_hash": "timestamp-hash",
                "message_imprint": "message-imprint",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_runtime_governance_health_writes_deterministic_diagnostics(tmp_path: Path) -> None:
    release_path = _release(tmp_path)
    authority = resolve_runtime_provenance_authority(release_path)
    output = tmp_path / "diagnostics"

    first = validate_runtime_governance_health(
        authority=authority,
        release_path=release_path,
        policy_path=_policy(tmp_path),
        output_dir=output,
        now=NOW,
    )
    second = validate_runtime_governance_health(
        authority=authority,
        release_path=release_path,
        policy_path=_policy(tmp_path),
        output_dir=output,
        now=NOW,
    )

    assert first == second
    assert first["health"]["status"] == "PASS"
    assert first["health"]["governance_continuity_score"] == 100
    assert (output / RUNTIME_HEALTH_FILE).is_file()
    assert (output / ATTESTATION_FRESHNESS_FILE).is_file()
    assert (output / RUNTIME_DRIFT_REPORT_FILE).is_file()


def test_stale_manifest_rejected_fail_closed(tmp_path: Path) -> None:
    release_path = _release(tmp_path, deployed_at=NOW - timedelta(seconds=120))
    authority = resolve_runtime_provenance_authority(release_path)

    with pytest.raises(RuntimeGovernanceDriftError, match="release_manifest_freshness"):
        validate_runtime_governance_health(
            authority=authority,
            release_path=release_path,
            policy_path=_policy(tmp_path, release_manifest_max_age_seconds=30),
            now=NOW,
        )


def test_stale_attestation_rejected_fail_closed(tmp_path: Path) -> None:
    release_path = _release(tmp_path)
    authority = resolve_runtime_provenance_authority(release_path)
    monitor = RuntimeGovernanceMonitor(
        authority=authority,
        release_path=release_path,
        policy_path=_policy(tmp_path, authority_bootstrap_max_age_seconds=30),
        started_at=NOW - timedelta(seconds=120),
    )

    with pytest.raises(RuntimeGovernanceDriftError, match="authority_bootstrap_freshness"):
        monitor.validate_once(now=NOW)


def test_policy_drift_detection_fails_closed(tmp_path: Path) -> None:
    release_path = _release(tmp_path)
    authority = resolve_runtime_provenance_authority(release_path)
    drifted = replace(authority, policy_bundle_hash="0" * 64)

    with pytest.raises(RuntimeGovernanceDriftError, match="policy_drift|runtime_provenance_authority_mismatch"):
        validate_runtime_governance_health(
            authority=drifted,
            release_path=release_path,
            policy_path=_policy(tmp_path),
            now=NOW,
        )


def test_authority_drift_detection_fails_closed(tmp_path: Path) -> None:
    release_path = _release(tmp_path)
    authority = resolve_runtime_provenance_authority(release_path)
    manifest = json.loads(release_path.read_text(encoding="utf-8"))
    manifest["release_id"] = "tampered-release-id"
    manifest["release_signature"] = sign_release_manifest(manifest)
    release_path.write_text(canonical_json(manifest), encoding="utf-8")

    with pytest.raises(RuntimeGovernanceDriftError, match="authority_identity_drift|provenance_drift"):
        validate_runtime_governance_health(
            authority=authority,
            release_path=release_path,
            policy_path=_policy(tmp_path),
            now=NOW,
        )


def test_rfc3161_replay_window_rejection(tmp_path: Path) -> None:
    release_path = _release(tmp_path)
    authority = resolve_runtime_provenance_authority(release_path)
    timestamp_path = _timestamp_verification(tmp_path, created_at=NOW - timedelta(seconds=120))

    with pytest.raises(RuntimeGovernanceDriftError, match="rfc3161_timestamp_freshness"):
        validate_runtime_governance_health(
            authority=authority,
            release_path=release_path,
            policy_path=_policy(
                tmp_path,
                require_runtime_rfc3161_timestamp=True,
                rfc3161_timestamp_max_age_seconds=30,
            ),
            timestamp_verification_path=timestamp_path,
            now=NOW,
        )


def test_missing_required_rfc3161_runtime_timestamp_fails_closed(tmp_path: Path) -> None:
    release_path = _release(tmp_path)
    authority = resolve_runtime_provenance_authority(release_path)

    with pytest.raises(RuntimeGovernanceDriftError, match="rfc3161_timestamp_freshness"):
        validate_runtime_governance_health(
            authority=authority,
            release_path=release_path,
            policy_path=_policy(tmp_path, require_runtime_rfc3161_timestamp=True),
            now=NOW,
        )


def test_periodic_monitor_single_iteration_passes(tmp_path: Path) -> None:
    release_path = _release(tmp_path)
    authority = resolve_runtime_provenance_authority(release_path)
    monitor = RuntimeGovernanceMonitor(
        authority=authority,
        release_path=release_path,
        policy_path=_policy(tmp_path),
        started_at=NOW,
    )

    result = monitor.run_periodic(iterations=1, output_dir=tmp_path / "periodic")

    assert result["health"]["status"] == "PASS"
    assert (tmp_path / "periodic" / RUNTIME_HEALTH_FILE).is_file()
