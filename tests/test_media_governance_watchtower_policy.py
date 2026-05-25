from __future__ import annotations

from tests.helpers.media_governance_watchtower_policy import (
    load_media_governance_watchtower_manifest,
    load_media_governance_watchtower_policy,
    valid_watchtower_metrics,
    verify_governance_watchtower,
    verify_watchtower_manifest,
)


def test_valid_governance_watchtower_metrics_pass() -> None:
    evidence = verify_governance_watchtower(valid_watchtower_metrics())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_GOVERNANCE_HEALTH_VALID"
    assert evidence["escalation_state"] == "GOVERNANCE_HEALTHY"


def test_repeated_drift_events_degrade_governance_score() -> None:
    metrics = valid_watchtower_metrics()
    metrics["drift_event_count"] = 3

    evidence = verify_governance_watchtower(metrics)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_REPEATED_DRIFT_EVENTS"
    assert evidence["escalation_state"] == "GOVERNANCE_DEGRADED"
    assert evidence["silent_pass"] is False


def test_unresolved_jurisdiction_conflicts_fail_closed() -> None:
    metrics = valid_watchtower_metrics()
    metrics["jurisdiction_conflicts"] = 1

    evidence = verify_governance_watchtower(metrics)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_UNRESOLVED_JURISDICTION_CONFLICTS"
    assert evidence["silent_pass"] is False


def test_excessive_revocations_trigger_governance_degradation() -> None:
    metrics = valid_watchtower_metrics()
    metrics["revocation_frequency"] = 3

    evidence = verify_governance_watchtower(metrics)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_REPEATED_REVOCATION_EVENTS"
    assert evidence["escalation_state"] == "GOVERNANCE_DEGRADED"
    assert evidence["silent_pass"] is False


def test_export_instability_affects_governance_health() -> None:
    metrics = valid_watchtower_metrics()
    metrics["export_failures"] = 2

    evidence = verify_governance_watchtower(metrics)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_EXPORT_FAILURE_PATTERN"
    assert evidence["silent_pass"] is False


def test_lineage_instability_fails_closed() -> None:
    metrics = valid_watchtower_metrics()
    metrics["lineage_breaks"] = 1

    evidence = verify_governance_watchtower(metrics)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_LINEAGE_INSTABILITY"
    assert evidence["silent_pass"] is False


def test_distribution_governance_decay_fails_closed() -> None:
    metrics = valid_watchtower_metrics()
    metrics["distribution_scope_failures"] = 3

    evidence = verify_governance_watchtower(metrics)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_DISTRIBUTION_GOVERNANCE_DECAY"
    assert evidence["silent_pass"] is False


def test_governance_critical_state_blocks_release() -> None:
    metrics = valid_watchtower_metrics()
    metrics["governance_health_score"] = 40

    evidence = verify_governance_watchtower(metrics)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_GOVERNANCE_CRITICAL"
    assert evidence["escalation_state"] == "GOVERNANCE_CRITICAL"
    assert evidence["silent_pass"] is False


def test_missing_governance_visibility_fails_closed() -> None:
    metrics = valid_watchtower_metrics()
    metrics["governance_visibility_present"] = False

    evidence = verify_governance_watchtower(metrics)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_VISIBILITY_MISSING"
    assert evidence["silent_pass"] is False


def test_watchtower_manifest_passes() -> None:
    evidence = verify_watchtower_manifest(load_media_governance_watchtower_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_WATCHTOWER_GOVERNANCE_HEALTH_VALID"


def test_governance_watchtower_policy_is_non_production_scaffolding() -> None:
    policy = load_media_governance_watchtower_policy()

    assert policy["governance_health_scoring_enabled"] is True
    assert policy["fail_closed_on_critical_governance_score"] is True
    assert policy["fail_closed_on_repeated_drift_events"] is True
    assert policy["fail_closed_on_lineage_instability"] is True
    assert policy["fail_closed_on_export_failure_pattern"] is True
    assert policy["fail_closed_on_repeated_revocation_events"] is True
    assert policy["fail_closed_on_unresolved_jurisdiction_conflicts"] is True
    assert policy["fail_closed_on_distribution_governance_decay"] is True
    assert policy["fail_closed_on_missing_governance_visibility"] is True
    assert policy["governance_watchtower_enabled"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["governance_health_states"]) == {
        "GOVERNANCE_HEALTHY",
        "GOVERNANCE_WARNING",
        "GOVERNANCE_DEGRADED",
        "GOVERNANCE_CRITICAL",
        "GOVERNANCE_FAIL_CLOSED",
    }
