from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit.rfc3161_anchor import TimestampVerificationError
from security.deployment_attestation import (
    DEFAULT_GOVERNANCE_RELEASE_PATH,
    DeploymentAttestationError,
    RuntimeProvenanceAuthority,
    assert_runtime_provenance_authority,
    canonical_json,
    current_git_commit,
    load_release_manifest,
    policy_bundle_hash,
    release_hash,
    resolve_runtime_provenance_authority,
    validate_normalized_provenance_context,
    validate_release_manifest,
)


class RuntimeGovernanceDriftError(RuntimeError):
    pass


DEFAULT_RUNTIME_GOVERNANCE_POLICY_PATH = Path("governance/runtime_governance_policy.json")
DEFAULT_RUNTIME_DIAGNOSTICS_DIR = Path("tmp/runtime_governance")
RUNTIME_HEALTH_FILE = "governance_runtime_health.json"
ATTESTATION_FRESHNESS_FILE = "attestation_freshness.json"
RUNTIME_DRIFT_REPORT_FILE = "runtime_drift_report.json"


@dataclass(frozen=True)
class RuntimeGovernancePolicy:
    release_manifest_max_age_seconds: int
    authority_bootstrap_max_age_seconds: int
    rfc3161_timestamp_max_age_seconds: int
    max_attestation_age_seconds: int
    monitor_interval_seconds: int
    require_runtime_rfc3161_timestamp: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_bootstrap_max_age_seconds": self.authority_bootstrap_max_age_seconds,
            "max_attestation_age_seconds": self.max_attestation_age_seconds,
            "monitor_interval_seconds": self.monitor_interval_seconds,
            "release_manifest_max_age_seconds": self.release_manifest_max_age_seconds,
            "require_runtime_rfc3161_timestamp": self.require_runtime_rfc3161_timestamp,
            "rfc3161_timestamp_max_age_seconds": self.rfc3161_timestamp_max_age_seconds,
        }


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception as exc:
        raise RuntimeGovernanceDriftError("governance_timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeGovernanceDriftError("governance_timestamp_invalid")
    return parsed.astimezone(timezone.utc)


def _load_json(path: Path, reason: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeGovernanceDriftError(reason) from exc
    if not isinstance(data, dict):
        raise RuntimeGovernanceDriftError(reason)
    return data


def _positive_int(data: dict[str, Any], key: str) -> int:
    try:
        value = int(data[key])
    except Exception as exc:
        raise RuntimeGovernanceDriftError(f"runtime_governance_policy_invalid:{key}") from exc
    if value <= 0:
        raise RuntimeGovernanceDriftError(f"runtime_governance_policy_invalid:{key}")
    return value


def load_runtime_governance_policy(
    path: Path | str = DEFAULT_RUNTIME_GOVERNANCE_POLICY_PATH,
) -> RuntimeGovernancePolicy:
    data = _load_json(Path(path), "runtime_governance_policy_missing")
    return RuntimeGovernancePolicy(
        release_manifest_max_age_seconds=_positive_int(data, "release_manifest_max_age_seconds"),
        authority_bootstrap_max_age_seconds=_positive_int(data, "authority_bootstrap_max_age_seconds"),
        rfc3161_timestamp_max_age_seconds=_positive_int(data, "rfc3161_timestamp_max_age_seconds"),
        max_attestation_age_seconds=_positive_int(data, "max_attestation_age_seconds"),
        monitor_interval_seconds=_positive_int(data, "monitor_interval_seconds"),
        require_runtime_rfc3161_timestamp=bool(data.get("require_runtime_rfc3161_timestamp", False)),
    )


def _age_seconds(created_at: datetime, now: datetime) -> float:
    return (now - created_at).total_seconds()


def _freshness_entry(
    *,
    control_id: str,
    created_at: datetime,
    now: datetime,
    max_age_seconds: int,
) -> dict[str, Any]:
    age = _age_seconds(created_at, now)
    return {
        "control_id": control_id,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "age_seconds": int(age),
        "max_age_seconds": max_age_seconds,
        "fresh": age >= 0 and age <= max_age_seconds,
    }


def _optional_timestamp_freshness(
    path: Path | None,
    *,
    now: datetime,
    policy: RuntimeGovernancePolicy,
) -> dict[str, Any]:
    if path is None or not path.exists():
        return {
            "control_id": "rfc3161_timestamp_freshness",
            "required": policy.require_runtime_rfc3161_timestamp,
            "fresh": not policy.require_runtime_rfc3161_timestamp,
            "reason": "timestamp_verification_not_configured",
        }
    data = _load_json(path, "timestamp_verification_malformed")
    if data.get("valid") is not True:
        raise RuntimeGovernanceDriftError("timestamp_verification_invalid")
    created = _parse_utc(str(data.get("created_at", "")))
    entry = _freshness_entry(
        control_id="rfc3161_timestamp_freshness",
        created_at=created,
        now=now,
        max_age_seconds=min(policy.rfc3161_timestamp_max_age_seconds, policy.max_attestation_age_seconds),
    )
    entry["timestamp_hash"] = data.get("timestamp_hash")
    entry["message_imprint"] = data.get("message_imprint")
    return entry


def _write_diagnostics(output_dir: Path, payloads: dict[str, dict[str, Any]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in payloads.items():
        (output_dir / name).write_text(canonical_json(payload) + "\n", encoding="utf-8")


class RuntimeGovernanceMonitor:
    def __init__(
        self,
        *,
        authority: RuntimeProvenanceAuthority | None = None,
        release_path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH,
        policy_path: Path | str = DEFAULT_RUNTIME_GOVERNANCE_POLICY_PATH,
        timestamp_verification_path: Path | str | None = None,
        started_at: datetime | None = None,
    ) -> None:
        self.release_path = Path(release_path)
        self.policy_path = Path(policy_path)
        self.policy = load_runtime_governance_policy(self.policy_path)
        self.authority = authority or resolve_runtime_provenance_authority(self.release_path)
        self.started_at = (started_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        self.timestamp_verification_path = Path(timestamp_verification_path) if timestamp_verification_path else None

    def _drift_report(self, now: datetime) -> dict[str, Any]:
        controls: dict[str, dict[str, Any]] = {}
        drift_reasons: list[str] = []
        try:
            assert_runtime_provenance_authority(self.authority, self.release_path)
            controls["authority_identity"] = {"status": "PASS", "authority_id": self.authority.authority_id}
        except DeploymentAttestationError as exc:
            controls["authority_identity"] = {"status": "FAIL", "reason": str(exc)}
            drift_reasons.append("authority_identity_drift")

        try:
            current_policy_hash = policy_bundle_hash()
            controls["policy_bundle_hash"] = {
                "status": "PASS" if current_policy_hash == self.authority.policy_bundle_hash else "FAIL",
                "expected": self.authority.policy_bundle_hash,
                "observed": current_policy_hash,
            }
            if current_policy_hash != self.authority.policy_bundle_hash:
                drift_reasons.append("policy_drift")
        except Exception as exc:
            controls["policy_bundle_hash"] = {"status": "FAIL", "reason": str(exc) or "policy_drift"}
            drift_reasons.append("policy_drift")

        try:
            manifest = load_release_manifest(self.release_path)
            observed_release_hash = release_hash(manifest)
            controls["release_hash"] = {
                "status": "PASS" if observed_release_hash == self.authority.release_hash else "FAIL",
                "expected": self.authority.release_hash,
                "observed": observed_release_hash,
            }
            if observed_release_hash != self.authority.release_hash:
                drift_reasons.append("provenance_drift")
            validate_release_manifest(
                self.release_path,
                expected_provenance_context=self.authority.context_dict(),
            )
            validate_normalized_provenance_context(self.authority.context_dict(), str(manifest.get("git_commit", "")))
            current_commit = current_git_commit()
            context = self.authority.context_dict()
            lineage_ok = (
                current_commit == context.get("current_commit")
                or current_commit in set(context.get("accepted_commit_set", []))
            )
            controls["runtime_lineage"] = {
                "status": "PASS" if lineage_ok else "FAIL",
                "current_commit": current_commit,
                "authority_current_commit": context.get("current_commit"),
            }
            if not lineage_ok:
                drift_reasons.append("runtime_lineage_divergence")
        except Exception as exc:
            controls["release_manifest"] = {"status": "FAIL", "reason": str(exc) or "provenance_drift"}
            drift_reasons.append("provenance_drift")

        return {
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "drift_detected": bool(drift_reasons),
            "drift_reasons": sorted(set(drift_reasons)),
            "controls": controls,
        }

    def _freshness_report(self, now: datetime) -> dict[str, Any]:
        manifest = load_release_manifest(self.release_path)
        release_entry = _freshness_entry(
            control_id="release_manifest_freshness",
            created_at=_parse_utc(str(manifest.get("deployment_timestamp", ""))),
            now=now,
            max_age_seconds=min(
                self.policy.release_manifest_max_age_seconds,
                max(self.policy.release_manifest_max_age_seconds, self.policy.max_attestation_age_seconds),
            ),
        )
        authority_entry = _freshness_entry(
            control_id="authority_bootstrap_freshness",
            created_at=self.started_at,
            now=now,
            max_age_seconds=min(
                self.policy.authority_bootstrap_max_age_seconds,
                self.policy.max_attestation_age_seconds,
            ),
        )
        timestamp_entry = _optional_timestamp_freshness(
            self.timestamp_verification_path,
            now=now,
            policy=self.policy,
        )
        entries = [release_entry, authority_entry, timestamp_entry]
        stale = [str(entry["control_id"]) for entry in entries if entry.get("fresh") is not True]
        return {
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "max_attestation_age_seconds": self.policy.max_attestation_age_seconds,
            "fresh": not stale,
            "stale_controls": stale,
            "controls": entries,
        }

    def validate_once(
        self,
        *,
        now: datetime | None = None,
        output_dir: Path | str | None = None,
    ) -> dict[str, Any]:
        current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        drift = self._drift_report(current_time)
        freshness = self._freshness_report(current_time)
        failed = list(drift.get("drift_reasons", [])) + list(freshness.get("stale_controls", []))
        passed_controls = 6 - len(set(failed))
        continuity_score = max(0, int((passed_controls / 6) * 100))
        health = {
            "generated_at": current_time.isoformat().replace("+00:00", "Z"),
            "status": "FAIL" if failed else "PASS",
            "failed_control_ids": sorted(set(str(item) for item in failed)),
            "governance_continuity_score": continuity_score,
            "authority_id": self.authority.authority_id,
            "release_hash": self.authority.release_hash,
            "policy_bundle_hash": self.authority.policy_bundle_hash,
            "tenant_id": self.authority.tenant_id,
        }
        payloads = {
            RUNTIME_HEALTH_FILE: health,
            ATTESTATION_FRESHNESS_FILE: freshness,
            RUNTIME_DRIFT_REPORT_FILE: drift,
        }
        if output_dir is not None:
            _write_diagnostics(Path(output_dir), payloads)
        if failed:
            raise RuntimeGovernanceDriftError(",".join(health["failed_control_ids"]))
        return {
            "health": health,
            "attestation_freshness": freshness,
            "runtime_drift_report": drift,
        }

    def run_periodic(
        self,
        *,
        iterations: int = 1,
        output_dir: Path | str | None = DEFAULT_RUNTIME_DIAGNOSTICS_DIR,
    ) -> dict[str, Any]:
        if iterations <= 0:
            raise RuntimeGovernanceDriftError("runtime_monitor_iterations_invalid")
        result: dict[str, Any] | None = None
        for index in range(iterations):
            result = self.validate_once(output_dir=output_dir)
            if index + 1 < iterations:
                time.sleep(self.policy.monitor_interval_seconds)
        return result or {}


def validate_runtime_governance_health(
    *,
    authority: RuntimeProvenanceAuthority | None = None,
    release_path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH,
    policy_path: Path | str = DEFAULT_RUNTIME_GOVERNANCE_POLICY_PATH,
    timestamp_verification_path: Path | str | None = None,
    output_dir: Path | str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    monitor = RuntimeGovernanceMonitor(
        authority=authority,
        release_path=release_path,
        policy_path=policy_path,
        timestamp_verification_path=timestamp_verification_path,
        started_at=now,
    )
    return monitor.validate_once(now=now, output_dir=output_dir)


def main() -> int:
    try:
        result = validate_runtime_governance_health(output_dir=DEFAULT_RUNTIME_DIAGNOSTICS_DIR)
    except (RuntimeGovernanceDriftError, TimestampVerificationError) as exc:
        print(canonical_json({"result": "FAIL", "reason": str(exc)}))
        return 1
    print(canonical_json({"result": "PASS", "health": result["health"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
