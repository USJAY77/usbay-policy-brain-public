from __future__ import annotations

from typing import Any

from governance.policy_registry_contracts import validate_policy_record


class PolicyRegistry:
    def __init__(self, policies: list[dict[str, Any]] | None = None):
        self._policies = tuple(policy for policy in policies or [] if isinstance(policy, dict))

    def register_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        validation = validate_policy_record(policy)
        return {
            "registration_status": "REGISTERED_READ_ONLY" if validation.valid else validation.status,
            "policy": dict(policy) if isinstance(policy, dict) else {},
            "reason_codes": list(validation.reason_codes),
            "read_only": True,
            "auto_approved": False,
            "auto_promoted": False,
            "auto_activated": False,
            "auto_retired": False,
        }

    def get_policy(self, policy_id: str) -> list[dict[str, Any]]:
        return [dict(policy) for policy in self._policies if policy.get("policy_id") == policy_id]

    def get_policy_version(self, policy_id: str, policy_version: str) -> dict[str, Any] | None:
        for policy in self._policies:
            if policy.get("policy_id") == policy_id and policy.get("policy_version") == policy_version:
                return dict(policy)
        return None

    def list_policy_versions(self, policy_id: str) -> list[str]:
        return sorted(str(policy.get("policy_version")) for policy in self._policies if policy.get("policy_id") == policy_id)

    def get_latest_policy(self, policy_id: str) -> dict[str, Any] | None:
        versions = self.get_policy(policy_id)
        if not versions:
            return None
        return sorted(versions, key=lambda policy: str(policy.get("created_at", "")))[-1]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        active = 0
        deprecated = 0
        for policy in self._policies:
            validation = validate_policy_record(policy)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
            if policy.get("status") == "ACTIVE":
                active += 1
            if policy.get("status") == "DEPRECATED":
                deprecated += 1
        latest = sorted(self._policies, key=lambda policy: str(policy.get("created_at", "")))[-1] if self._policies else {}
        return {
            "policy_registry_status": "BLOCKED" if reasons else ("VERIFIED" if self._policies else "BLOCKED"),
            "policy_count": len(self._policies),
            "active_policy_count": active,
            "deprecated_policy_count": deprecated,
            "latest_policy_version": str(latest.get("policy_version", "")),
            "promotion_status": "BLOCKED",
            "reason_codes": sorted(set(reasons)) or ([] if self._policies else ["POLICY_REGISTRY_EMPTY"]),
            "read_only": True,
            "auto_approved": False,
            "auto_promoted": False,
            "auto_activated": False,
            "auto_retired": False,
        }


def empty_policy_registry_dashboard_state() -> dict[str, Any]:
    return PolicyRegistry().summary()
