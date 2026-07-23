from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

POLICY_PACK_SCHEMA = "usbay.governance_policy_pack.v1"
POLICY_ERROR_REGISTRY_PATH = Path("governance/policy_errors.json")
POLICY_ERROR_SCHEMA = "usbay.governance_policy_error_registry.v1"
POLICY_ERROR_CODES = (
    "POLICY_SCHEMA_INVALID",
    "POLICY_DUPLICATE_ID",
    "POLICY_CONFLICTING_RULES",
    "POLICY_MISSING_HUMAN_APPROVAL",
    "POLICY_FAIL_CLOSED_MISSING",
    "POLICY_EXPIRED",
    "POLICY_SCOPE_INVALID",
)
SECRET_MARKERS = (
    "BEGIN " + "PRIVATE " + "KEY",
    "raw_secret",
    "approval_contents",
    "private_key",
    "USBAY_SECRET",
)


class PolicyPackValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidationSnapshot:
    namespace: str
    payload_hash: str


_VALIDATION_SNAPSHOT_CACHE: dict[tuple[str, str], ValidationSnapshot] = {}
_VALIDATION_SNAPSHOT_CACHE_LOCK = threading.RLock()
_VALIDATION_SNAPSHOT_CACHE_STATS = {"hits": 0, "misses": 0, "evictions": 0, "corruptions": 0}
_VALIDATION_SNAPSHOT_CACHE_MAX_ENTRIES = 8192


@dataclass(frozen=True)
class PolicyValidationIssue:
    code: str
    policy_id: str | None
    detail: str

    def to_dict(self) -> dict[str, str | None]:
        return {"code": self.code, "policy_id": self.policy_id, "detail": self.detail}


@dataclass(frozen=True)
class PolicyPackValidationResult:
    valid: bool
    errors: tuple[PolicyValidationIssue, ...]
    policy_count: int
    high_risk_policy_count: int
    tenant_scope_count: int
    environment_scope_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": [error.to_dict() for error in self.errors],
            "policy_count": self.policy_count,
            "high_risk_policy_count": self.high_risk_policy_count,
            "tenant_scope_count": self.tenant_scope_count,
            "environment_scope_count": self.environment_scope_count,
        }


def load_policy_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / POLICY_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyPackValidationError("policy_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != POLICY_ERROR_SCHEMA:
        raise PolicyPackValidationError("policy_error_registry_invalid")
    errors = payload.get("errors")
    if not isinstance(errors, list):
        raise PolicyPackValidationError("policy_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise PolicyPackValidationError("policy_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(POLICY_ERROR_CODES) - set(registry))
    if missing:
        raise PolicyPackValidationError("policy_error_registry_incomplete:" + ",".join(missing))
    return registry


def load_policy_pack(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyPackValidationError("policy_pack_missing_or_invalid") from exc
    if not isinstance(payload, dict):
        raise PolicyPackValidationError("policy_pack_invalid")
    return payload


def validate_policy_pack(
    policy_pack: dict[str, Any],
    *,
    now: datetime | None = None,
    allowed_tenants: tuple[str, ...] = ("t1", "t2", "edgeguard-demo"),
    allowed_environments: tuple[str, ...] = ("test", "staging", "production"),
) -> PolicyPackValidationResult:
    current_time = now or datetime.now(timezone.utc)
    errors: list[PolicyValidationIssue] = []
    if not isinstance(policy_pack, dict) or policy_pack.get("schema") != POLICY_PACK_SCHEMA:
        errors.append(PolicyValidationIssue("POLICY_SCHEMA_INVALID", None, "unsupported_policy_pack_schema"))
    if policy_pack.get("fail_closed") is not True:
        errors.append(PolicyValidationIssue("POLICY_FAIL_CLOSED_MISSING", None, "policy_pack_fail_closed_missing"))
    _validate_scope(policy_pack.get("scope"), None, errors, allowed_tenants, allowed_environments)
    _validate_window(policy_pack.get("valid_from"), policy_pack.get("valid_until"), None, errors, current_time)
    policies = policy_pack.get("policies")
    if not isinstance(policies, list) or not policies:
        errors.append(PolicyValidationIssue("POLICY_SCHEMA_INVALID", None, "policies_missing"))
        policies = []
    seen_ids: set[str] = set()
    high_risk_count = 0
    tenant_scope_values: set[str] = set()
    environment_scope_values: set[str] = set()
    for index, policy in enumerate(policies):
        if not isinstance(policy, dict):
            errors.append(PolicyValidationIssue("POLICY_SCHEMA_INVALID", None, f"policy_invalid:{index}"))
            continue
        policy_id = str(policy.get("policy_id", "") or "")
        if not policy_id:
            errors.append(PolicyValidationIssue("POLICY_SCHEMA_INVALID", None, f"policy_id_missing:{index}"))
        elif policy_id in seen_ids:
            errors.append(PolicyValidationIssue("POLICY_DUPLICATE_ID", policy_id, "duplicate_policy_id"))
        else:
            seen_ids.add(policy_id)
        risk = str(policy.get("risk_level", "")).lower()
        high_risk = risk in {"high", "critical"} or policy.get("high_risk") is True
        if high_risk:
            high_risk_count += 1
        if high_risk and policy.get("requires_human_approval") is not True:
            errors.append(PolicyValidationIssue("POLICY_MISSING_HUMAN_APPROVAL", policy_id or None, "high_risk_policy_requires_human_approval"))
        if policy.get("fail_closed") is not True:
            errors.append(PolicyValidationIssue("POLICY_FAIL_CLOSED_MISSING", policy_id or None, "policy_fail_closed_missing"))
        _validate_scope(policy.get("scope"), policy_id or None, errors, allowed_tenants, allowed_environments)
        scope = policy.get("scope") if isinstance(policy.get("scope"), dict) else {}
        for tenant in scope.get("tenant_ids", []) if isinstance(scope.get("tenant_ids"), list) else []:
            tenant_scope_values.add(str(tenant))
        for environment in scope.get("environments", []) if isinstance(scope.get("environments"), list) else []:
            environment_scope_values.add(str(environment))
        _validate_window(policy.get("valid_from"), policy.get("valid_until"), policy_id or None, errors, current_time)
        if _has_conflicting_rules(policy):
            errors.append(PolicyValidationIssue("POLICY_CONFLICTING_RULES", policy_id or None, "allow_and_deny_rules_overlap"))
    return PolicyPackValidationResult(
        valid=not errors,
        errors=tuple(errors),
        policy_count=len(policies),
        high_risk_policy_count=high_risk_count,
        tenant_scope_count=len(tenant_scope_values),
        environment_scope_count=len(environment_scope_values),
    )


def validate_policy_pack_file(path: Path, **kwargs: Any) -> PolicyPackValidationResult:
    return validate_policy_pack(load_policy_pack(path), **kwargs)


def explain_policy_error(root: Path, code: str) -> dict[str, str]:
    registry = load_policy_error_registry(root)
    if code not in registry:
        raise PolicyPackValidationError("policy_error_unknown:" + code)
    return {"code": code, **registry[code]}


def policy_pack_summary(result: PolicyPackValidationResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "policy_count": result.policy_count,
        "high_risk_policy_count": result.high_risk_policy_count,
        "tenant_scope_count": result.tenant_scope_count,
        "environment_scope_count": result.environment_scope_count,
        "error_codes": sorted({error.code for error in result.errors}),
    }


def clear_validation_snapshot_cache() -> None:
    with _VALIDATION_SNAPSHOT_CACHE_LOCK:
        _VALIDATION_SNAPSHOT_CACHE.clear()
        _VALIDATION_SNAPSHOT_CACHE_STATS["hits"] = 0
        _VALIDATION_SNAPSHOT_CACHE_STATS["misses"] = 0
        _VALIDATION_SNAPSHOT_CACHE_STATS["evictions"] = 0
        _VALIDATION_SNAPSHOT_CACHE_STATS["corruptions"] = 0


def validation_snapshot_cache_stats() -> dict[str, int]:
    with _VALIDATION_SNAPSHOT_CACHE_LOCK:
        return {
            "entries": len(_VALIDATION_SNAPSHOT_CACHE),
            "hits": _VALIDATION_SNAPSHOT_CACHE_STATS["hits"],
            "misses": _VALIDATION_SNAPSHOT_CACHE_STATS["misses"],
            "evictions": _VALIDATION_SNAPSHOT_CACHE_STATS["evictions"],
            "corruptions": _VALIDATION_SNAPSHOT_CACHE_STATS["corruptions"],
        }


def _validation_snapshot_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def assert_cached_validation_safe(namespace: str, payload: Any, validator: Callable[[Any], None]) -> None:
    try:
        payload_hash = _validation_snapshot_hash(payload)
    except Exception:
        validator(payload)
        return
    cache_key = (namespace, payload_hash)
    with _VALIDATION_SNAPSHOT_CACHE_LOCK:
        snapshot = _VALIDATION_SNAPSHOT_CACHE.get(cache_key)
        if snapshot is not None:
            if snapshot == ValidationSnapshot(namespace=namespace, payload_hash=payload_hash):
                _VALIDATION_SNAPSHOT_CACHE_STATS["hits"] += 1
                return
            _VALIDATION_SNAPSHOT_CACHE.pop(cache_key, None)
            _VALIDATION_SNAPSHOT_CACHE_STATS["corruptions"] += 1
        _VALIDATION_SNAPSHOT_CACHE_STATS["misses"] += 1
    validator(payload)
    with _VALIDATION_SNAPSHOT_CACHE_LOCK:
        if len(_VALIDATION_SNAPSHOT_CACHE) >= _VALIDATION_SNAPSHOT_CACHE_MAX_ENTRIES:
            _VALIDATION_SNAPSHOT_CACHE.clear()
            _VALIDATION_SNAPSHOT_CACHE_STATS["evictions"] += 1
        _VALIDATION_SNAPSHOT_CACHE[cache_key] = ValidationSnapshot(namespace=namespace, payload_hash=payload_hash)


def assert_policy_diagnostics_safe(payload: Any) -> None:
    encoded = json.dumps(payload, sort_keys=True, default=str)
    for marker in SECRET_MARKERS:
        if marker in encoded:
            raise PolicyPackValidationError("POLICY_DIAGNOSTICS_UNSAFE")


def redacted_policy_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {str(key): redacted_policy_payload(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redacted_policy_payload(value) for value in payload]
    if isinstance(payload, tuple):
        return [redacted_policy_payload(value) for value in payload]
    if isinstance(payload, str):
        redacted = payload
        for marker in SECRET_MARKERS:
            redacted = redacted.replace(marker, "[REDACTED]")
        return redacted
    return payload


def _validate_scope(
    scope: Any,
    policy_id: str | None,
    errors: list[PolicyValidationIssue],
    allowed_tenants: tuple[str, ...],
    allowed_environments: tuple[str, ...],
) -> None:
    if not isinstance(scope, dict):
        errors.append(PolicyValidationIssue("POLICY_SCOPE_INVALID", policy_id, "scope_missing"))
        return
    tenant_ids = scope.get("tenant_ids")
    environments = scope.get("environments")
    if not isinstance(tenant_ids, list) or not tenant_ids:
        errors.append(PolicyValidationIssue("POLICY_SCOPE_INVALID", policy_id, "tenant_scope_missing"))
    elif any(not isinstance(tenant, str) or tenant not in allowed_tenants for tenant in tenant_ids):
        errors.append(PolicyValidationIssue("POLICY_SCOPE_INVALID", policy_id, "tenant_scope_invalid"))
    if not isinstance(environments, list) or not environments:
        errors.append(PolicyValidationIssue("POLICY_SCOPE_INVALID", policy_id, "environment_scope_missing"))
    elif any(not isinstance(environment, str) or environment not in allowed_environments for environment in environments):
        errors.append(PolicyValidationIssue("POLICY_SCOPE_INVALID", policy_id, "environment_scope_invalid"))


def _validate_window(
    valid_from: Any,
    valid_until: Any,
    policy_id: str | None,
    errors: list[PolicyValidationIssue],
    now: datetime,
) -> None:
    try:
        start = _parse_time(valid_from)
        end = _parse_time(valid_until)
    except PolicyPackValidationError:
        errors.append(PolicyValidationIssue("POLICY_EXPIRED", policy_id, "validity_window_invalid"))
        return
    if start > now or end <= now or start >= end:
        errors.append(PolicyValidationIssue("POLICY_EXPIRED", policy_id, "validity_window_expired"))


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise PolicyPackValidationError("policy_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise PolicyPackValidationError("policy_time_invalid") from exc
    if parsed.tzinfo is None:
        raise PolicyPackValidationError("policy_time_invalid")
    return parsed.astimezone(timezone.utc)


def _has_conflicting_rules(policy: dict[str, Any]) -> bool:
    allow_rules = _normalized_rule_keys(policy.get("allow_rules"))
    deny_rules = _normalized_rule_keys(policy.get("deny_rules"))
    return bool(allow_rules.intersection(deny_rules))


def _normalized_rule_keys(rules: Any) -> set[str]:
    if not isinstance(rules, list):
        return set()
    normalized: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        action = str(rule.get("action", "")).strip()
        resource = str(rule.get("resource", "*")).strip() or "*"
        condition = str(rule.get("condition", "*")).strip() or "*"
        if action:
            normalized.add(f"{action}:{resource}:{condition}")
    return normalized
