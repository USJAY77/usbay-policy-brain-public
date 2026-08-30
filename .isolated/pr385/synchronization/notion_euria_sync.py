from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


NOTION_EURIA_SYNC_VERSION = "pb231-235-notion-euria-read-only-sync-v1"
DEFAULT_POLICY_HASH = "88d1aaa62bbe011c9f51d7f159a7526a2fe283b94314e8c9b9cce73b199f04d1"
ALLOWED_SYNC_DIRECTION = "Notion -> Euria"
BLOCKED_SYNC_DIRECTION = "Euria -> Notion"


class SyncState(str, Enum):
    READ_ONLY = "READ_ONLY"
    BLOCKED = "BLOCKED"


class ConflictDecision(str, Enum):
    USE_NOTION = "USE_NOTION"
    BLOCK_EURIA_WRITE = "BLOCK_EURIA_WRITE"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"


@dataclass(frozen=True)
class NotionEuriaMapping:
    notion_section: str
    euria_project: str
    usbay_control_plane_category: str
    allowed_sync_direction: str = ALLOWED_SYNC_DIRECTION
    blocked_sync_direction: str = BLOCKED_SYNC_DIRECTION
    evidence_path: str = "governance/evidence/pb231_235"
    policy_hash: str = DEFAULT_POLICY_HASH
    sync_state: SyncState = SyncState.READ_ONLY

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["sync_state"] = self.sync_state.value
        payload["contract_version"] = NOTION_EURIA_SYNC_VERSION
        payload["notion_source_of_truth"] = True
        payload["euria_governed_consumer_only"] = True
        payload["live_connector_calls_allowed"] = False
        payload["browser_automation_allowed"] = False
        payload["desktop_automation_allowed"] = False
        payload["external_api_calls_allowed"] = False
        return payload


def mapping_registry_json() -> dict[str, Any]:
    mappings = [
        NotionEuriaMapping(
            notion_section="Governance Pilot Controls",
            euria_project="Read-Only Governance Consumer",
            usbay_control_plane_category="controlled_live_pilot",
        ),
        NotionEuriaMapping(
            notion_section="Policy Evidence",
            euria_project="Evidence Review",
            usbay_control_plane_category="audit_evidence",
        ),
    ]
    return {
        "contract_version": NOTION_EURIA_SYNC_VERSION,
        "source_of_truth": "Notion",
        "consumer": "Euria",
        "default_sync_state": SyncState.READ_ONLY.value,
        "write_back_allowed": False,
        "live_connector_calls_allowed": False,
        "browser_automation_allowed": False,
        "desktop_automation_allowed": False,
        "external_api_calls_allowed": False,
        "mappings": [mapping.to_dict() for mapping in mappings],
    }


def validate_mapping(mapping: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    required = (
        "notion_section",
        "euria_project",
        "usbay_control_plane_category",
        "allowed_sync_direction",
        "blocked_sync_direction",
        "evidence_path",
        "policy_hash",
        "sync_state",
    )
    for field in required:
        if field not in mapping or not isinstance(mapping.get(field), str) or not mapping.get(field):
            gaps.append(f"MISSING_{field.upper()}")
    if mapping.get("allowed_sync_direction") != ALLOWED_SYNC_DIRECTION:
        gaps.append("INVALID_ALLOWED_SYNC_DIRECTION")
    if mapping.get("blocked_sync_direction") != BLOCKED_SYNC_DIRECTION:
        gaps.append("EURIA_TO_NOTION_WRITE_NOT_BLOCKED")
    if mapping.get("sync_state") not in {SyncState.READ_ONLY.value, SyncState.BLOCKED.value}:
        gaps.append("INVALID_SYNC_STATE")
    if mapping.get("policy_hash") != DEFAULT_POLICY_HASH:
        gaps.append("UNKNOWN_POLICY_HASH")
    return sorted(set(gaps))


def validate_sync_registry(registry: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(registry, dict):
        return {"decision": "FAIL_CLOSED", "status": "BLOCKED", "gaps": ["MALFORMED_SYNC_REGISTRY"]}
    gaps: list[str] = []
    if registry.get("source_of_truth") != "Notion":
        gaps.append("NOTION_NOT_SOURCE_OF_TRUTH")
    if registry.get("consumer") != "Euria":
        gaps.append("EURIA_NOT_GOVERNED_CONSUMER")
    for flag in (
        "write_back_allowed",
        "live_connector_calls_allowed",
        "browser_automation_allowed",
        "desktop_automation_allowed",
        "external_api_calls_allowed",
    ):
        if registry.get(flag) is not False:
            gaps.append(f"{flag.upper()}_MUST_BE_FALSE")
    mappings = registry.get("mappings")
    if not isinstance(mappings, list) or not mappings:
        gaps.append("MISSING_MAPPINGS")
    else:
        for mapping in mappings:
            gaps.extend(validate_mapping(mapping if isinstance(mapping, dict) else {}))
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "status": "READ_ONLY" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "contract_version": NOTION_EURIA_SYNC_VERSION,
        "local_evidence_only": True,
    }


def conflict_resolution_rules_json() -> dict[str, Any]:
    return {
        "contract_version": NOTION_EURIA_SYNC_VERSION,
        "source_of_truth": "Notion",
        "default_decision": ConflictDecision.USE_NOTION.value,
        "rules": [
            {
                "condition": "euria_attempts_write_to_notion",
                "decision": ConflictDecision.BLOCK_EURIA_WRITE.value,
                "outcome": "BLOCKED",
            },
            {
                "condition": "notion_and_euria_values_differ",
                "decision": ConflictDecision.USE_NOTION.value,
                "outcome": "READ_ONLY",
            },
            {
                "condition": "policy_hash_missing_or_unknown",
                "decision": ConflictDecision.REQUIRE_HUMAN_REVIEW.value,
                "outcome": "BLOCKED",
            },
        ],
        "external_resolution_calls_allowed": False,
    }


def resolve_conflict(*, direction: str, policy_hash: str, values_match: bool = True) -> dict[str, Any]:
    if direction == BLOCKED_SYNC_DIRECTION:
        return {"decision": "BLOCKED", "rule": "BLOCK_EURIA_WRITE", "gaps": ["EURIA_TO_NOTION_WRITE_BLOCKED"]}
    if policy_hash != DEFAULT_POLICY_HASH:
        return {"decision": "BLOCKED", "rule": "REQUIRE_HUMAN_REVIEW", "gaps": ["UNKNOWN_POLICY_HASH"]}
    if not values_match:
        return {"decision": "READ_ONLY", "rule": "USE_NOTION", "source_of_truth": "Notion", "gaps": []}
    return {"decision": "READ_ONLY", "rule": "USE_NOTION", "source_of_truth": "Notion", "gaps": []}


def evidence_sync_contract_json() -> dict[str, Any]:
    return {
        "contract_version": NOTION_EURIA_SYNC_VERSION,
        "evidence_path": "governance/evidence/pb231_235",
        "local_evidence_only": True,
        "notion_writes_allowed": False,
        "euria_writes_allowed": False,
        "github_writes_allowed": False,
        "codex_actions_allowed": False,
        "browser_automation_allowed": False,
        "desktop_automation_allowed": False,
        "external_api_calls_allowed": False,
        "required_artifacts": [
            "notion_euria_mapping_registry.json",
            "sync_validation_report.json",
            "conflict_resolution_rules.json",
            "evidence_sync_contract.json",
            "read_only_pilot_sync_report.md",
        ],
    }


def read_only_sync_report_json() -> dict[str, Any]:
    registry = mapping_registry_json()
    validation = validate_sync_registry(registry)
    return {
        "decision": validation["decision"],
        "status": validation["status"],
        "source_of_truth": "Notion",
        "consumer": "Euria",
        "systems": ["Notion", "Euria", "USBAY Control Plane", "GitHub", "Codex"],
        "live_connector_calls_performed": False,
        "browser_automation_performed": False,
        "desktop_automation_performed": False,
        "external_api_calls_performed": False,
        "local_evidence_only": True,
        "mapping_count": len(registry["mappings"]),
        "gaps": validation["gaps"],
        "contract_version": NOTION_EURIA_SYNC_VERSION,
    }
