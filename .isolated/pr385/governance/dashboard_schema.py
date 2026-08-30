from __future__ import annotations

from typing import Any

from governance.capability_manifest import CAPABILITY_MANIFEST


DASHBOARD_SCHEMA_VERSION = "usbay.governance.dashboard_schema.v1"


def dashboard_schema() -> dict[str, Any]:
    sections = []
    for capability in CAPABILITY_MANIFEST:
        sections.append(
            {
                "capability_id": capability["capability_id"],
                "display_name": capability["display_name"],
                "required_states": list(capability["dashboard_states"]),
                "read_only": True,
            }
        )
    return {
        "schema": DASHBOARD_SCHEMA_VERSION,
        "sections": sections,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def validate_dashboard_schema() -> dict[str, Any]:
    schema = dashboard_schema()
    section_ids = [section["capability_id"] for section in schema["sections"]]
    duplicate_sections = sorted({section_id for section_id in section_ids if section_ids.count(section_id) > 1})
    missing_states = sorted(section["capability_id"] for section in schema["sections"] if not section["required_states"])
    valid = not duplicate_sections and not missing_states
    return {
        "schema": DASHBOARD_SCHEMA_VERSION,
        "valid": valid,
        "status": "VALID" if valid else "BLOCKED",
        "section_count": len(schema["sections"]),
        "duplicate_sections": duplicate_sections,
        "missing_states": missing_states,
        "read_only": True,
    }
