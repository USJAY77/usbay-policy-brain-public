"""Local publication registry and policy loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from publication.errors import PublicationPolicyError, PublicationRegistryError
from publication.models import BlockReason, PublicationDecisionResult, RegistryRecord


def load_json_file(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    try:
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise PublicationPolicyError(f"Unable to read JSON file: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise PublicationPolicyError(f"Invalid JSON file: {file_path}") from exc
    if not isinstance(data, dict):
        raise PublicationPolicyError(f"JSON file must contain an object: {file_path}")
    return data


def load_registry_record(path: str | Path) -> RegistryRecord:
    data = load_json_file(path)
    try:
        return RegistryRecord.from_dict(data)
    except TypeError as exc:
        raise PublicationRegistryError(f"Invalid registry record: {path}") from exc


class InMemoryRegistryStore:
    """Simple local registry store for deterministic tests and local validation."""

    def __init__(self, records: list[RegistryRecord] | None = None) -> None:
        self._records = {record.artifact_id: record for record in records or []}

    def get(self, artifact_id: str) -> RegistryRecord | PublicationDecisionResult:
        if not artifact_id:
            return PublicationDecisionResult.blocked(
                artifact_id="UNKNOWN_ARTIFACT",
                reason=BlockReason.ARTIFACT_ID_UNKNOWN,
                details=("artifact_id is required",),
            )
        record = self._records.get(artifact_id)
        if record is None:
            return PublicationDecisionResult.blocked(
                artifact_id=artifact_id,
                reason=BlockReason.REGISTRY_RECORD_MISSING,
                details=("registry record does not exist",),
            )
        return record

    def put(self, record: RegistryRecord) -> None:
        self._records[record.artifact_id] = record
