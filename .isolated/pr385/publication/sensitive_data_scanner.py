"""Local fail-closed sensitive data scanner for publication artifacts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from publication.models import (
    BlockReason,
    SensitiveDataCategory,
    SensitiveScanResult,
    hash_payload,
)


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?:\+?\d[\s().-]*){8,}\d")
API_KEY_RE = re.compile(r"\b(?:api[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*[A-Za-z0-9_\-]{12,}\b", re.IGNORECASE)
TOKEN_RE = re.compile(r"\b(?:token|bearer)\s*[:= ]\s*[A-Za-z0-9_\-.]{16,}\b", re.IGNORECASE)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PASSWORD_SECRET_RE = re.compile(r"\b(?:password|passwd|secret)\s*[:=]\s*\S+", re.IGNORECASE)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
CUSTOMER_CONFIDENTIAL_RE = re.compile(r"\b(?:customer confidential|customer-confidential|confidential customer|raw customer data)\b", re.IGNORECASE)


PATTERNS: tuple[tuple[SensitiveDataCategory, re.Pattern[str]], ...] = (
    (SensitiveDataCategory.EMAIL, EMAIL_RE),
    (SensitiveDataCategory.PHONE, PHONE_RE),
    (SensitiveDataCategory.API_KEY, API_KEY_RE),
    (SensitiveDataCategory.TOKEN, TOKEN_RE),
    (SensitiveDataCategory.PRIVATE_KEY, PRIVATE_KEY_RE),
    (SensitiveDataCategory.PASSWORD_OR_SECRET, PASSWORD_SECRET_RE),
    (SensitiveDataCategory.IBAN, IBAN_RE),
    (SensitiveDataCategory.CREDIT_CARD, CREDIT_CARD_RE),
    (SensitiveDataCategory.CUSTOMER_CONFIDENTIAL, CUSTOMER_CONFIDENTIAL_RE),
)


def scan_publication_content(
    *,
    artifact_id: str,
    content: str,
    policy_version: str = "1.0",
    metadata: Mapping[str, Any] | None = None,
) -> SensitiveScanResult:
    if not artifact_id or not isinstance(content, str):
        evidence = _evidence(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            content_hash="sha256:invalid_scan_input",
            detected=(),
            policy_version=policy_version,
            metadata=metadata,
            invalid_input=True,
        )
        return SensitiveScanResult.blocked(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            reason=BlockReason.INVALID_SCAN_INPUT,
            categories=(),
            evidence=evidence,
            policy_version=policy_version,
        )

    detected: list[SensitiveDataCategory] = []
    counts: dict[str, int] = {}
    for category, pattern in PATTERNS:
        matches = pattern.findall(content)
        if matches:
            detected.append(category)
            counts[category.value] = len(matches)

    content_hash = hash_payload({"artifact_id": artifact_id, "content": content})
    evidence = _evidence(
        artifact_id=artifact_id,
        content_hash=content_hash,
        detected=tuple(detected),
        policy_version=policy_version,
        metadata=metadata,
        counts=counts,
    )
    if detected:
        return SensitiveScanResult.blocked(
            artifact_id=artifact_id,
            reason=BlockReason.SENSITIVE_DATA_PRESENT,
            categories=tuple(detected),
            evidence=evidence,
            policy_version=policy_version,
        )
    return SensitiveScanResult.passed_clean(
        artifact_id=artifact_id,
        evidence=evidence,
        policy_version=policy_version,
    )


def _evidence(
    *,
    artifact_id: str,
    content_hash: str,
    detected: tuple[SensitiveDataCategory, ...],
    policy_version: str,
    metadata: Mapping[str, Any] | None,
    counts: dict[str, int] | None = None,
    invalid_input: bool = False,
) -> dict[str, Any]:
    metadata_keys = tuple(sorted(str(key) for key in (metadata or {}).keys()))
    return {
        "artifact_id": artifact_id,
        "content_hash": content_hash,
        "detected_categories": tuple(category.value for category in detected),
        "detected_counts": dict(sorted((counts or {}).items())),
        "redaction_required": bool(detected) or invalid_input,
        "metadata_keys": metadata_keys,
        "policy_version": policy_version,
        "raw_values_stored": False,
    }
