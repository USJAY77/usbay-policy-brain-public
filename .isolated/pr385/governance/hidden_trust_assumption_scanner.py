"""Defensive governance diagnostics for hidden trust assumptions.

This capability is defensive, local-only, read-only, and governance-focused.
No exploit generation, attack automation, credential harvesting, or offensive execution is allowed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from governance.policy_pack import redacted_policy_payload

HIDDEN_TRUST_SCANNER_SCHEMA = "usbay.governance_hidden_trust_assumption_scanner.v1"
HIDDEN_TRUST_SCANNER_ERROR_REGISTRY_PATH = Path("governance/hidden_trust_assumption_errors.json")
HIDDEN_TRUST_SCANNER_ERROR_SCHEMA = "usbay.governance_hidden_trust_assumption_error_registry.v1"
HIDDEN_TRUST_SCANNER_ERROR_CODES = (
    "HIDDEN_TRUST_INPUT_MISSING",
    "HIDDEN_TRUST_INPUT_MALFORMED",
    "HIDDEN_TRUST_INPUT_STALE",
    "HIDDEN_TRUST_INPUT_UNSIGNED",
    "HIDDEN_TRUST_INPUT_AMBIGUOUS",
    "HIDDEN_TRUST_IMPLICIT_ASSUMPTION",
    "HIDDEN_TRUST_STALE_AUTHORITY_REUSE",
    "HIDDEN_TRUST_CACHED_APPROVAL_WITHOUT_FRESHNESS",
    "HIDDEN_TRUST_FALLBACK_ALLOW",
    "HIDDEN_TRUST_REPLAYABLE_STATE",
    "HIDDEN_TRUST_MUTABLE_TRACKED_REGISTRY",
    "HIDDEN_TRUST_SUBPROCESS_LEAKAGE",
    "HIDDEN_TRUST_RUNTIME_POLICY_BYPASS",
    "HIDDEN_TRUST_UNSIGNED_METADATA",
    "HIDDEN_TRUST_MISSING_HUMAN_APPROVAL",
    "HIDDEN_TRUST_DIAGNOSTICS_UNSAFE",
)
MODULE_VERSIONS = {"hidden_trust_assumption_scanner": HIDDEN_TRUST_SCANNER_SCHEMA}
DEFAULT_MAX_METADATA_AGE_SECONDS = 86_400
SCAN_SUFFIXES = frozenset({".py", ".json", ".yml", ".yaml", ".md", ".toml"})
EXCLUDED_DIRS = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"})
SECRET_MARKERS = (
    "BEGIN " + "PRIVATE KEY",
    "BEGIN " + "RSA PRIVATE KEY",
    "BEGIN " + "OPENSSH PRIVATE KEY",
    "USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM",
    "approval_contents",
    "raw_payload",
    "private_key",
)


class HiddenTrustAssumptionScannerError(RuntimeError):
    pass


@dataclass(frozen=True)
class HiddenTrustFinding:
    code: str
    risk: str
    mechanism: str
    gap: str
    audit_evidence: str
    human_impact: str
    affected_files: tuple[str, ...]
    finding_severity: str
    merge_gate: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "risk": self.risk,
            "mechanism": self.mechanism,
            "gap": self.gap,
            "audit_evidence": self.audit_evidence,
            "human_impact": self.human_impact,
            "affected_files": list(self.affected_files),
            "finding_severity": self.finding_severity,
            "merge_gate": self.merge_gate,
            "line": self.line,
        }


@dataclass(frozen=True)
class HiddenTrustScanResult:
    valid: bool
    errors: tuple[str, ...]
    findings: tuple[HiddenTrustFinding, ...]
    scanned_file_count: int
    scanner_mode: str
    metadata_hash: str
    merge_gate: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "findings": [finding.to_dict() for finding in self.findings],
            "scanned_file_count": self.scanned_file_count,
            "scanner_mode": self.scanner_mode,
            "metadata_hash": self.metadata_hash,
            "merge_gate": self.merge_gate,
        }


PATTERNS: tuple[tuple[str, str, str, str, str, str, str], ...] = (
    (
        "HIDDEN_TRUST_IMPLICIT_ASSUMPTION",
        r"\b(assume|implicitly)\s+(trusted|valid|approved|verified)\b|trust\s+by\s+default",
        "implicit runtime trust assumption",
        "source text assumes trust without a proof boundary",
        "operator may believe governance proof exists when it does not",
        "high",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_STALE_AUTHORITY_REUSE",
        r"\b(stale|cached|reuse[d]?)_(runtime_)?authority\b|reuse\s+.*authority",
        "stale authority reuse",
        "authority continuity may be reused without freshness validation",
        "operator may approve decisions bound to stale provenance",
        "critical",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_CACHED_APPROVAL_WITHOUT_FRESHNESS",
        r"cached[_\s-]*approval(?!.*freshness)|approval_cache(?!.*ttl)",
        "cached approval without freshness proof",
        "approval state can persist without age or nonce proof",
        "human approval boundaries may be bypassed by old state",
        "critical",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_FALLBACK_ALLOW",
        r"fallback[_\s-]*allow|allow[_\s-]*on[_\s-]*(error|failure)|default[_\s-]*allow",
        "silent fallback-to-allow",
        "failure path may allow execution instead of denying",
        "fail-closed guarantee can be inverted",
        "critical",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_REPLAYABLE_STATE",
        r"replayable[_\s-]*trust|trust_state_cache|nonce_cache(?!.*ttl)",
        "replayable trust state",
        "trust state lacks deterministic freshness or replay binding",
        "attacker or stale test state may replay trust decisions",
        "high",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_MUTABLE_TRACKED_REGISTRY",
        r"audit/key_registry\.json.*(write_text|open\(.?[wa]\b|register_public_key)|DEFAULT_REGISTRY_PATH\s*=\s*Path\(.audit/key_registry\.json",
        "mutable tracked registry usage",
        "tracked identity registry may be mutated during tests or runtime",
        "trusted node identity lineage can drift silently",
        "critical",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_SUBPROCESS_LEAKAGE",
        r"subprocess\.(run|Popen|call|check_call|check_output).*?(approval|private_key|secret|token)",
        "subprocess trust leakage",
        "sensitive trust material may cross process boundaries",
        "operator secrets or approval state may leak into child processes",
        "high",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_RUNTIME_POLICY_BYPASS",
        r"bypass[_\s-]*(governance|policy|approval)|skip[_\s-]*(governance|policy|approval)",
        "runtime policy bypass path",
        "runtime path names a governance bypass mechanism",
        "execution may evade policy brain authority",
        "critical",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_UNSIGNED_METADATA",
        r"unsigned[_\s-]*(governance_)?metadata|signature\s*[:=]\s*[\"']?[\"']",
        "ambiguous or unsigned governance metadata",
        "metadata can be accepted without signature evidence",
        "auditors may receive unverifiable governance state",
        "high",
        "BLOCK",
    ),
    (
        "HIDDEN_TRUST_MISSING_HUMAN_APPROVAL",
        r"risk_level\s*[:=]\s*[\"']?(high|critical)[\"']?.{0,120}(requires_human_approval\s*[:=]\s*False|human_approval\s*[:=]\s*False)",
        "missing human approval boundary",
        "high-risk action appears to disable human approval",
        "sensitive operations may proceed without human oversight",
        "critical",
        "BLOCK",
    ),
)


def load_hidden_trust_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / HIDDEN_TRUST_SCANNER_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HiddenTrustAssumptionScannerError("hidden_trust_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != HIDDEN_TRUST_SCANNER_ERROR_SCHEMA:
        raise HiddenTrustAssumptionScannerError("hidden_trust_error_registry_invalid")
    entries = payload.get("errors")
    if not isinstance(entries, list):
        raise HiddenTrustAssumptionScannerError("hidden_trust_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise HiddenTrustAssumptionScannerError("hidden_trust_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(HIDDEN_TRUST_SCANNER_ERROR_CODES) - set(registry))
    if missing:
        raise HiddenTrustAssumptionScannerError("hidden_trust_error_registry_incomplete:" + ",".join(missing))
    return registry


def scan_hidden_trust_assumptions(
    root: Path,
    *,
    metadata: dict[str, Any],
    scan_paths: Iterable[Path] | None = None,
    now_utc: str | None = None,
    max_metadata_age_seconds: int = DEFAULT_MAX_METADATA_AGE_SECONDS,
) -> HiddenTrustScanResult:
    root = root.resolve()
    errors = _metadata_errors(metadata, now_utc=now_utc, max_age_seconds=max_metadata_age_seconds)
    if not root.exists() or not root.is_dir():
        errors.append("HIDDEN_TRUST_INPUT_MISSING")
    paths = list(_resolve_scan_paths(root, scan_paths)) if not errors else []
    findings = tuple(_scan_file(root, path) for path in paths)
    flattened = tuple(finding for group in findings for finding in group)
    try:
        payload = {
            "errors": errors,
            "findings": [finding.to_dict() for finding in flattened],
            "metadata_hash": _metadata_hash(metadata),
            "scanner_mode": "LOCAL_READ_ONLY",
        }
        assert_hidden_trust_scanner_safe(payload)
    except HiddenTrustAssumptionScannerError:
        errors.append("HIDDEN_TRUST_DIAGNOSTICS_UNSAFE")
    deduped_errors = tuple(dict.fromkeys(errors))
    merge_gate = "BLOCK" if deduped_errors or flattened else "PASS"
    return HiddenTrustScanResult(
        valid=not deduped_errors and not flattened,
        errors=deduped_errors,
        findings=flattened,
        scanned_file_count=len(paths),
        scanner_mode="LOCAL_READ_ONLY",
        metadata_hash=_metadata_hash(metadata),
        merge_gate=merge_gate,
    )


def scan_hidden_trust_assumptions_file(
    root: Path,
    *,
    metadata_path: Path,
    scan_paths: Iterable[Path] | None = None,
    now_utc: str | None = None,
    max_metadata_age_seconds: int = DEFAULT_MAX_METADATA_AGE_SECONDS,
) -> HiddenTrustScanResult:
    return scan_hidden_trust_assumptions(
        root,
        metadata=_load_json_object(metadata_path, "HIDDEN_TRUST_INPUT_MISSING"),
        scan_paths=scan_paths,
        now_utc=now_utc,
        max_metadata_age_seconds=max_metadata_age_seconds,
    )


def explain_hidden_trust_assumption(root: Path, code: str) -> dict[str, str]:
    registry = load_hidden_trust_error_registry(root)
    if code not in registry:
        raise HiddenTrustAssumptionScannerError("hidden_trust_error_unknown:" + code)
    return {"code": code, **registry[code]}


def hidden_trust_scan_summary(result: HiddenTrustScanResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "errors": list(result.errors),
        "finding_count": len(result.findings),
        "scanned_file_count": result.scanned_file_count,
        "scanner_mode": result.scanner_mode,
        "metadata_hash": result.metadata_hash,
        "merge_gate": result.merge_gate,
    }


def redacted_hidden_trust_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_hidden_trust_scanner_safe(payload: Any) -> None:
    redacted = redacted_policy_payload(payload)
    if redacted != payload or _contains_secret_marker(payload):
        raise HiddenTrustAssumptionScannerError("HIDDEN_TRUST_DIAGNOSTICS_UNSAFE")


def _metadata_errors(metadata: dict[str, Any], *, now_utc: str | None, max_age_seconds: int) -> list[str]:
    errors: list[str] = []
    if not isinstance(metadata, dict):
        return ["HIDDEN_TRUST_INPUT_MISSING"]
    if metadata.get("schema") != HIDDEN_TRUST_SCANNER_SCHEMA:
        errors.append("HIDDEN_TRUST_INPUT_MALFORMED")
    if metadata.get("signed") is not True or not _sha256_valid(str(metadata.get("signature_hash", ""))):
        errors.append("HIDDEN_TRUST_INPUT_UNSIGNED")
    if not _sha256_valid(str(metadata.get("policy_hash", ""))) or not str(metadata.get("scan_scope", "")).strip():
        errors.append("HIDDEN_TRUST_INPUT_AMBIGUOUS")
    generated_at = str(metadata.get("generated_at_utc", ""))
    if not _timestamp_fresh(generated_at, now_utc=now_utc, max_age_seconds=max_age_seconds):
        errors.append("HIDDEN_TRUST_INPUT_STALE")
    if _contains_secret_marker(metadata):
        errors.append("HIDDEN_TRUST_DIAGNOSTICS_UNSAFE")
    return errors


def _resolve_scan_paths(root: Path, scan_paths: Iterable[Path] | None) -> Iterable[Path]:
    if scan_paths:
        for candidate in scan_paths:
            path = candidate if candidate.is_absolute() else root / candidate
            if path.is_file():
                yield path.resolve()
            elif path.is_dir():
                yield from _walk_scan_files(path.resolve())
            else:
                raise HiddenTrustAssumptionScannerError("HIDDEN_TRUST_INPUT_MISSING")
        return
    yield from _walk_scan_files(root)


def _walk_scan_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix in SCAN_SUFFIXES:
            yield path


def _scan_file(root: Path, path: Path) -> tuple[HiddenTrustFinding, ...]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        raise HiddenTrustAssumptionScannerError("HIDDEN_TRUST_INPUT_MALFORMED") from exc
    relative = _relative_path(root, path)
    findings: list[HiddenTrustFinding] = []
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        for code, pattern, mechanism, gap, impact, severity, gate in PATTERNS:
            if re.search(pattern, line, flags=re.IGNORECASE):
                findings.append(
                    HiddenTrustFinding(
                        code=code,
                        risk=severity,
                        mechanism=mechanism,
                        gap=gap,
                        audit_evidence=_evidence_hash(relative, line_number, code),
                        human_impact=impact,
                        affected_files=(relative,),
                        finding_severity=severity,
                        merge_gate=gate,
                        line=line_number,
                    )
                )
    return tuple(findings)


def _relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return "external:" + _sha256_hex(str(path.resolve()).encode("utf-8"))


def _evidence_hash(relative_path: str, line_number: int, code: str) -> str:
    return _sha256_hex(_canonical_json({"code": code, "line": line_number, "path": relative_path}).encode("utf-8"))


def _metadata_hash(metadata: Any) -> str:
    return _sha256_hex(_canonical_json(metadata if isinstance(metadata, dict) else {}).encode("utf-8"))


def _contains_secret_marker(payload: Any) -> bool:
    text = _canonical_json(payload)
    return any(marker in text for marker in SECRET_MARKERS)


def _load_json_object(path: Path, failure_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HiddenTrustAssumptionScannerError(failure_code) from exc
    if not isinstance(payload, dict):
        raise HiddenTrustAssumptionScannerError(failure_code)
    return payload


def _timestamp_fresh(value: str, *, now_utc: str | None, max_age_seconds: int) -> bool:
    generated = _parse_utc(value)
    now = _parse_utc(now_utc) if now_utc else datetime.now(timezone.utc)
    if generated is None or now is None or max_age_seconds <= 0:
        return False
    if generated > now:
        return False
    return (now - generated).total_seconds() <= max_age_seconds


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if not value.endswith("Z") or parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed


def _sha256_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise HiddenTrustAssumptionScannerError("HIDDEN_TRUST_INPUT_MALFORMED") from exc
