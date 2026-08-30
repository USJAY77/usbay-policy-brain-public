#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = Path(__file__).resolve().parent / "templates" / "governance_dashboard.html"
DEFAULT_OUTPUT = Path("artifacts/governance-dashboard.html")
DEFAULT_AUDIT_OUTPUT = Path("artifacts/governance-dashboard-audit.json")
DEFAULT_TIMELINES = (Path("pr41_timeline.json"), Path("pr42_timeline.json"))
DEFAULT_REVIEWS = (Path("pr41_reviews.json"), Path("pr42_reviews.json"))
DEFAULT_REVIEWERS = (Path("pr41_reviewers.json"), Path("pr42_reviewers.json"))
DEFAULT_FRONTEND_SECRET_AUDIT = Path("artifacts/frontend-secret-exposure-audit.json")

DASHBOARD_SCHEMA = "usbay.governance_dashboard_audit.v1"
POLICY_VERSION = "usbay.governance_dashboard_policy.v1"
SAFE_STATES = {"PASS", "BLOCKED", "FAIL", "WARN", "REVIEW_REQUIRED"}
REDACTED = "[REDACTED]"
SENSITIVE_KEYS = {
    "authorization",
    "credential",
    "credentials",
    "password",
    "payload",
    "private_key",
    "private-key",
    "record_signature",
    "secret",
    "signature",
    "token",
    "approval_contents",
}
SECRET_VALUE_PATTERN = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|-----BEGIN PGP SIGNATURE-----|ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|xox[baprs]-[A-Za-z0-9-]+)",
    re.IGNORECASE,
)


class DashboardValidationError(RuntimeError):
    """Raised when governance evidence cannot be safely rendered."""


@dataclass(frozen=True)
class EvidenceSource:
    name: str
    path: Path
    sha256: str


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def pretty_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def load_json_strict(path: Path) -> Any:
    if not path.is_file():
        raise DashboardValidationError(f"GOVERNANCE_DASHBOARD_EVIDENCE_MISSING:{path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DashboardValidationError(f"GOVERNANCE_DASHBOARD_EVIDENCE_MALFORMED:{path}") from exc


def sanitize_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key in sorted(value):
            normalized_key = str(key).lower()
            if normalized_key in SENSITIVE_KEYS or normalized_key.endswith("_token") or normalized_key.endswith("_secret"):
                sanitized[str(key)] = REDACTED
            else:
                sanitized[str(key)] = sanitize_evidence(value[key])
        return sanitized
    if isinstance(value, list):
        return [sanitize_evidence(item) for item in value]
    if isinstance(value, str):
        if SECRET_VALUE_PATTERN.search(value):
            return REDACTED
        return value
    return value


def assert_sanitized(value: Any) -> None:
    rendered = canonical_json(value)
    forbidden = ("PRIVATE KEY", "BEGIN PGP SIGNATURE", "ghp_", "github_pat_", "xoxb-", "approval_contents")
    leaked = [marker for marker in forbidden if marker in rendered]
    if leaked:
        raise DashboardValidationError("GOVERNANCE_DASHBOARD_SANITIZER_FAILED:" + ",".join(leaked))


def _actor_login(value: Any) -> str:
    if isinstance(value, dict):
        login = value.get("login")
        if isinstance(login, str) and login:
            return login
    return ""


def _commit_events(timeline: Any) -> list[dict[str, Any]]:
    if not isinstance(timeline, list):
        raise DashboardValidationError("GOVERNANCE_DASHBOARD_TIMELINE_INVALID")
    commits = [item for item in timeline if isinstance(item, dict) and item.get("sha")]
    if not commits:
        raise DashboardValidationError("GOVERNANCE_DASHBOARD_TIMELINE_COMMITS_MISSING")
    return commits


def validate_commit_lineage(commits: list[dict[str, Any]]) -> list[str]:
    anomalies: list[str] = []
    previous_sha = ""
    for index, commit in enumerate(commits):
        sha = str(commit.get("sha") or "")
        if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
            anomalies.append(f"COMMIT_SHA_INVALID:{index}")
        verification = commit.get("verification") if isinstance(commit.get("verification"), dict) else {}
        if verification.get("verified") is not True or verification.get("reason") != "valid":
            anomalies.append(f"UNSIGNED_GOVERNANCE_COMMIT:{sha or index}")
        verified_at = verification.get("verified_at")
        if not isinstance(verified_at, str) or not verified_at:
            anomalies.append(f"COMMIT_VERIFICATION_TIMESTAMP_MISSING:{sha or index}")
        parents = commit.get("parents") if isinstance(commit.get("parents"), list) else []
        parent_shas = [str(parent.get("sha")) for parent in parents if isinstance(parent, dict) and parent.get("sha")]
        if index > 0 and previous_sha not in parent_shas:
            anomalies.append(f"PROVENANCE_CHAIN_BREAK:{sha or index}")
        previous_sha = sha
    return anomalies


def summarize_reviews(reviews: list[Any]) -> dict[str, Any]:
    if not isinstance(reviews, list):
        raise DashboardValidationError("GOVERNANCE_DASHBOARD_REVIEWS_INVALID")
    latest: dict[str, dict[str, Any]] = {}
    for review in reviews:
        if not isinstance(review, dict):
            continue
        login = _actor_login(review.get("user"))
        if not login:
            continue
        submitted_at = str(review.get("submitted_at") or "")
        if login not in latest or submitted_at >= str(latest[login].get("submitted_at") or ""):
            latest[login] = review
    approvals = sorted(login for login, review in latest.items() if str(review.get("state") or "").upper() == "APPROVED")
    return {
        "approval_count": len(approvals),
        "approval_actor_hashes": [sha256_text(login) for login in approvals],
        "approval_actors": approvals,
        "decision": "PASS" if len(approvals) >= 2 else "BLOCKED",
        "reason": "DUAL_REVIEWER_AUTHORIZATION_VERIFIED" if len(approvals) >= 2 else "DUAL_REVIEWER_AUTHORIZATION_MISSING",
    }


def summarize_requested_reviewers(reviewers: Any) -> dict[str, Any]:
    if not isinstance(reviewers, dict):
        raise DashboardValidationError("GOVERNANCE_DASHBOARD_REVIEWERS_INVALID")
    users = reviewers.get("users") if isinstance(reviewers.get("users"), list) else []
    teams = reviewers.get("teams") if isinstance(reviewers.get("teams"), list) else []
    return {
        "requested_user_count": len(users),
        "requested_team_count": len(teams),
        "requested_user_hashes": [sha256_text(_actor_login(user)) for user in users if _actor_login(user)],
    }


def summarize_frontend_secret_audit(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DashboardValidationError("GOVERNANCE_DASHBOARD_FRONTEND_SECRET_AUDIT_INVALID")
    required = {"schema", "decision", "finding_count", "audit_hash", "scanner_policy_hash", "created_at_utc"}
    missing = sorted(required - set(payload))
    if missing:
        raise DashboardValidationError("GOVERNANCE_DASHBOARD_FRONTEND_SECRET_AUDIT_MISSING_FIELDS:" + ",".join(missing))
    decision = str(payload.get("decision"))
    finding_count = int(payload.get("finding_count"))
    if decision != "ALLOW" or finding_count != 0:
        return {"decision": "BLOCKED", "reason": "FRONTEND_SECRET_EXPOSURE_FINDINGS_PRESENT", "finding_count": finding_count}
    return {
        "decision": "PASS",
        "reason": "FRONTEND_SECRET_EXPOSURE_VALIDATION_CLEAN",
        "finding_count": finding_count,
        "audit_hash": payload["audit_hash"],
        "scanner_policy_hash": payload["scanner_policy_hash"],
        "created_at_utc": payload["created_at_utc"],
    }


def build_dashboard_state(
    *,
    root: Path = ROOT,
    timeline_paths: tuple[Path, ...] = DEFAULT_TIMELINES,
    review_paths: tuple[Path, ...] = DEFAULT_REVIEWS,
    reviewer_paths: tuple[Path, ...] = DEFAULT_REVIEWERS,
    frontend_secret_audit_path: Path = DEFAULT_FRONTEND_SECRET_AUDIT,
    actor: str = "codex",
    device: str = "local",
    timestamp: str = "2026-05-22T00:00:00Z",
) -> dict[str, Any]:
    sources: list[EvidenceSource] = []
    timelines = []
    reviews = []
    reviewers = []
    for path in timeline_paths:
        resolved = _resolve(root, path)
        timelines.append((path.as_posix(), load_json_strict(resolved)))
        sources.append(EvidenceSource("timeline", path, sha256_file(resolved)))
    for path in review_paths:
        resolved = _resolve(root, path)
        reviews.append((path.as_posix(), load_json_strict(resolved)))
        sources.append(EvidenceSource("reviews", path, sha256_file(resolved)))
    for path in reviewer_paths:
        resolved = _resolve(root, path)
        reviewers.append((path.as_posix(), load_json_strict(resolved)))
        sources.append(EvidenceSource("requested_reviewers", path, sha256_file(resolved)))
    frontend_resolved = _resolve(root, frontend_secret_audit_path)
    frontend_secret_audit = load_json_strict(frontend_resolved)
    sources.append(EvidenceSource("frontend_secret_audit", frontend_secret_audit_path, sha256_file(frontend_resolved)))

    timeline_rows: list[dict[str, Any]] = []
    all_anomalies: list[str] = []
    verified_commit_count = 0
    for source_path, timeline in timelines:
        commits = _commit_events(timeline)
        anomalies = validate_commit_lineage(commits)
        all_anomalies.extend(f"{source_path}:{anomaly}" for anomaly in anomalies)
        for commit in commits:
            verification = commit.get("verification") if isinstance(commit.get("verification"), dict) else {}
            verified = verification.get("verified") is True and verification.get("reason") == "valid"
            if verified:
                verified_commit_count += 1
            timestamp_value = verification.get("verified_at") or (commit.get("author") or {}).get("date")
            timeline_rows.append(
                {
                    "source": source_path,
                    "commit_sha": commit.get("sha"),
                    "verification_state": "VERIFIED" if verified else "UNVERIFIED",
                    "verification_reason": verification.get("reason") or "missing",
                    "audit_timestamp": timestamp_value,
                    "reviewer_chain": [],
                    "governance_decision": "PASS" if verified else "BLOCKED",
                    "anomaly_markers": [] if verified else ["UNSIGNED_GOVERNANCE_COMMIT"],
                }
            )

    review_summaries = []
    for source_path, payload in reviews:
        summary = summarize_reviews(payload)
        review_summaries.append({"source": source_path, **summary})
        if summary["decision"] != "PASS":
            all_anomalies.append(f"{source_path}:{summary['reason']}")
    requested_reviewer_summaries = [
        {"source": source_path, **summarize_requested_reviewers(payload)} for source_path, payload in reviewers
    ]
    reviewer_chain = sorted({actor for summary in review_summaries for actor in summary["approval_actors"]})
    for row in timeline_rows:
        row["reviewer_chain"] = reviewer_chain

    frontend_summary = summarize_frontend_secret_audit(frontend_secret_audit)
    if frontend_summary["decision"] != "PASS":
        all_anomalies.append(str(frontend_summary["reason"]))

    branch_hygiene = {
        "decision": "BLOCKED",
        "reason": "BRANCH_HYGIENE_EVIDENCE_MISSING",
        "evidence_required": "governed branch hygiene audit artifact",
    }
    all_anomalies.append(branch_hygiene["reason"])

    provenance_export_state = {
        "decision": "PASS" if verified_commit_count == len(timeline_rows) and timeline_rows else "BLOCKED",
        "verified_commit_count": verified_commit_count,
        "timeline_entry_count": len(timeline_rows),
        "reason": "VERIFIED_COMMIT_LINEAGE_PRESENT" if verified_commit_count == len(timeline_rows) else "UNVERIFIED_COMMIT_LINEAGE",
    }
    if provenance_export_state["decision"] != "PASS":
        all_anomalies.append(provenance_export_state["reason"])

    controls = [
        {"name": "verified_commit_lineage", **provenance_export_state},
        {
            "name": "reviewer_approvals",
            "decision": "PASS" if all(summary["decision"] == "PASS" for summary in review_summaries) else "BLOCKED",
            "reason": "ALL_REVIEW_CHAINS_VERIFIED" if all(summary["decision"] == "PASS" for summary in review_summaries) else "REVIEW_CHAIN_INCOMPLETE",
            "evidence_count": len(review_summaries),
        },
        {"name": "branch_hygiene_status", **branch_hygiene},
        {"name": "frontend_secret_exposure_validation", **frontend_summary},
        {
            "name": "governance_audit_export_summaries",
            "decision": "PASS",
            "reason": "SANITIZED_HASH_ONLY_EXPORT_SUMMARIES",
            "evidence_source_count": len(sources),
        },
    ]

    overall_decision = "PASS" if all(control["decision"] == "PASS" for control in controls) and not all_anomalies else "BLOCKED"
    audit_payload = {
        "schema": DASHBOARD_SCHEMA,
        "actor": actor,
        "device": device,
        "decision": overall_decision,
        "timestamp": timestamp,
        "policy_version": POLICY_VERSION,
        "controls": controls,
        "governance_anomalies": sorted(set(all_anomalies)),
        "timeline": timeline_rows,
        "reviewer_approvals": sanitize_evidence(review_summaries),
        "requested_reviewers": sanitize_evidence(requested_reviewer_summaries),
        "frontend_secret_exposure_validation": sanitize_evidence(frontend_summary),
        "provenance_export_state": provenance_export_state,
        "evidence_sources": [
            {"name": source.name, "path": source.path.as_posix(), "sha256": source.sha256} for source in sources
        ],
    }
    audit_payload["dashboard_audit_hash"] = sha256_text(canonical_json(audit_payload))
    sanitized = sanitize_evidence(audit_payload)
    assert_sanitized(sanitized)
    return sanitized


def render_dashboard(state: dict[str, Any], template_path: Path = TEMPLATE) -> str:
    if state.get("schema") != DASHBOARD_SCHEMA:
        raise DashboardValidationError("GOVERNANCE_DASHBOARD_SCHEMA_INVALID")
    for field in ("actor", "device", "decision", "timestamp", "policy_version"):
        if not state.get(field):
            raise DashboardValidationError(f"GOVERNANCE_DASHBOARD_AUDIT_FIELD_MISSING:{field}")
    template = template_path.read_text(encoding="utf-8")
    control_rows = []
    for control in state.get("controls", []):
        decision = html.escape(str(control.get("decision", "BLOCKED")))
        if decision not in SAFE_STATES:
            decision = "BLOCKED"
        control_rows.append(
            "        <tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(control.get("name", ""))),
                decision,
                decision,
                html.escape(str(control.get("evidence_count", control.get("evidence_source_count", control.get("verified_commit_count", ""))))),
                html.escape(str(control.get("reason", ""))),
            )
        )
    timeline_rows = []
    for item in state.get("timeline", []):
        timeline_rows.append(
            "        <tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>".format(
                html.escape(str(item.get("audit_timestamp", ""))),
                html.escape(str(item.get("commit_sha", ""))),
                html.escape(str(item.get("verification_state", ""))),
                html.escape(", ".join(str(actor) for actor in item.get("reviewer_chain", []))),
                html.escape(str(item.get("governance_decision", "BLOCKED"))),
                html.escape(str(item.get("governance_decision", "BLOCKED"))),
                html.escape(", ".join(str(marker) for marker in item.get("anomaly_markers", []))),
            )
        )
    evidence_json = html.escape(pretty_json(state))
    replacements = {
        "{overall_decision}": html.escape(str(state["decision"])),
        "{control_rows}": "\n".join(control_rows),
        "{timeline_rows}": "\n".join(timeline_rows),
        "{evidence_json}": evidence_json,
    }
    rendered = template
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    return rendered


def write_outputs(state: dict[str, Any], html_output: Path, audit_output: Path) -> None:
    html_output.parent.mkdir(parents=True, exist_ok=True)
    audit_output.parent.mkdir(parents=True, exist_ok=True)
    audit_output.write_text(canonical_json(state) + "\n", encoding="utf-8")
    html_output.write_text(render_dashboard(state), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render deterministic USBAY governance evidence dashboard")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--audit-output", type=Path, default=DEFAULT_AUDIT_OUTPUT)
    parser.add_argument("--timestamp", default="2026-05-22T00:00:00Z")
    args = parser.parse_args(argv)
    state = build_dashboard_state(root=args.root, timestamp=args.timestamp)
    html_output = _resolve(args.root, args.output)
    audit_output = _resolve(args.root, args.audit_output)
    write_outputs(state, html_output, audit_output)
    print(f"GOVERNANCE_DASHBOARD_DECISION={state['decision']}")
    print(f"GOVERNANCE_DASHBOARD_AUDIT={audit_output}")
    print(f"GOVERNANCE_DASHBOARD_HTML={html_output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except DashboardValidationError as exc:
        raise SystemExit(f"GOVERNANCE_DASHBOARD_BLOCKED:{exc}") from exc
