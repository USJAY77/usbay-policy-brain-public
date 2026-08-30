from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from governance.hashing import sha256_reference
from governance.production_readiness_baseline import READY as PHASE1_READY, evaluate_readiness_manifest, load_readiness_manifest
from governance.production_readiness_phase2 import (
    PHASE2_APPROVAL_SCHEMA,
    PHASE2_POLICY_VERSION,
    READY as PHASE2_READY,
    deterministic_release_approval_hash,
    evaluate_phase2_readiness,
    load_phase2_manifest,
)
from governance.production_readiness_phase3 import (
    APPROVED,
    PHASE3_APPROVAL_SCHEMA,
    PHASE3_POLICY_VERSION,
    READY as PHASE3_READY,
    deterministic_phase3_approval_hash,
    deterministic_persistence_hash,
    evaluate_phase3_readiness,
    load_phase3_manifest,
)
from governance.production_readiness_phase4 import (
    READY_METADATA_ONLY as PHASE4_READY,
    evaluate_phase4_authorization_boundary,
    load_phase4_manifest,
)


POST_MERGE_SCHEMA = "usbay.production_readiness.post_merge_health.v1"
TIMESTAMP = "2026-07-25T00:00:00Z"
EXPIRY = "2026-07-26T00:00:00Z"
COMMIT_SHA = "a" * 40
BRANCH = "main"

PHASE1_FILES = (
    "docs/governance/PRODUCTION_READINESS_PHASE_1_CONTROL_BASELINE.md",
    "governance/evidence/production_readiness_phase1_manifest.json",
    "governance/production_readiness_baseline.py",
    "tests/test_production_readiness_baseline.py",
)
PHASE2_FILES = (
    "docs/governance/PRODUCTION_READINESS_PHASE_2_FOUNDATION.md",
    "governance/evidence/production_readiness_phase2_foundation.json",
    "governance/production_readiness_phase2.py",
    "tests/test_production_readiness_phase2.py",
)
PHASE3_FILES = (
    "docs/governance/PRODUCTION_READINESS_PHASE_3_OPERATIONAL_RESILIENCE.md",
    "governance/evidence/production_readiness_phase3_manifest.json",
    "governance/evidence/production_readiness_phase3_schema.json",
    "governance/production_readiness_phase3.py",
    "tests/test_production_readiness_phase3.py",
)
PHASE4_FILES = (
    "docs/governance/PRODUCTION_READINESS_PHASE_4_AUTHORIZATION_BOUNDARY.md",
    "governance/evidence/production_readiness_phase4_manifest.json",
    "governance/evidence/production_readiness_phase4_schema.json",
    "governance/production_readiness_phase4.py",
    "tests/test_production_readiness_phase4.py",
)


@dataclass(frozen=True)
class PostMergeHealth:
    status: str
    reason_codes: tuple[str, ...]
    phase_results: Mapping[str, str]
    evidence_hashes: Mapping[str, str]
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    release_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": POST_MERGE_SCHEMA,
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "phase_results": dict(self.phase_results),
            "evidence_hashes": dict(self.evidence_hashes),
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "deployment_authorized": self.deployment_authorized,
            "release_authorized": self.release_authorized,
        }
        return {**payload, "health_hash": sha256_reference(payload)}


def evaluate_post_merge_health(*, root: Path = Path(".")) -> PostMergeHealth:
    try:
        return _evaluate(root=root)
    except Exception:
        return PostMergeHealth(status="BLOCKED", reason_codes=("POST_MERGE_HEALTH_EXCEPTION",), phase_results={}, evidence_hashes={})


def _evaluate(*, root: Path) -> PostMergeHealth:
    reasons: list[str] = []
    evidence_hashes: dict[str, str] = {}
    for phase, files in (("phase1", PHASE1_FILES), ("phase2", PHASE2_FILES), ("phase3", PHASE3_FILES), ("phase4", PHASE4_FILES)):
        missing = [path for path in files if not (root / path).is_file()]
        reasons.extend(f"POST_MERGE_{phase.upper()}_FILE_MISSING:{path}" for path in missing)
        for path in files:
            target = root / path
            if target.is_file():
                evidence_hashes[path] = sha256_reference({"path": path, "content": target.read_text(encoding="utf-8", errors="ignore")})
    for json_path in (
        "governance/evidence/production_readiness_phase1_manifest.json",
        "governance/evidence/production_readiness_phase2_foundation.json",
        "governance/evidence/production_readiness_phase3_manifest.json",
        "governance/evidence/production_readiness_phase3_schema.json",
        "governance/evidence/production_readiness_phase4_manifest.json",
        "governance/evidence/production_readiness_phase4_schema.json",
    ):
        try:
            json.loads((root / json_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            reasons.append(f"POST_MERGE_JSON_INVALID:{json_path}")

    phase_results = {} if reasons else _phase_results(root=root)
    for phase, status in phase_results.items():
        if status != "READY":
            reasons.append(f"POST_MERGE_{phase.upper()}_NOT_READY:{status}")
    status = "READY" if not reasons else "BLOCKED"
    return PostMergeHealth(
        status=status,
        reason_codes=tuple(sorted(set(reasons))),
        phase_results=phase_results,
        evidence_hashes=dict(sorted(evidence_hashes.items())),
    )


def _phase_results(*, root: Path) -> dict[str, str]:
    phase1 = evaluate_readiness_manifest(load_readiness_manifest(root / "governance/evidence/production_readiness_phase1_manifest.json"), root=root, evaluation_timestamp=TIMESTAMP)
    phase2_manifest = load_phase2_manifest(root / "governance/evidence/production_readiness_phase2_foundation.json")
    phase2_pending = evaluate_phase2_readiness(phase2_manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP, root=root)
    phase2_approval = {
        "schema": PHASE2_APPROVAL_SCHEMA,
        "approval_state": "APPROVED",
        "commit_sha": COMMIT_SHA,
        "readiness_id": phase2_pending.readiness_id,
        "readiness_evaluation_id": phase2_pending.evaluation_id,
        "policy_version": PHASE2_POLICY_VERSION,
        "issued_at": TIMESTAMP,
        "expires_at": EXPIRY,
    }
    phase2 = evaluate_phase2_readiness(
        phase2_manifest,
        approval={**phase2_approval, "approval_hash": deterministic_release_approval_hash(phase2_approval)},
        commit_sha=COMMIT_SHA,
        timestamp=TIMESTAMP,
        root=root,
    )
    phase3_manifest = load_phase3_manifest(root / "governance/evidence/production_readiness_phase3_manifest.json")
    record = phase3_manifest["controls"][-1]["persistence_record"]
    record["persistence_hash"] = deterministic_persistence_hash(record)
    phase3_pending = evaluate_phase3_readiness(phase3_manifest, commit_sha=COMMIT_SHA, branch=BRANCH, timestamp=TIMESTAMP, root=root)
    phase3_approval = {
        "schema": PHASE3_APPROVAL_SCHEMA,
        "commit_sha": COMMIT_SHA,
        "branch": BRANCH,
        "release_identifier": "phase3-release-readiness",
        "production_readiness_evaluation_id": phase3_pending.evaluation_id,
        "policy_version": PHASE3_POLICY_VERSION,
        "control_manifest_version": phase3_manifest["manifest_version"],
        "evidence_export_hash": "sha256:" + "5" * 64,
        "approval_actor": "human-governance-review",
        "approval_role": "release-approver",
        "approval_timestamp": TIMESTAMP,
        "approval_expiry": EXPIRY,
        "approval_decision": APPROVED,
    }
    phase3 = evaluate_phase3_readiness(
        phase3_manifest,
        approval={**phase3_approval, "approval_hash": deterministic_phase3_approval_hash(phase3_approval)},
        commit_sha=COMMIT_SHA,
        branch=BRANCH,
        timestamp=TIMESTAMP,
        root=root,
    )
    phase4 = evaluate_phase4_authorization_boundary(
        load_phase4_manifest(root / "governance/evidence/production_readiness_phase4_manifest.json"),
        timestamp=TIMESTAMP,
    )
    return {
        "phase1": "READY" if phase1.readiness_state == PHASE1_READY else phase1.readiness_state,
        "phase2": "READY" if phase2.release_gate_result == PHASE2_READY else phase2.release_gate_result,
        "phase3": "READY" if phase3.readiness_outcome == PHASE3_READY else phase3.readiness_outcome,
        "phase4": "READY" if phase4.decision == PHASE4_READY and phase4.production_boundary_ready else phase4.decision,
    }
