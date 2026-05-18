#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.verify_production_readiness import LANE_FAST_CONTRACT, LANE_HEAVY_SCAN, LANE_ORCHESTRATION, load_lane_policy

PROVENANCE_VERSION = "usbay.governance_provenance.v1"
SIGNER_MODE = "hash-only-local"
SIGNATURE_ALGORITHM = "sha256-detached-hash"
DEFAULT_OUTPUT = Path("evidence/governance-provenance.json")
DEFAULT_EVIDENCE = Path("evidence/production-readiness-guard-output.txt")
DEFAULT_WORKFLOW = Path(".github/workflows/production-readiness.yml")
ALLOWED_LANES = (LANE_FAST_CONTRACT, LANE_ORCHESTRATION, LANE_HEAVY_SCAN)
ALLOWED_RESULTS = {"PASS", "FAIL", "BLOCKED", "REVIEW_REQUIRED"}


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"GOVERNANCE_PROVENANCE_EVIDENCE_MISSING:{path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_value(args: list[str], fallback: str = "unknown") -> str:
    completed = subprocess.run(["git", "-C", str(REPO_ROOT), *args], text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        return fallback
    value = completed.stdout.strip()
    return value or fallback


def build_provenance(
    *,
    root: Path,
    lane: str,
    workflow_name: str,
    workflow_path: Path,
    evidence_path: Path,
    validation_result: str,
    timestamp_utc: str,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    if lane not in ALLOWED_LANES:
        raise SystemExit("GOVERNANCE_PROVENANCE_LANE_UNKNOWN")
    if validation_result not in ALLOWED_RESULTS:
        raise SystemExit("GOVERNANCE_PROVENANCE_VALIDATION_RESULT_INVALID")
    root = root.resolve()
    workflow_abs = workflow_path if workflow_path.is_absolute() else root / workflow_path
    evidence_abs = evidence_path if evidence_path.is_absolute() else root / evidence_path
    _policy, policy_hash = load_lane_policy(root)
    workflow_hash = sha256_file(workflow_abs)
    evidence_hash = sha256_file(evidence_abs)
    resolved_commit = commit_sha or git_value(["rev-parse", "HEAD"])
    orchestration_payload = {
        "governance_lane": lane,
        "workflow_name": workflow_name,
        "workflow_sha": workflow_hash,
        "commit_sha": resolved_commit,
        "policy_hash": policy_hash,
        "evidence_hash": evidence_hash,
        "validation_result": validation_result,
    }
    orchestration_hash = sha256_text(canonical_json(orchestration_payload))
    signed_body = {
        "provenance_version": PROVENANCE_VERSION,
        "governance_lane": lane,
        "workflow_name": workflow_name,
        "workflow_sha": workflow_hash,
        "commit_sha": resolved_commit,
        "policy_hash": policy_hash,
        "orchestration_hash": orchestration_hash,
        "evidence_hash": evidence_hash,
        "timestamp_utc": timestamp_utc,
        "validation_result": validation_result,
        "signer_mode": SIGNER_MODE,
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }
    payload_hash = sha256_text(canonical_json(signed_body))
    signature = sha256_text(canonical_json({"payload_hash": payload_hash, "signer_mode": SIGNER_MODE}))
    provenance = {
        **signed_body,
        "signature": signature,
        "provenance_payload_hash": payload_hash,
    }
    provenance["provenance_fingerprint"] = sha256_text(canonical_json(provenance))
    return provenance


def write_provenance(path: Path, provenance: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(provenance) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate hash-only USBAY governance provenance evidence")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--lane", choices=ALLOWED_LANES, default=LANE_FAST_CONTRACT)
    parser.add_argument("--workflow-name", default="production-readiness")
    parser.add_argument("--workflow-path", type=Path, default=DEFAULT_WORKFLOW)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timestamp-utc", default=utc_now())
    parser.add_argument("--validation-result", choices=sorted(ALLOWED_RESULTS), default="PASS")
    parser.add_argument("--commit-sha")
    args = parser.parse_args(argv)
    provenance = build_provenance(
        root=args.root,
        lane=args.lane,
        workflow_name=args.workflow_name,
        workflow_path=args.workflow_path,
        evidence_path=args.evidence,
        validation_result=args.validation_result,
        timestamp_utc=args.timestamp_utc,
        commit_sha=args.commit_sha,
    )
    output_path = args.output if args.output.is_absolute() else args.root / args.output
    write_provenance(output_path, provenance)
    print("GOVERNANCE_PROVENANCE_CREATED=true")
    print(f"signer_mode={SIGNER_MODE}")
    print(f"governance_lane={provenance['governance_lane']}")
    print(f"policy_hash={provenance['policy_hash']}")
    print(f"evidence_hash={provenance['evidence_hash']}")
    print(f"provenance_fingerprint={provenance['provenance_fingerprint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
