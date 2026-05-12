#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from governance.operations_observability import (  # noqa: E402
    collect_governance_health_snapshot,
    diagnostics_json,
    verify_baseline_lineage_status,
    verify_dependency_graph_status,
    verify_governance_status,
    verify_release_integrity_status,
    verify_signer_continuity_status,
)
from governance.incidents import (  # noqa: E402
    GovernanceIncidentError,
    assert_audit_safe_payload,
    fail_closed_reason,
    incident_summary,
    recommended_operator_action,
    redact_payload,
    recovery_checklist,
    validate_recovery_path,
)
from governance.policy_pack import (  # noqa: E402
    PolicyPackValidationError,
    assert_policy_diagnostics_safe,
    explain_policy_error,
    policy_pack_summary,
    redacted_policy_payload,
    validate_policy_pack_file,
)
from governance.release_integrity import DEFAULT_BASELINE_TAG, GovernanceReleaseIntegrityError  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="USBAY governance operations diagnostics")
    parser.add_argument(
        "command",
        choices=(
            "status",
            "verify-release",
            "verify-dependencies",
            "verify-signer",
            "verify-baseline",
            "incident-summary",
            "recommended-action",
            "explain-fail-closed",
            "recovery-checklist",
            "validate-recovery",
            "validate-policy-pack",
            "explain-policy-error",
            "show-policy-summary",
        ),
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--baseline-tag", default=DEFAULT_BASELINE_TAG)
    parser.add_argument("--regression-suite-status", default="not_run")
    parser.add_argument("--incident-code")
    parser.add_argument("--failure", action="append", default=[])
    parser.add_argument("--human-approval-confirmed", action="store_true")
    parser.add_argument("--policy-pack", type=Path)
    parser.add_argument("--policy-error-code")
    args = parser.parse_args(argv)

    try:
        if args.command == "status":
            snapshot = verify_governance_status(
                args.root,
                regression_suite_status=args.regression_suite_status,
                baseline_tag=args.baseline_tag,
            )
            print(diagnostics_json({"governance_status": snapshot.to_dict()}))
            return 0
        if args.command == "verify-release":
            print(diagnostics_json({"release_integrity": verify_release_integrity_status(args.root, args.manifest, baseline_tag=args.baseline_tag)}))
            return 0
        if args.command == "verify-dependencies":
            print(diagnostics_json({"dependency_graph": verify_dependency_graph_status(args.root)}))
            return 0
        if args.command == "verify-signer":
            print(diagnostics_json(verify_signer_continuity_status(args.root)))
            return 0
        if args.command == "verify-baseline":
            print(diagnostics_json(verify_baseline_lineage_status(args.root, baseline_tag=args.baseline_tag)))
            return 0
        if args.command == "incident-summary":
            failures = args.failure
            if not failures:
                snapshot = collect_governance_health_snapshot(
                    args.root,
                    regression_suite_status=args.regression_suite_status,
                    baseline_tag=args.baseline_tag,
                )
                failures = list(snapshot.failures)
            payload = {"incident_summary": incident_summary(args.root, failures)}
            assert_audit_safe_payload(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "recommended-action":
            if not args.incident_code:
                raise GovernanceIncidentError("incident_code_required")
            payload = {"recommended_operator_action": recommended_operator_action(args.root, args.incident_code)}
            assert_audit_safe_payload(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "explain-fail-closed":
            if not args.incident_code:
                raise GovernanceIncidentError("incident_code_required")
            payload = {"fail_closed_reason": fail_closed_reason(args.root, args.incident_code)}
            assert_audit_safe_payload(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "recovery-checklist":
            if not args.incident_code:
                raise GovernanceIncidentError("incident_code_required")
            payload = {"recovery_checklist": recovery_checklist(args.root, args.incident_code)}
            assert_audit_safe_payload(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "validate-recovery":
            if not args.incident_code:
                raise GovernanceIncidentError("incident_code_required")
            payload = validate_recovery_path(
                args.root,
                args.incident_code,
                human_approval_confirmed=args.human_approval_confirmed,
            )
            assert_audit_safe_payload(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "validate-policy-pack":
            if args.policy_pack is None:
                raise PolicyPackValidationError("policy_pack_path_required")
            result = validate_policy_pack_file(args.policy_pack)
            payload = {"policy_pack_validation": result.to_dict()}
            payload = redacted_policy_payload(payload)
            assert_policy_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.valid else 1
        if args.command == "explain-policy-error":
            if not args.policy_error_code:
                raise PolicyPackValidationError("policy_error_code_required")
            payload = {"policy_error": explain_policy_error(args.root, args.policy_error_code)}
            assert_policy_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "show-policy-summary":
            if args.policy_pack is None:
                raise PolicyPackValidationError("policy_pack_path_required")
            result = validate_policy_pack_file(args.policy_pack)
            payload = {"policy_summary": policy_pack_summary(result)}
            assert_policy_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.valid else 1
    except (GovernanceReleaseIntegrityError, GovernanceIncidentError, PolicyPackValidationError) as exc:
        payload = redact_payload({"valid": False, "failure": str(exc)})
        payload = redacted_policy_payload(payload)
        assert_audit_safe_payload(payload)
        assert_policy_diagnostics_safe(payload)
        print(diagnostics_json(payload))
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
