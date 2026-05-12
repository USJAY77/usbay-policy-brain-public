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
from governance.policy_simulation import (  # noqa: E402
    PolicySimulationError,
    assert_simulation_diagnostics_safe,
    explain_policy_decision,
    redacted_simulation_payload,
    simulate_policy_file,
    simulation_summary,
)
from governance.policy_parity import (  # noqa: E402
    PolicyParityError,
    assert_parity_diagnostics_safe,
    explain_parity_failure,
    parity_summary,
    redacted_parity_payload,
    verify_policy_parity_files,
)
from governance.policy_proof_bundle import (  # noqa: E402
    PolicyProofBundleError,
    assert_proof_bundle_safe,
    explain_proof_bundle,
    export_policy_proof_bundle_file,
    proof_bundle_summary,
    redacted_proof_bundle_payload,
    verify_policy_proof_bundle_file,
)
from governance.proof_timestamp_anchor import (  # noqa: E402
    ProofTimestampAnchorError,
    anchor_proof_bundle_file,
    assert_timestamp_anchor_safe,
    explain_timestamp_anchor,
    redacted_timestamp_anchor_payload,
    timestamp_anchor_summary,
    verify_proof_timestamp_anchor_file,
)
from governance.rfc3161_timestamp import (  # noqa: E402
    RFC3161TimestampError,
    assert_rfc3161_safe,
    explain_rfc3161_preflight,
    prepare_rfc3161_request_file,
    redacted_rfc3161_payload,
    rfc3161_request_summary,
    verify_rfc3161_request_file,
)
from governance.worm_evidence_manifest import (  # noqa: E402
    WORMEvidenceManifestError,
    assert_worm_safe,
    explain_worm_manifest,
    prepare_worm_manifest_file,
    redacted_worm_payload,
    verify_worm_manifest_file,
    worm_manifest_summary,
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
            "simulate-policy",
            "explain-policy-decision",
            "show-simulation-summary",
            "verify-policy-parity",
            "explain-parity-failure",
            "show-parity-summary",
            "export-policy-proof-bundle",
            "verify-policy-proof-bundle",
            "explain-proof-bundle",
            "anchor-proof-bundle",
            "verify-proof-timestamp",
            "explain-timestamp-anchor",
            "prepare-rfc3161-request",
            "verify-rfc3161-request",
            "explain-rfc3161-preflight",
            "prepare-worm-manifest",
            "verify-worm-manifest",
            "explain-worm-manifest",
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
    parser.add_argument("--request-context", type=Path)
    parser.add_argument("--tenant-id")
    parser.add_argument("--environment")
    parser.add_argument("--risk-level", default="low")
    parser.add_argument("--required-human-approval", action="store_true")
    parser.add_argument("--simulation-error-code")
    parser.add_argument("--runtime-decision", type=Path)
    parser.add_argument("--parity-error-code")
    parser.add_argument("--proof-bundle", type=Path)
    parser.add_argument("--proof-error-code")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validation-timestamp")
    parser.add_argument("--timestamp-anchor", type=Path)
    parser.add_argument("--timestamp-error-code")
    parser.add_argument("--rfc3161-request", type=Path)
    parser.add_argument("--rfc3161-error-code")
    parser.add_argument("--nonce")
    parser.add_argument("--requested-policy-oid")
    parser.add_argument("--worm-manifest", type=Path)
    parser.add_argument("--worm-error-code")
    parser.add_argument("--retention-policy-label")
    parser.add_argument("--artifact-type", default="governance_policy_proof_bundle")
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
        if args.command == "simulate-policy":
            result = _simulate_from_args(args)
            payload = redacted_simulation_payload({"policy_simulation": result.to_dict()})
            assert_simulation_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.decision in {"ALLOW", "DENY", "REQUIRE_HUMAN_REVIEW"} else 1
        if args.command == "explain-policy-decision":
            if not args.simulation_error_code:
                raise PolicySimulationError("simulation_error_code_required")
            payload = {"policy_decision_error": explain_policy_decision(args.root, args.simulation_error_code)}
            assert_simulation_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "show-simulation-summary":
            result = _simulate_from_args(args)
            payload = redacted_simulation_payload({"simulation_summary": simulation_summary(result)})
            assert_simulation_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.decision in {"ALLOW", "DENY", "REQUIRE_HUMAN_REVIEW"} else 1
        if args.command == "verify-policy-parity":
            result = _parity_from_args(args)
            payload = redacted_parity_payload({"policy_parity": result.to_dict()})
            assert_parity_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.valid else 1
        if args.command == "explain-parity-failure":
            if not args.parity_error_code:
                raise PolicyParityError("parity_error_code_required")
            payload = {"parity_failure": explain_parity_failure(args.root, args.parity_error_code)}
            assert_parity_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "show-parity-summary":
            result = _parity_from_args(args)
            payload = redacted_parity_payload({"parity_summary": parity_summary(result)})
            assert_parity_diagnostics_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.valid else 1
        if args.command == "export-policy-proof-bundle":
            if args.output is None:
                raise PolicyProofBundleError("proof_bundle_output_required")
            bundle = export_policy_proof_bundle_file(
                *_proof_source_args(args),
                args.output,
                tenant_id=args.tenant_id,
                environment=args.environment,
                risk_level=args.risk_level,
                required_human_approval=args.required_human_approval,
                validation_timestamp=args.validation_timestamp,
            )
            payload = redacted_proof_bundle_payload({"policy_proof_bundle": proof_bundle_summary(bundle), "output": str(args.output)})
            assert_proof_bundle_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "verify-policy-proof-bundle":
            if args.proof_bundle is None:
                raise PolicyProofBundleError("proof_bundle_path_required")
            result = verify_policy_proof_bundle_file(args.proof_bundle)
            payload = redacted_proof_bundle_payload({"policy_proof_bundle_verification": result.to_dict()})
            assert_proof_bundle_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.valid else 1
        if args.command == "explain-proof-bundle":
            if not args.proof_error_code:
                raise PolicyProofBundleError("proof_bundle_error_code_required")
            payload = {"proof_bundle_error": explain_proof_bundle(args.root, args.proof_error_code)}
            assert_proof_bundle_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "anchor-proof-bundle":
            if args.proof_bundle is None:
                raise ProofTimestampAnchorError("proof_bundle_path_required")
            if args.output is None:
                raise ProofTimestampAnchorError("timestamp_anchor_output_required")
            anchor = anchor_proof_bundle_file(args.proof_bundle, args.output, timestamp=args.validation_timestamp)
            payload = redacted_timestamp_anchor_payload({"proof_timestamp_anchor": timestamp_anchor_summary(anchor), "output": str(args.output)})
            assert_timestamp_anchor_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "verify-proof-timestamp":
            if args.timestamp_anchor is None:
                raise ProofTimestampAnchorError("timestamp_anchor_path_required")
            result = verify_proof_timestamp_anchor_file(args.timestamp_anchor, proof_bundle_path=args.proof_bundle)
            payload = redacted_timestamp_anchor_payload({"proof_timestamp_verification": result.to_dict()})
            assert_timestamp_anchor_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.valid else 1
        if args.command == "explain-timestamp-anchor":
            if not args.timestamp_error_code:
                raise ProofTimestampAnchorError("timestamp_anchor_error_code_required")
            payload = {"timestamp_anchor_error": explain_timestamp_anchor(args.root, args.timestamp_error_code)}
            assert_timestamp_anchor_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "prepare-rfc3161-request":
            if args.proof_bundle is None:
                raise RFC3161TimestampError("proof_bundle_path_required")
            if args.timestamp_anchor is None:
                raise RFC3161TimestampError("timestamp_anchor_path_required")
            if args.output is None:
                raise RFC3161TimestampError("rfc3161_request_output_required")
            request = prepare_rfc3161_request_file(
                args.proof_bundle,
                args.timestamp_anchor,
                args.output,
                nonce=args.nonce,
                requested_policy_oid=args.requested_policy_oid or "1.3.6.1.4.1.55555.1.3161.0",
            )
            payload = redacted_rfc3161_payload({"rfc3161_request_preflight": rfc3161_request_summary(request), "output": str(args.output)})
            assert_rfc3161_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "verify-rfc3161-request":
            if args.rfc3161_request is None:
                raise RFC3161TimestampError("rfc3161_request_path_required")
            result = verify_rfc3161_request_file(args.rfc3161_request)
            payload = redacted_rfc3161_payload({"rfc3161_request_verification": result.to_dict()})
            assert_rfc3161_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.valid else 1
        if args.command == "explain-rfc3161-preflight":
            if not args.rfc3161_error_code:
                raise RFC3161TimestampError("rfc3161_error_code_required")
            payload = {"rfc3161_preflight_error": explain_rfc3161_preflight(args.root, args.rfc3161_error_code)}
            assert_rfc3161_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "prepare-worm-manifest":
            if args.proof_bundle is None:
                raise WORMEvidenceManifestError("proof_bundle_path_required")
            if args.timestamp_anchor is None:
                raise WORMEvidenceManifestError("timestamp_anchor_path_required")
            if args.rfc3161_request is None:
                raise WORMEvidenceManifestError("rfc3161_request_path_required")
            if args.output is None:
                raise WORMEvidenceManifestError("worm_manifest_output_required")
            if not args.retention_policy_label:
                raise WORMEvidenceManifestError("WORM_RETENTION_POLICY_MISSING")
            manifest = prepare_worm_manifest_file(
                args.proof_bundle,
                args.timestamp_anchor,
                args.rfc3161_request,
                args.output,
                retention_policy_label=args.retention_policy_label,
                created_at=args.validation_timestamp,
                artifact_type=args.artifact_type,
            )
            payload = redacted_worm_payload({"worm_evidence_manifest": worm_manifest_summary(manifest), "output": str(args.output)})
            assert_worm_safe(payload)
            print(diagnostics_json(payload))
            return 0
        if args.command == "verify-worm-manifest":
            if args.worm_manifest is None:
                raise WORMEvidenceManifestError("worm_manifest_path_required")
            result = verify_worm_manifest_file(
                args.worm_manifest,
                proof_bundle_path=args.proof_bundle,
                timestamp_anchor_path=args.timestamp_anchor,
                rfc3161_request_path=args.rfc3161_request,
            )
            payload = redacted_worm_payload({"worm_manifest_verification": result.to_dict()})
            assert_worm_safe(payload)
            print(diagnostics_json(payload))
            return 0 if result.valid else 1
        if args.command == "explain-worm-manifest":
            if not args.worm_error_code:
                raise WORMEvidenceManifestError("worm_error_code_required")
            payload = {"worm_manifest_error": explain_worm_manifest(args.root, args.worm_error_code)}
            assert_worm_safe(payload)
            print(diagnostics_json(payload))
            return 0
    except (
        GovernanceReleaseIntegrityError,
        GovernanceIncidentError,
        PolicyPackValidationError,
        PolicySimulationError,
        PolicyParityError,
        PolicyProofBundleError,
        ProofTimestampAnchorError,
        RFC3161TimestampError,
        WORMEvidenceManifestError,
    ) as exc:
        payload = redact_payload({"valid": False, "failure": str(exc)})
        payload = redacted_policy_payload(payload)
        payload = redacted_simulation_payload(payload)
        payload = redacted_parity_payload(payload)
        payload = redacted_proof_bundle_payload(payload)
        payload = redacted_timestamp_anchor_payload(payload)
        payload = redacted_rfc3161_payload(payload)
        payload = redacted_worm_payload(payload)
        assert_audit_safe_payload(payload)
        assert_policy_diagnostics_safe(payload)
        assert_simulation_diagnostics_safe(payload)
        assert_parity_diagnostics_safe(payload)
        assert_proof_bundle_safe(payload)
        assert_timestamp_anchor_safe(payload)
        assert_rfc3161_safe(payload)
        assert_worm_safe(payload)
        print(diagnostics_json(payload))
        return 1
    return 2


def _simulate_from_args(args: argparse.Namespace):
    if args.policy_pack is None:
        raise PolicySimulationError("policy_pack_path_required")
    if args.request_context is None:
        raise PolicySimulationError("simulation_request_context_required")
    if not args.tenant_id:
        raise PolicySimulationError("simulation_tenant_id_required")
    if not args.environment:
        raise PolicySimulationError("simulation_environment_required")
    return simulate_policy_file(
        args.policy_pack,
        args.request_context,
        tenant_id=args.tenant_id,
        environment=args.environment,
        risk_level=args.risk_level,
        required_human_approval=args.required_human_approval,
    )


def _parity_from_args(args: argparse.Namespace):
    if args.policy_pack is None:
        raise PolicyParityError("policy_pack_path_required")
    if args.request_context is None:
        raise PolicyParityError("parity_request_context_required")
    if args.runtime_decision is None:
        raise PolicyParityError("runtime_decision_path_required")
    if not args.tenant_id:
        raise PolicyParityError("parity_tenant_id_required")
    if not args.environment:
        raise PolicyParityError("parity_environment_required")
    return verify_policy_parity_files(
        args.policy_pack,
        args.request_context,
        args.runtime_decision,
        tenant_id=args.tenant_id,
        environment=args.environment,
        risk_level=args.risk_level,
        required_human_approval=args.required_human_approval,
    )


def _proof_source_args(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    if args.policy_pack is None:
        raise PolicyProofBundleError("policy_pack_path_required")
    if args.request_context is None:
        raise PolicyProofBundleError("proof_request_context_required")
    if args.runtime_decision is None:
        raise PolicyProofBundleError("proof_runtime_decision_required")
    if not args.tenant_id:
        raise PolicyProofBundleError("proof_tenant_id_required")
    if not args.environment:
        raise PolicyProofBundleError("proof_environment_required")
    return args.policy_pack, args.request_context, args.runtime_decision


if __name__ == "__main__":
    raise SystemExit(main())
