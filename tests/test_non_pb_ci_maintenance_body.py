"""Synthetic controls using unittest; no enrollment or approval."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pytest

from scripts import non_pb_ci_maintenance_body as route
from scripts.governance_pr_body_integration import generate_pr_body, pb026_metadata, validate_repository_template
from scripts.governance_pr_template_validator import generate_pr_body as pb025_body, pb025_metadata
from scripts.usbay_pb_metadata_authority import PBMetadata, generate_metadata, validate_generated_metadata, MetadataAuthorityBlocked


def metadata():
    return route.MaintenanceMetadata(
        route.ROUTE, "synthetic/repository", "a" * 40, "b" * 40,
        "Synthetic owner reference, not authority.", "Correct synthetic CI dependencies.",
        "Human scope review required.", "Existing policy, no waiver.",
        "https://github.com/synthetic/repository/actions/runs/123", "b" * 40,
        "Synthetic result: 13 selected, not a real run.", "Synthetic audit reference.",
        "Reviewable maintenance.", "Decline before merge; retain evidence.")


CHANGES = [("M", ".github/workflows/governance-resilience.yml"), ("A", "requirements-resilience.txt")]
SECTIONS = {"PURPOSE", "RISK", "POLICY LINK", "REQUIRED APPROVALS", "GOVERNANCE CHECKS", "AUDIT",
            "IMPACT", "MECHANISM", "GAP", "VALIDATION", "VALIDATION RESULTS", "CHANGED FILES",
            "SOURCE", "COMMIT OR SOURCE REFERENCE", "ROLLBACK", "ROLLBACK PLAN", "DECISION", "STATUS"}

pytestmark = pytest.mark.governance


class MaintenanceTests(unittest.TestCase):
    def test_positive_complete_non_authorizing_non_mutating(self):
        m = metadata()
        before = asdict(m)
        changes = list(CHANGES)
        body = route.generate_body(m, changes)
        self.assertEqual({s[3:].upper() for s in body.splitlines() if s.startswith("## ")}, SECTIONS)
        self.assertIn("## REQUIRED APPROVALS\n- USBAY-GLOBAL23\n- USBAY-AUDIT", body)
        self.assertIn("## Decision\nREVIEW_REQUIRED", body)
        self.assertIn("## Status\nAWAITING_APPROVAL", body)
        self.assertIn(m.validation_reference, body)
        self.assertIn(m.candidate_sha, body)
        self.assertEqual(asdict(m), before)
        self.assertEqual(changes, CHANGES)
        route.validate_body(body, m, changes)

    def test_missing_fields(self):
        for field in route.FIELDS:
            with self.subTest(field=field):
                value = asdict(metadata())
                del value[field]
                with self.assertRaises(route.MaintenanceBodyBlocked): route.metadata_from_mapping(value)

    def test_unknown_authority_pb_fields(self):
        for field in ("pb_number", "approved", "execution_authorized", "reviewer_identity"):
            with self.subTest(field=field):
                value = asdict(metadata())
                value[field] = True
                with self.assertRaises(route.MaintenanceBodyBlocked): route.metadata_from_mapping(value)

    def test_empty_fields_and_exact_types(self):
        for field in route.FIELDS:
            for value in ("", True):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(route.MaintenanceBodyBlocked):
                        route.generate_body(replace(metadata(), **{field: value}), CHANGES)

    def test_protected_and_mixed_paths(self):
        for path in ("policy/policy.json", "gateway/app.py", "security/tenant_context.py", "security/decision_store.py",
                     "audit/exporter.py", "runtime/replit_executor.py", ".replit", "requirements.txt",
                     "docs/non_pb_ci_maintenance_route.md", "../requirements-ci.txt", ".github/workflows/../policy.yml"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(route.MaintenanceBodyBlocked, "PB_OR_HUMAN_CLARIFICATION_REQUIRED"):
                    route.generate_body(metadata(), CHANGES + [("M", path)])

    def test_ambiguous_types_and_inventory(self):
        for status in ("D", "R100", "T", "?", True):
            with self.subTest(status=status):
                with self.assertRaises(route.MaintenanceBodyBlocked): route.generate_body(metadata(), [(status, "requirements-ci.txt")])
        for changes in ([], CHANGES * 2, [("M",)], [("M", True)], CHANGES * 51):
            with self.subTest(changes=str(changes)[:30]):
                with self.assertRaises(route.MaintenanceBodyBlocked): route.generate_body(metadata(), changes)
        self.assertEqual(len(route.validate_changeset([("A", f"requirements-synthetic-{i}.txt") for i in range(100)])), 100)

    def test_reference_consistency_and_text_boundaries(self):
        cases = [("candidate_sha", "bad"), ("validation_head_sha", "c" * 40), ("route", "pb"),
                 ("validation_reference", "https://github.com/other/repository/actions/runs/123"),
                 ("validation_reference", "https://github.com/synthetic/repository/actions/runs/123?x=1"),
                 ("risk", "x" * 16001), ("audit", "x\x00y"), ("purpose", "safe\n## Status\nAPPROVED")]
        for field, value in cases:
            with self.subTest(field=field):
                with self.assertRaises(route.MaintenanceBodyBlocked): route.generate_body(replace(metadata(), **{field: value}), CHANGES)
        route.generate_body(replace(metadata(), risk="x" * 16000), CHANGES)

    def test_every_missing_section(self):
        body = route.generate_body(metadata(), CHANGES)
        for section in SECTIONS:
            with self.subTest(section=section):
                actual = next(s for s in body.splitlines() if s.startswith("## ") and s[3:].upper() == section)
                with self.assertRaises(route.MaintenanceBodyBlocked):
                    route.validate_body(body.replace(actual, "## REMOVED", 1), metadata(), CHANGES)

    def test_false_approval_and_results(self):
        body = route.generate_body(metadata(), CHANGES)
        for old, new in (("USBAY-AUDIT", "another reviewer"), ("REVIEW_REQUIRED", "VERIFIED"),
                         ("AWAITING_APPROVAL", "APPROVED"), ("13 selected", "6363 passed")):
            with self.subTest(old=old):
                with self.assertRaises(route.MaintenanceBodyBlocked): route.validate_body(body.replace(old, new), metadata(), CHANGES)

    def test_duplicate_keys_after_escape_decoding(self):
        with self.assertRaises(route.MaintenanceBodyBlocked):
            json.loads('{"route":1,"rout\\u0065":2}', object_pairs_hook=route._closed_json)

    def test_git_inventory_complete_and_failures_block(self):
        for result in (SimpleNamespace(returncode=0, stdout="M\tpolicy/policy.json\nM\trequirements-ci.txt\n"),
                       SimpleNamespace(returncode=128, stdout="")):
            with patch.object(route.subprocess, "run", return_value=result) as call:
                with self.assertRaises(route.MaintenanceBodyBlocked): route.read_git_changeset(Path("."), metadata())
                self.assertEqual(call.call_args.args[0][-3:], ["a" * 40, "b" * 40, "--"])
                self.assertEqual(call.call_args.kwargs["timeout"], 10)

    def test_semantic_and_provenance_limits(self):
        body = route.generate_body(metadata(), [("M", ".github/workflows/policy.yml")])
        self.assertIn("path eligibility alone cannot prove unchanged semantics", body)
        self.assertIn("actual human scope/evidence review", body)
        self.assertIn("not authenticated evidence", body)

    def test_pb026_literal_historical_hash(self):
        self.assertEqual(hashlib.sha256(generate_pr_body(pb026_metadata()).encode()).hexdigest(),
                         "38afbf68b3da934e656caa9fb3e2bb1d27dfabbe74247a892d9919bf6ab092f7")

    def test_pb025_generation_and_validation(self):
        body = pb025_body(pb025_metadata())
        for section in ("PURPOSE", "RISK", "POLICY LINK", "REQUIRED APPROVALS", "AUDIT", "IMPACT"):
            self.assertIn("## " + section + "\n", body)
        self.assertIn("## Decision\nVERIFIED", body)

    def test_pb023_title_commit_rules_preserved(self):
        pb = PBMetadata(23, "synthetic-pb", "Synthetic PB", "REVIEW_REQUIRED", "AWAITING_APPROVAL")
        generated = generate_metadata(pb)
        self.assertEqual(generated.pr_title, "PB-023 REVIEW_REQUIRED: Synthetic PB")
        self.assertEqual(generated.commit_title, generated.pr_title)
        for field in ("pr_title", "commit_title", "branch_name"):
            with self.subTest(field=field):
                with self.assertRaises(MetadataAuthorityBlocked):
                    validate_generated_metadata(pb, replace(generated, **{field: "Non PB maintenance"}))

    def test_fallback_guard_remains_valid(self):
        text = Path(".github/pull_request_template.md").read_text()
        self.assertEqual(validate_repository_template(text)["template_mode"], "FAIL_CLOSED_FALLBACK_GUARD")


if __name__ == "__main__": unittest.main()
