from __future__ import annotations

import pytest

from governance.audit_normalization import (
    REASON_AUDIT_CONTROL_MISSING,
    audit_canonicalization_report,
    audit_normalization_report,
)
from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.evidence_normalization import evidence_canonicalization_report, evidence_normalization_report
from governance.lineage_normalization import lineage_canonicalization_report, lineage_normalization_report


pytestmark = pytest.mark.governance


def test_normalization_exposes_audit_evidence_and_lineage_statuses():
    audit = audit_normalization_report()
    audit_canonical = audit_canonicalization_report()
    evidence = evidence_normalization_report()
    evidence_canonical = evidence_canonicalization_report()
    lineage = lineage_normalization_report()
    lineage_canonical = lineage_canonicalization_report()

    assert audit["audit_status"] == "VALID"
    assert audit_canonical["audit_canonicalization_status"] == "VALID"
    assert evidence["evidence_status"] == "VALID"
    assert evidence_canonical["evidence_canonicalization_status"] == "VALID"
    assert lineage["lineage_status"] == "VALID"
    assert lineage_canonical["lineage_canonicalization_status"] == "VALID"
    assert len(audit["capabilities"]) == len(CAPABILITY_MANIFEST)
    assert len(evidence["capabilities"]) == len(CAPABILITY_MANIFEST)
    assert len(lineage["capabilities"]) == len(CAPABILITY_MANIFEST)
    for row in audit["capabilities"]:
        assert row["audit_status"] == "VALID"
        assert row["audit_required"] is True


def test_audit_normalization_fails_closed_when_control_is_missing():
    capability = dict(CAPABILITY_MANIFEST[0])
    capability["controls"] = tuple(control for control in capability["controls"] if control != "audit_linkage")
    manifest = (capability,) + CAPABILITY_MANIFEST[1:]

    report = audit_normalization_report(manifest=manifest)

    assert report["audit_status"] == "BLOCKED"
    assert REASON_AUDIT_CONTROL_MISSING in report["reason_codes"]
