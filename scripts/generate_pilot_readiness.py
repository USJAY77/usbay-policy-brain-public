#!/usr/bin/env python3
"""USBAY Pilot Readiness Center generator.

Produces two evidence-based deliverables that prove whether USBAY is ready
for real pilot onboarding:

  * pilot_readiness_manifest.json
  * pilot_readiness_report.pdf

Status is computed FROM EVIDENCE ONLY. Each of the ten readiness sections
references concrete artifacts in this repository. The generator verifies that
every referenced artifact exists; if any referenced evidence is missing the
section FAILS CLOSED (it cannot be reported READY). Overall posture is the
fail-closed roll-up of the section statuses.

This script does NOT touch the governed runtime components (Policy Brain,
Enforcement Gateway, Audit Chain, Root of Trust, Governance Mesh, Federated
Governance). It only reads file presence and writes the two deliverables.
"""

import datetime
import hashlib
import json
import os

from fpdf import FPDF
from fpdf.enums import XPos, YPos

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

READY = "READY"
PARTIALLY_READY = "PARTIALLY_READY"
NOT_READY = "NOT_READY"

PRODUCT = "USBAY"

INVARIANTS = [
    ("USBAY", "ENFORCEMENT_AUTHORITY"),
    ("Euria", "ANALYSIS_ONLY"),
    ("Human approval", "MANDATORY"),
    ("Fail closed", "DEFAULT"),
]

# Each section maps to concrete evidence artifacts in the repo. The generator
# fails closed on any missing artifact, so this list is the single source of
# truth for what "ready" means.
SECTIONS = [
    {
        "id": 1,
        "name": "Governance Controls",
        "intent": "Policy controls, ruleset baseline, and release manifest are defined and version-pinned.",
        "evidence": [
            ("Production readiness lanes", "governance/production_readiness_lanes.json"),
            ("Policy pack", "governance/policy_pack.py"),
            ("Policy release manifest", "governance/policy_release_manifest.json"),
            ("Repository rulesets", "repo_rulesets.json"),
        ],
    },
    {
        "id": 2,
        "name": "Trust Infrastructure",
        "intent": "Hardware trust root, timestamp anchoring, and key custody are provisioned.",
        "evidence": [
            ("Hardware trust root authority", "governance/hardware_trust_root_authority.py"),
            ("Timestamp anchor (RFC3161)", "audit/anchor.py"),
            ("Vault key custody config", "vault/config/vault.hcl"),
        ],
    },
    {
        "id": 3,
        "name": "Licensing Status",
        "intent": "Governance Runtime License terms are bound to the active policy release.",
        "evidence": [
            ("Policy release manifest (license binding)", "governance/policy_release_manifest.json"),
            ("Licensing lifecycle evidence", "evidence/lifecycle_journey_full.png"),
        ],
    },
    {
        "id": 4,
        "name": "Independent Assurance",
        "intent": "Audit verification, external verifier federation, and auditor bundle are available.",
        "evidence": [
            ("Audit verifier", "audit/verify.py"),
            ("Audit chain verification script", "scripts/verify_audit_chain.py"),
            ("Auditor verification bundle", "governance/auditor_verification_bundle.py"),
            ("External verifier federation", "governance/external_verifier_federation.py"),
        ],
    },
    {
        "id": 5,
        "name": "Customer Journey Readiness",
        "intent": "End-to-end governance journey and evidence-package deliverables are demonstrable.",
        "evidence": [
            ("Lifecycle journey artifact", "evidence/lifecycle_journey_full.png"),
            ("Evidence package journey artifact", "evidence/evidencepkg_journey_full.png"),
        ],
    },
    {
        "id": 6,
        "name": "Reference Architecture Readiness",
        "intent": "Enterprise reference architecture is documented for prospect review.",
        "evidence": [
            ("Enterprise architecture", "docs/pilot/USBAY_ENTERPRISE_ARCHITECTURE.md"),
        ],
    },
    {
        "id": 7,
        "name": "Certification Readiness",
        "intent": "Release-readiness audit and a signed CI evidence manifest are present.",
        "evidence": [
            ("Governance release readiness audit", "docs/usbay-governance-release-readiness-audit.md"),
            ("CI evidence manifest", "evidence/governance-evidence-manifest.json"),
        ],
    },
    {
        "id": 8,
        "name": "Deployment Readiness",
        "intent": "Production verification, deployment package, and signed release manifest are in place.",
        "evidence": [
            ("Production readiness verifier", "scripts/verify_production_readiness.py"),
            ("Production deployment package", "deployment/production"),
            ("Signed governance release manifest", "governance_release.json"),
        ],
    },
    {
        "id": 9,
        "name": "Operational Readiness",
        "intent": "Live-pilot verification, operating checklist, and tamper-evident ledger are operational.",
        "evidence": [
            ("Live pilot verifier", "scripts/verify_live_pilot_v1.py"),
            ("Production readiness checklist", "docs/usbay-production-readiness-checklist.md"),
            ("Audit hash chain", "audit/hash_chain.py"),
            ("Audit ledger", "audit/ledger.py"),
        ],
    },
    {
        "id": 10,
        "name": "Remaining Open Risks",
        "intent": "Incident register, runbooks, and governance provenance close the residual-risk loop.",
        "evidence": [
            ("Incident register", "governance/incidents.py"),
            ("Incident runbooks", "governance/incident_runbooks.json"),
            ("Governance provenance", "evidence/governance-provenance.json"),
        ],
    },
]


def _digest(path):
    """Return a short sha256 prefix for a present file/dir, else None."""
    try:
        if os.path.isdir(path):
            return "dir"
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return None


def evaluate_section(section):
    items = []
    present = 0
    for label, rel in section["evidence"]:
        abspath = os.path.join(ROOT, rel)
        exists = os.path.exists(abspath)
        if exists:
            present += 1
        items.append({
            "label": label,
            "path": rel,
            "present": exists,
            "sha256_prefix": _digest(abspath) if exists else None,
        })
    total = len(items)
    missing = total - present
    if missing == 0:
        status = READY
    elif present == 0:
        status = NOT_READY
    else:
        status = PARTIALLY_READY
    return {
        "id": section["id"],
        "name": section["name"],
        "intent": section["intent"],
        "status": status,
        "evidence_total": total,
        "evidence_present": present,
        "evidence_missing": missing,
        "evidence": items,
    }


def roll_up(sections):
    statuses = [s["status"] for s in sections]
    if any(s == NOT_READY for s in statuses):
        return NOT_READY
    if any(s == PARTIALLY_READY for s in statuses):
        return PARTIALLY_READY
    return READY


def build_manifest():
    sections = [evaluate_section(s) for s in SECTIONS]
    overall = roll_up(sections)
    total_ev = sum(s["evidence_total"] for s in sections)
    present_ev = sum(s["evidence_present"] for s in sections)
    return {
        "schema": "usbay.pilot_readiness/v1",
        "product": PRODUCT,
        "title": "USBAY Pilot Readiness Manifest",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall_status": overall,
        "fail_closed": True,
        "fail_closed_rule": "A section that references any missing evidence cannot be reported READY; overall posture is the fail-closed roll-up of section statuses.",
        "invariants": {k: v for k, v in INVARIANTS},
        "summary": {
            "sections_total": len(sections),
            "sections_ready": sum(1 for s in sections if s["status"] == READY),
            "sections_partially_ready": sum(1 for s in sections if s["status"] == PARTIALLY_READY),
            "sections_not_ready": sum(1 for s in sections if s["status"] == NOT_READY),
            "evidence_total": total_ev,
            "evidence_present": present_ev,
            "evidence_missing": total_ev - present_ev,
        },
        "sections": sections,
        "note": "Status is computed from evidence presence in the workspace only. Not stored, transmitted, or persisted beyond these generated deliverables.",
    }


STATUS_RGB = {
    READY: (34, 139, 94),
    PARTIALLY_READY: (181, 119, 14),
    NOT_READY: (185, 28, 28),
}
INK = (15, 23, 32)
MUTE = (90, 105, 120)
RULE = (210, 218, 226)


def _ascii(text):
    return (text.replace("\u2014", "-").replace("\u2013", "-")
            .replace("\u2192", "->").replace("\u2022", "-")
            .encode("latin-1", "replace").decode("latin-1"))


class ReadinessPDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*MUTE)
        self.cell(0, 6, _ascii("USBAY Pilot Readiness Report"), align="L")
        self.cell(0, 6, _ascii("USBAY ENFORCEMENT_AUTHORITY"), align="R")
        self.ln(8)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MUTE)
        self.cell(0, 6, _ascii(
            "Status computed from evidence only - fail closed on any missing evidence   |   Page %d" % self.page_no()),
            align="C")


def status_chip(pdf, status, x, y, w=44, h=9):
    r, g, b = STATUS_RGB[status]
    pdf.set_fill_color(r, g, b)
    pdf.set_draw_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(x, y)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(w, h, _ascii(status), border=0, align="C", fill=True)


def build_pdf(manifest, out_path):
    pdf = ReadinessPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(16, 16, 16)
    pdf.add_page()

    # Cover
    pdf.set_text_color(*MUTE)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 6, _ascii("PILOT ONBOARDING - EXECUTIVE READINESS"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(*INK)
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 12, _ascii("USBAY Pilot Readiness Report"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*MUTE)
    pdf.cell(0, 6, _ascii("Generated %s   |   %s" % (manifest["generated_at"], manifest["schema"])), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # Overall posture banner
    r, g, b = STATUS_RGB[manifest["overall_status"]]
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 14, _ascii("OVERALL READINESS:  %s" % manifest["overall_status"]), border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C", fill=True)
    pdf.ln(3)

    s = manifest["summary"]
    pdf.set_text_color(*INK)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5.5, _ascii(
        "Sections: %d ready, %d partially ready, %d not ready (of %d).  "
        "Evidence: %d of %d artifacts present.  %s"
        % (s["sections_ready"], s["sections_partially_ready"], s["sections_not_ready"],
           s["sections_total"], s["evidence_present"], s["evidence_total"],
           manifest["fail_closed_rule"])))
    pdf.ln(2)

    # Invariants line
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*MUTE)
    inv = "   -   ".join("%s %s" % (k, v) for k, v in manifest["invariants"].items())
    pdf.multi_cell(0, 5, _ascii("Invariants:  " + inv))
    pdf.ln(2)
    pdf.set_draw_color(*RULE)
    pdf.line(16, pdf.get_y(), 194, pdf.get_y())
    pdf.ln(4)

    # Sections
    for sec in manifest["sections"]:
        if pdf.get_y() > 250:
            pdf.add_page()
        pdf.set_text_color(*INK)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(140, 9, _ascii("%d. %s" % (sec["id"], sec["name"])), new_x=XPos.LMARGIN, new_y=YPos.TOP)
        status_chip(pdf, sec["status"], 150, pdf.get_y(), w=44, h=8)
        pdf.ln(10)
        pdf.set_x(16)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*MUTE)
        pdf.multi_cell(0, 5, _ascii(sec["intent"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)
        for item in sec["evidence"]:
            pdf.set_x(16)
            mark = "[OK]" if item["present"] else "[MISSING]"
            if item["present"]:
                pdf.set_text_color(34, 139, 94)
            else:
                pdf.set_text_color(185, 28, 28)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(22, 5, _ascii(mark), new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_text_color(*INK)
            pdf.set_font("Helvetica", "", 8.5)
            extra = ("  sha256:" + item["sha256_prefix"]) if item.get("sha256_prefix") and item["sha256_prefix"] != "dir" else ""
            pdf.multi_cell(0, 5, _ascii("%s  -  %s%s" % (item["label"], item["path"], extra)),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    pdf.output(out_path)


def main():
    manifest = build_manifest()
    json_path = os.path.join(ROOT, "pilot_readiness_manifest.json")
    pdf_path = os.path.join(ROOT, "pilot_readiness_report.pdf")
    with open(json_path, "w") as fh:
        json.dump(manifest, fh, indent=2)
    build_pdf(manifest, pdf_path)
    print("OVERALL:", manifest["overall_status"])
    for sec in manifest["sections"]:
        print("  %2d %-32s %-16s %d/%d" % (
            sec["id"], sec["name"], sec["status"],
            sec["evidence_present"], sec["evidence_total"]))
    print("wrote", json_path)
    print("wrote", pdf_path, os.path.getsize(pdf_path), "bytes")


if __name__ == "__main__":
    main()
