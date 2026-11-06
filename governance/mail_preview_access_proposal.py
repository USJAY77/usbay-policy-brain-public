"""UNADOPTED contract sketch, not a validator, identity verifier or capability.

No Gateway imports this module. There is no route, transport, credential parser,
signature verifier, issuer enrollment, grant constructor, storage or callback.
All inputs (including typed records) are UNTRUSTED hypothesis data. Consistency,
hashes and caller claims never establish authenticity, freshness or permission.
Every result stays BLOCKED; this module cannot render or return mail content.

Open human governance decisions / conservative proposals (NOT adopted policy):
* Define offline display separately from preparation, approval and execution.
  Proposed action review_draft, purpose offline_preview_display, exact-version
  scope only; no mailbox-wide, wildcard, delegated or provider/send permission.
* Select an independent identity verifier, audience and subject/tenant mapping.
  Existing evidence:read and intake credentials are NOT mail permissions.
* Designate the authoritative draft store and its tenant/mailbox/draft/version
  mapping; client identifiers and PreviewContext cannot be authoritative.
* Define issuer enrollment, signed reviewauthority schema, revocation and
  validity/clock rules. Existing dry-run approvals do not silently gain purpose.
* Define coherent currentness generations, freshness and recovery source,
  rollback/uncertain-state handling. Missing/unavailable/stale means deny.
* Decide display replay/audit policy. Conservative proposal: one-time attempt
  per exact binding, durable atomic reservation and audit before disclosure,
  with a final authority/resource/config recheck. Uncertain commit means deny;
  read-only reconciliation must establish state, never reset or retry issuance.
  Retention, atomicity across stores and recovery protocol remain unresolved.

Proposed integration order, only AFTER adoption and implementation review:
independent credential verification -> server-side resource resolution ->
signature/trust/purpose/scope verification -> coherent fresh/recovery snapshot ->
exact existing preview continuity -> atomic replay/audit -> final TOCTOU check
-> render. Render is not send/approval authority. Do not wire this sketch as
the verifier. Existing audit/replay implementations are candidate mechanisms,
not proof of a transaction, applicable grant, or authorization in this sketch.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from governance.mail_draft_preview import (
    OfflineMailPreview, PreviewContext, preview_continuity_matches,
)
from governance.mail_draft_review import MailDraft

PROPOSED_AUDIENCE = "usbay:offline-mail-preview:proposal"
PROPOSED_ACTION = "review_draft"
PROPOSED_PURPOSE = "offline_preview_display"
PROPOSED_SCOPE = "EXACT_DRAFT_VERSION_ONLY"
SOURCE_KINDS = (
    "identity", "resource", "authority", "freshness", "recovery", "replay", "audit",
)


@dataclass(frozen=True, repr=False)
class ProposedBinding:
    """Comparison data only. draft_id/version must eventually be store-owned."""

    subject: str
    tenant: str
    mailbox_id: str
    source_message_id: str
    source_message_version: str
    draft_id: str
    draft_version: str
    request_binding: str
    continuity_digest: str
    audience: str = PROPOSED_AUDIENCE
    action: str = PROPOSED_ACTION
    purpose: str = PROPOSED_PURPOSE
    scope: str = PROPOSED_SCOPE


@dataclass(frozen=True, repr=False)
class HypotheticalSourceRecord:
    """UNVERIFIED test data, never a trusted verifier output or signed grant.

    binding is a proposed snapshot join, not a claim that an identity token
    itself signs mail contents. evidence_ref/issuer_ref do not establish trust.
    generation is a proposed coherent snapshot ID, not a trusted high-water.
    """

    kind: str
    binding: ProposedBinding
    issuer_ref: str
    evidence_ref: str
    generation: str
    observed_at: int
    expires_at: int
    revoked: bool = False
    state: str = "CURRENT"


@dataclass(frozen=True)
class ProposalAnalysis:
    """Diagnostic codes only; publicly constructible, never an ALLOW token."""

    blockers: tuple[str, ...]
    status: str = field(default="BLOCKED_UNADOPTED_PROPOSAL", init=False)
    access_authorized: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    evidence_verified: bool = field(default=False, init=False)


def propose_binding(
    preview: OfflineMailPreview, *, draft: MailDraft, context: PreviewContext,
    draft_id: str, draft_version: str,
) -> ProposedBinding:
    """Reuse exact byte/context continuity, NOT subject or resource authority."""
    if (type(draft_id) is not str or not draft_id.strip()
            or type(draft_version) is not str or not draft_version.strip()):
        raise ValueError("PROPOSED_RESOURCE_ID_REQUIRED")
    if not preview_continuity_matches(preview, draft, context):
        raise ValueError("PROPOSED_PREVIEW_CONTINUITY_MISMATCH")
    return ProposedBinding(
        context.actor, context.tenant, draft.mailbox_id,
        draft.source_message_id, draft.source_message_version,
        draft_id, draft_version, preview.review_request.binding,
        preview.continuity_digest,
    )


def analyze_hypothetical_sources(
    expected: ProposedBinding, records: tuple[HypotheticalSourceRecord, ...], *,
    now: int, max_age_seconds: int,
) -> ProposalAnalysis:
    """Pure structural negative-case analysis. Even perfect forgery stays denied.

    Freshness budget is explicit hypothetical test input, NOT a policy default.
    No adapters, bool callbacks, ALLOW dictionaries or hashes are accepted as
    authority. No signature/currentness/replay/audit verification is performed.
    """
    blockers = ["CONTRACT_NOT_ADOPTED", "INDEPENDENT_VERIFIERS_NOT_CONNECTED"]
    if (type(expected) is not ProposedBinding
            or any(type(v) is not str or not v.strip()
                   for v in vars(expected).values())
            or (expected.audience, expected.action, expected.purpose, expected.scope)
            != (PROPOSED_AUDIENCE, PROPOSED_ACTION, PROPOSED_PURPOSE, PROPOSED_SCOPE)):
        return ProposalAnalysis(tuple(blockers + ["INVALID_PROPOSED_BINDING"]))
    if (type(now) is not int or now < 0 or type(max_age_seconds) is not int
            or max_age_seconds < 0 or type(records) is not tuple):
        return ProposalAnalysis(tuple(blockers + ["INVALID_PROPOSED_INPUT"]))
    indexed = {}
    for record in records:
        if type(record) is not HypotheticalSourceRecord or record.kind not in SOURCE_KINDS:
            blockers.append("INVALID_SOURCE_RECORD")
            continue
        if record.kind in indexed:
            blockers.append("DUPLICATE_SOURCE_RECORD")
        indexed[record.kind] = record
    generations = set()
    for kind in SOURCE_KINDS:
        record = indexed.get(kind)
        if record is None:
            blockers.append(kind.upper() + "_SOURCE_MISSING")
            continue
        if type(record.binding) is not ProposedBinding or record.binding != expected:
            blockers.append(kind.upper() + "_BINDING_MISMATCH")
        if any(type(v) is not str or not v.strip()
               for v in (record.issuer_ref, record.evidence_ref, record.generation)):
            blockers.append(kind.upper() + "_PROVENANCE_MISSING")
        else:
            generations.add(record.generation)
        if record.revoked is not False or record.state != "CURRENT":
            blockers.append(kind.upper() + "_NOT_CURRENT")
        if (type(record.observed_at) is not int or type(record.expires_at) is not int
                or not 0 <= record.observed_at <= now < record.expires_at
                or now - record.observed_at > max_age_seconds):
            blockers.append(kind.upper() + "_STALE_OR_EXPIRED")
    if len(generations) > 1:
        blockers.append("INCOHERENT_SNAPSHOT")
    return ProposalAnalysis(tuple(dict.fromkeys(blockers)))
