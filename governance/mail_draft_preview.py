"""In-memory offline preview, not an authenticated or executable capability.

No I/O, transport, approval, clock, replay store or issuance is implemented here.
Continuity means equality to caller-supplied inputs, not authenticity or authority.
Local render limits do not define operational mail policy.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage
import hashlib
import html
import json
import unicodedata

from governance.mail_draft_review import MailAttachment, MailDraft, _address, bind_mail_draft
from governance.product_dry_run import DryRunRequest

MAX_BODY_BYTES = 64 * 1024
MAX_ATTACHMENT_BYTES = 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 4 * 1024 * 1024
MAX_ATTACHMENTS = 12
MAX_RECIPIENTS = 100
MAX_LABEL_CHARS = 512
MAX_FILENAME_CHARS = 160
SCHEMA = "usbay.offline_mail_preview.v1"
_MIME_POLICY = policy.SMTP.clone(max_line_length=78, refold_source="all")


class MailPreviewError(ValueError):
    """Fixed, content-free local rejection code."""


@dataclass(frozen=True, repr=False)
class PreviewContext:
    action_id: str
    actor: str
    agent: str
    tenant: str
    policy_version: str


@dataclass(frozen=True, repr=False)
class PrivateEnvelope:
    """Private caller memory only; never part of the rendered document or MIME."""

    sender: str
    to: tuple[str, ...]
    cc: tuple[str, ...]
    bcc: tuple[str, ...]


@dataclass(frozen=True, repr=False)
class AttachmentLabel:
    filename: str
    size: int


@dataclass(frozen=True, repr=False)
class MailPreviewView:
    sender: str
    to: tuple[str, ...]
    cc: tuple[str, ...]
    subject: str
    body_text: str
    attachments: tuple[AttachmentLabel, ...]


@dataclass(frozen=True, repr=False)
class OfflineMailPreview:
    """Publicly constructible data. Never accept this object as an ALLOW token."""

    view: MailPreviewView
    mime_bytes: bytes
    private_envelope: PrivateEnvelope
    review_request: DryRunRequest
    continuity_digest: str
    schema: str = field(default=SCHEMA, init=False)
    send_available: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)


def _display_text(value: str, *, limit: int, multiline: bool = False) -> None:
    if type(value) is not str or len(value) > limit:
        raise MailPreviewError("PREVIEW_TEXT_LIMIT")
    for char in value:
        if multiline and char in "\r\n\t":
            continue
        if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            raise MailPreviewError("PREVIEW_DISPLAY_CONTROL")


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")).hexdigest()


def _checked_inputs(draft: MailDraft, context: PreviewContext) -> str:
    if type(draft) is not MailDraft or type(context) is not PreviewContext:
        raise MailPreviewError("PREVIEW_INPUT_TYPE")
    for value in (
        context.action_id, context.actor, context.agent, context.tenant, context.policy_version,
    ):
        _display_text(value, limit=MAX_LABEL_CHARS)
    for value in (
        draft.mailbox_id, draft.source_message_id, draft.source_message_version,
        draft.from_identity, draft.subject, draft.action_type,
    ):
        _display_text(value, limit=MAX_LABEL_CHARS)
    for group in (draft.to, draft.cc, draft.bcc):
        if type(group) is not tuple or len(group) > MAX_RECIPIENTS:
            raise MailPreviewError("PREVIEW_RECIPIENT_LIMIT")
        for address in group:
            _display_text(address, limit=254)
    if sum(map(len, (draft.to, draft.cc, draft.bcc))) > MAX_RECIPIENTS:
        raise MailPreviewError("PREVIEW_RECIPIENT_LIMIT")
    if type(draft.body) is not bytes or len(draft.body) > MAX_BODY_BYTES:
        raise MailPreviewError("PREVIEW_BODY_LIMIT")
    # Invalid UTF-8 is represented visibly by U+FFFD, never used to rebuild MIME.
    body_text = draft.body.decode("utf-8", errors="replace")
    _display_text(body_text, limit=MAX_BODY_BYTES, multiline=True)
    if type(draft.attachments) is not tuple or len(draft.attachments) > MAX_ATTACHMENTS:
        raise MailPreviewError("PREVIEW_ATTACHMENT_LIMIT")
    total = 0
    for attachment in draft.attachments:
        if type(attachment) is not MailAttachment or type(attachment.content) is not bytes:
            raise MailPreviewError("PREVIEW_ATTACHMENT_TYPE")
        _display_text(attachment.filename, limit=MAX_FILENAME_CHARS)
        total += len(attachment.content)
        if len(attachment.content) > MAX_ATTACHMENT_BYTES or total > MAX_TOTAL_ATTACHMENT_BYTES:
            raise MailPreviewError("PREVIEW_ATTACHMENT_LIMIT")
    return body_text


def build_offline_preview(draft: MailDraft, context: PreviewContext) -> OfflineMailPreview:
    """Create deterministic MIME and a text-only view without external effects.

    The existing binding retains its normalization contract. An additional exact
    snapshot binds even normalization-equivalent changes to this particular view.
    Neither digest is proof of authentic input, approval, freshness or replay safety.
    """
    body_text = _checked_inputs(draft, context)
    try:
        request = bind_mail_draft(draft, **asdict(context))
    except ValueError:
        raise MailPreviewError("PREVIEW_DRAFT_BINDING_INVALID") from None
    snapshot = {
        "schema": SCHEMA, "context": asdict(context),
        "draft": {
            "mailbox_id": draft.mailbox_id,
            "source_message_id": draft.source_message_id,
            "source_message_version": draft.source_message_version,
            "from_identity": draft.from_identity, "to": draft.to,
            "cc": draft.cc, "bcc": draft.bcc, "subject": draft.subject,
            "body_sha256": hashlib.sha256(draft.body).hexdigest(),
            "attachments": [
                {"filename": item.filename, "sha256": hashlib.sha256(item.content).hexdigest()}
                for item in draft.attachments
            ],
            "action_type": draft.action_type,
        },
        "review_binding": request.binding,
    }
    exact_digest = _digest(snapshot)
    envelope = PrivateEnvelope(
        _address(draft.from_identity),
        tuple(sorted(_address(v) for v in draft.to)),
        tuple(sorted(_address(v) for v in draft.cc)),
        tuple(sorted(_address(v) for v in draft.bcc)),
    )
    message = EmailMessage(policy=_MIME_POLICY)
    message["From"] = draft.from_identity
    message["To"] = ", ".join(draft.to)
    if draft.cc:
        message["Cc"] = ", ".join(draft.cc)
    message["Subject"] = draft.subject
    # Base64 preserves original bytes, including line endings and a missing final
    # newline. Do not round-trip through set_content(str) or invent Date/Message-ID.
    message.set_content(draft.body, maintype="text", subtype="plain", cte="base64")
    for attachment in draft.attachments:
        message.add_attachment(
            attachment.content, maintype="application", subtype="octet-stream",
            cte="base64", filename=attachment.filename,
        )
    if message.is_multipart():
        # "_" cannot occur in base64 content. No random MIME boundary generation.
        message.set_boundary("usbay_offline_" + exact_digest)
    mime_bytes = message.as_bytes()
    view = MailPreviewView(
        draft.from_identity, draft.to, draft.cc, draft.subject, body_text,
        tuple(AttachmentLabel(item.filename, len(item.content)) for item in draft.attachments),
    )
    continuity = _digest({
        "exact_snapshot": exact_digest, "mime_sha256": hashlib.sha256(mime_bytes).hexdigest(),
        "envelope": asdict(envelope),
    })
    return OfflineMailPreview(view, mime_bytes, envelope, request, continuity)


def preview_continuity_matches(
    preview: OfflineMailPreview, draft: MailDraft, context: PreviewContext,
) -> bool:
    """Equality to current caller inputs only; a caller can construct a new object."""
    if type(preview) is not OfflineMailPreview:
        return False
    try:
        return preview == build_offline_preview(draft, context)
    except (ValueError, TypeError, UnicodeError):
        return False


def render_offline_preview(
    preview: OfflineMailPreview, *, draft: MailDraft, context: PreviewContext,
) -> str:
    """Return inert HTML, never attachment bytes, BCC addresses or active URLs."""
    if not preview_continuity_matches(preview, draft, context):
        raise MailPreviewError("PREVIEW_CONTINUITY_MISMATCH")
    view = preview.view
    escape = html.escape
    labels = "".join(
        f"<li>{escape(item.filename)} ({item.size} bytes)</li>" for item in view.attachments
    ) or "<li>Geen bijlagen</li>"
    return (
        '<!doctype html><html lang="nl"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; base-uri \'none\'; form-action \'none\'; sandbox">'
        '<meta name="referrer" content="no-referrer">'
        '<title>Offline Governed Mail-concept</title></head><body><main>'
        '<h1>Offline Governed Mail-concept</h1>'
        '<p>Alleen lezen. Geen bewijs van authenticiteit, goedkeuring, freshness, '
        'replayveiligheid of verzendbevoegdheid.</p>'
        '<p>BCC-adressen zijn verborgen en staan alleen in de privé-envelope.</p>'
        f'<dl><dt>Van</dt><dd>{escape(view.sender)}</dd>'
        f'<dt>To</dt><dd>{escape(", ".join(view.to))}</dd>'
        f'<dt>CC</dt><dd>{escape(", ".join(view.cc))}</dd>'
        f'<dt>Onderwerp</dt><dd>{escape(view.subject)}</dd></dl>'
        '<h2>Body</h2><p>UTF-8-tekstweergave; ongeldige bytes worden zichtbaar '
        'vervangen. De oorspronkelijke bytes blijven in de MIME behouden.</p>'
        f'<pre>{escape(view.body_text)}</pre><h2>Bijlagen — niet te openen</h2>'
        f'<ul>{labels}</ul>'
        '<button type="button" disabled>Verzenden niet beschikbaar</button>'
        '</main></body></html>'
    )
