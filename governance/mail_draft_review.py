"""PB-366: exact-action binding for offline mail draft review only.

No mailbox/provider adapter, draft storage, model call or send function exists.
Digest equality is content continuity, never permission or anonymization.
Raw content remains in the caller's memory; audit receives only B1 hashes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from governance.connector_framework import sha256_payload
from governance.product_dry_run import DryRunRequest


SERIALIZATION_VERSION = "usbay.mail_draft_review.v1"
_LOCAL = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_ADDRESS = re.compile(_LOCAL + r"@" + _LABEL + r"(?:\." + _LABEL + r")+")


def _address(value: str) -> str:
    # Narrow envelope-address subset only: no display names, quoted local
    # parts, EAI/IDN conversion, provider aliases or header parsing.
    if not isinstance(value, str) or any(c in value for c in "\r\n\x00"):
        raise ValueError("MAIL_ADDRESS_INVALID")
    normalized = value.strip().lower()  # supplied advisory contract v1
    if len(normalized) > 254 or not _ADDRESS.fullmatch(normalized):
        raise ValueError("MAIL_ADDRESS_INVALID")
    if len(normalized.split("@", 1)[0]) > 64:
        raise ValueError("MAIL_ADDRESS_INVALID")
    return normalized


def _text(value: str, code: str) -> str:
    if not isinstance(value, str) or not value or any(c in value for c in "\r\n\x00"):
        raise ValueError(code)
    return value


@dataclass(frozen=True, repr=False)
class MailAttachment:
    filename: str
    content: bytes


@dataclass(frozen=True, repr=False)
class MailDraft:
    mailbox_id: str
    source_message_id: str
    source_message_version: str
    from_identity: str
    to: tuple[str, ...]
    cc: tuple[str, ...]
    bcc: tuple[str, ...]
    subject: str
    body: bytes
    attachments: tuple[MailAttachment, ...] = ()
    action_type: str = "review_draft"


def bind_mail_draft(
    draft: MailDraft, *, action_id: str, actor: str, agent: str,
    tenant: str, policy_version: str,
) -> DryRunRequest:
    """Return a request for B1 preparation; this function does not approve it.

    All request fields are explicit; no approval expiry/retention default is
    invented. Names, subject, body bytes, recipient roles and ordering of MIME
    attachments are bound. No raw mail data is returned in the request.
    """
    if not isinstance(draft, MailDraft) or draft.action_type != "review_draft":
        raise ValueError("MAIL_REVIEW_ONLY")
    for field in (action_id, actor, agent, tenant, policy_version):
        _text(field, "MAIL_CONTEXT_REQUIRED")
    mailbox = _text(draft.mailbox_id, "MAILBOX_REQUIRED")
    source = _text(draft.source_message_id, "SOURCE_MESSAGE_REQUIRED")
    version = _text(draft.source_message_version, "SOURCE_VERSION_REQUIRED")
    sender = _address(draft.from_identity)
    recipient_groups = []
    seen = set()
    for group in (draft.to, draft.cc, draft.bcc):
        if type(group) is not tuple:
            raise ValueError("MAIL_RECIPIENT_TUPLE_REQUIRED")
        normalized = tuple(sorted(_address(value) for value in group))
        if len(set(normalized)) != len(normalized) or seen.intersection(normalized):
            raise ValueError("MAIL_DUPLICATE_RECIPIENT")
        seen.update(normalized)
        recipient_groups.append(normalized)
    if not recipient_groups[0]:
        raise ValueError("MAIL_TO_REQUIRED")
    if not isinstance(draft.subject, str) or any(c in draft.subject for c in "\r\n\x00"):
        raise ValueError("MAIL_SUBJECT_INVALID")
    if type(draft.body) is not bytes or type(draft.attachments) is not tuple:
        raise ValueError("MAIL_IMMUTABLE_BYTES_REQUIRED")
    attachments = []
    for attachment in draft.attachments:
        if not isinstance(attachment, MailAttachment) or type(attachment.content) is not bytes:
            raise ValueError("MAIL_ATTACHMENT_INVALID")
        filename = _text(attachment.filename, "MAIL_ATTACHMENT_NAME_INVALID")
        attachments.append({"filename": filename,
                            "bytes_sha256": hashlib.sha256(attachment.content).hexdigest()})
    target = {"serialization": SERIALIZATION_VERSION, "action_type": "review_draft",
              "mailbox_id": mailbox, "source_message_id": source,
              "source_message_version": version, "from_identity": sender,
              "to": recipient_groups[0], "cc": recipient_groups[1], "bcc": recipient_groups[2]}
    content = {"serialization": SERIALIZATION_VERSION,
               "target_hash": sha256_payload(target), "subject": draft.subject,
               "body_bytes_sha256": hashlib.sha256(draft.body).hexdigest(),
               "attachments": attachments}
    return DryRunRequest(
        action_id=action_id, actor=actor, agent=agent, tenant=tenant,
        capability="governance_review", policy_version=policy_version,
        target_hash=content["target_hash"], payload_hash=sha256_payload(content), dry_run=True,
    )
