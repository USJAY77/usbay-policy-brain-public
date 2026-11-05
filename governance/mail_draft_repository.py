"""Bounded in-memory fixture repository, NOT an authoritative mail store.

Labels are untrusted, exact comparison data; no authenticated identity, owner
entitlement, access token or ALLOW is produced. No I/O, provider, route, clock,
grant, reset, delete, restore or ownership-transfer API exists.

Versions are canonical decimal labels, starting at "1", strictly increasing per
draft in this instance only. They are separate from source_message_version.
There is no durable high-water, recovery, anti-rollback or replay guarantee.
RLock serializes local resolve/CAS/render, not other processes or later disclosure.
Only render_current keeps final snapshot validation and completed HTML rendering
in one operation; a separate require_current cannot protect subsequent caller
work. No readlease or authority is produced. Preview continuity is still required.

Frozen snapshots resist ordinary mutation; a private independent tuple of exact
builtin values detects altered returned snapshots on subsequent repository use.
Object identity rejects copies and foreign instances. This is not a security
boundary against arbitrary Python code running inside the same process.
Limits below are local synthetic-fixture bounds, not adopted mail policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from threading import RLock

from governance.mail_draft_preview import (
    MAX_ATTACHMENTS, MAX_RECIPIENTS, MailPreviewError, PreviewContext, build_offline_preview,
    render_offline_preview,
)
from governance.mail_draft_review import MailAttachment, MailDraft

MAX_DRAFTS = 32
MAX_MESSAGE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_VERSION = 999_999_999
MAX_RENDERED_HTML_BYTES = 1024 * 1024
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_VERSION = re.compile(r"[1-9][0-9]{0,8}\Z")
_VALIDATION_CONTEXT = PreviewContext(
    "fixture-validation", "fixture-owner", "fixture-agent",
    "fixture-tenant", "fixture-policy",
)


class DraftRepositoryError(ValueError):
    """Fixed code only; never includes labels, content or lookup existence."""


@dataclass(frozen=True, repr=False)
class DraftSnapshot:
    """Comparison data, never authority. Only current store-issued objects work."""

    tenant: str
    owner: str
    mailbox_id: str
    draft_id: str
    version: str
    draft: MailDraft


@dataclass(frozen=True, repr=False)
class DraftRenderBinding:
    """Untrusted continuity metadata, publicly constructible, never a grant."""

    tenant: str
    owner: str
    mailbox_id: str
    draft_id: str
    version: str
    preview_continuity_digest: str


@dataclass(frozen=True, repr=False)
class RenderedDraft:
    """Inert HTML and local comparison data; no envelope or execution capability."""

    binding: DraftRenderBinding
    html: str


@dataclass(frozen=True, repr=False)
class _Entry:
    owner: str
    version: int
    data: tuple
    size: int
    snapshot: DraftSnapshot


def _label(value: str) -> str:
    if type(value) is not str or not _LABEL.fullmatch(value):
        raise DraftRepositoryError("DRAFT_REPOSITORY_LABEL_INVALID")
    return value


def _version(value: str) -> str:
    if type(value) is not str or not _VERSION.fullmatch(value):
        raise DraftRepositoryError("DRAFT_REPOSITORY_VERSION_INVALID")
    return value


def _freeze(draft: MailDraft, max_bytes: int) -> tuple[tuple, int]:
    # Strict nested builtin types avoid retaining mutable aliases or invoking
    # caller-controlled equality while comparing against the stored tuple.
    if type(draft) is not MailDraft:
        raise DraftRepositoryError("DRAFT_REPOSITORY_DRAFT_INVALID")
    text = (
        draft.mailbox_id, draft.source_message_id, draft.source_message_version,
        draft.from_identity, draft.subject, draft.action_type,
    )
    groups = (draft.to, draft.cc, draft.bcc)
    if (any(type(v) is not str for v in text) or type(draft.body) is not bytes
            or any(type(g) is not tuple or len(g) > MAX_RECIPIENTS for g in groups)
            or any(type(v) is not str for g in groups for v in g)
            or type(draft.attachments) is not tuple or len(draft.attachments) > MAX_ATTACHMENTS
            or any(type(a) is not MailAttachment or type(a.filename) is not str
                   or type(a.content) is not bytes for a in draft.attachments)):
        raise DraftRepositoryError("DRAFT_REPOSITORY_DRAFT_INVALID")
    try:
        # Public preview builder also invokes existing bind_mail_draft, preserving
        # mail validation, immutable-byte and local rendering checks. Its output
        # is discarded, not treated as an approval or repository authorization.
        build_offline_preview(draft, _VALIDATION_CONTEXT)
        attachments = tuple((a.filename, a.content) for a in draft.attachments)
        size = (len(draft.body) + sum(len(content) for _, content in attachments)
                + sum(len(v.encode("utf-8")) for v in text)
                + sum(len(v.encode("utf-8")) for g in groups for v in g)
                + sum(len(name.encode("utf-8")) for name, _ in attachments))
    except (MailPreviewError, ValueError, TypeError, UnicodeError):
        raise DraftRepositoryError("DRAFT_REPOSITORY_DRAFT_INVALID") from None
    if size > max_bytes:
        raise DraftRepositoryError("DRAFT_REPOSITORY_MESSAGE_LIMIT")
    data = (
        draft.mailbox_id, draft.source_message_id, draft.source_message_version,
        draft.from_identity, draft.to, draft.cc, draft.bcc, draft.subject,
        draft.body, attachments, draft.action_type,
    )
    return data, size


def _snapshot(key: tuple[str, str, str], owner: str, version: int, data: tuple) -> DraftSnapshot:
    attachments = tuple(MailAttachment(name, content) for name, content in data[9])
    draft = MailDraft(*data[:9], attachments, data[10])
    return DraftSnapshot(key[0], owner, key[1], key[2], str(version), draft)


class InMemoryDraftRepository:
    """No persistence or global registry; scope is one local Python instance."""

    def __init__(
        self, *, max_drafts: int = MAX_DRAFTS,
        max_message_bytes: int = MAX_MESSAGE_BYTES, max_total_bytes: int = MAX_TOTAL_BYTES,
    ):
        for value, upper in (
            (max_drafts, MAX_DRAFTS), (max_message_bytes, MAX_MESSAGE_BYTES),
            (max_total_bytes, MAX_TOTAL_BYTES),
        ):
            if type(value) is not int or not 1 <= value <= upper:
                raise DraftRepositoryError("DRAFT_REPOSITORY_LIMIT_INVALID")
        self._max_drafts = max_drafts
        self._max_message_bytes = max_message_bytes
        self._max_total_bytes = max_total_bytes
        self._entries: dict[tuple[str, str, str], _Entry] = {}
        self._total_bytes = 0
        self._lock = RLock()

    def create(
        self, *, tenant: str, owner: str, mailbox_id: str, draft_id: str, draft: MailDraft,
    ) -> DraftSnapshot:
        key = (_label(tenant), _label(mailbox_id), _label(draft_id))
        owner = _label(owner)
        data, size = _freeze(draft, self._max_message_bytes)
        if data[0] != mailbox_id:
            raise DraftRepositoryError("DRAFT_REPOSITORY_MISMATCH")
        with self._lock:
            if key in self._entries:
                raise DraftRepositoryError("DRAFT_REPOSITORY_MISMATCH")
            if (len(self._entries) >= self._max_drafts
                    or self._total_bytes + size > self._max_total_bytes):
                raise DraftRepositoryError("DRAFT_REPOSITORY_CAPACITY")
            result = _snapshot(key, owner, 1, data)
            self._entries[key] = _Entry(owner, 1, data, size, result)
            self._total_bytes += size
            return result

    def _current(self, tenant, owner, mailbox_id, draft_id, version) -> tuple[tuple, _Entry]:
        # Caller holds _lock. Every public resolve/CAS requires all five labels.
        key = (_label(tenant), _label(mailbox_id), _label(draft_id))
        owner, version = _label(owner), _version(version)
        entry = self._entries.get(key)
        if entry is None or entry.owner != owner or str(entry.version) != version:
            raise DraftRepositoryError("DRAFT_REPOSITORY_MISMATCH")
        current = entry.snapshot
        if type(current) is not DraftSnapshot:
            raise DraftRepositoryError("DRAFT_REPOSITORY_SNAPSHOT_INVALID")
        labels = (current.tenant, current.owner, current.mailbox_id,
                  current.draft_id, current.version)
        if (any(type(v) is not str for v in labels)
                or labels != (tenant, owner, mailbox_id, draft_id, version)):
            raise DraftRepositoryError("DRAFT_REPOSITORY_SNAPSHOT_INVALID")
        data, _ = _freeze(current.draft, self._max_message_bytes)
        if data != entry.data:
            raise DraftRepositoryError("DRAFT_REPOSITORY_SNAPSHOT_INVALID")
        return key, entry

    def resolve(
        self, *, tenant: str, owner: str, mailbox_id: str, draft_id: str, version: str,
    ) -> DraftSnapshot:
        with self._lock:
            _, entry = self._current(tenant, owner, mailbox_id, draft_id, version)
            return entry.snapshot

    def require_current(
        self, snapshot: DraftSnapshot, *,
        tenant: str, owner: str, mailbox_id: str, draft_id: str, version: str,
    ) -> DraftSnapshot:
        with self._lock:
            _, entry = self._current(tenant, owner, mailbox_id, draft_id, version)
            if type(snapshot) is not DraftSnapshot or snapshot is not entry.snapshot:
                raise DraftRepositoryError("DRAFT_REPOSITORY_SNAPSHOT_INVALID")
            return entry.snapshot

    def render_current(
        self, snapshot: DraftSnapshot, *, tenant: str, owner: str, mailbox_id: str,
        draft_id: str, version: str, context: PreviewContext,
    ) -> RenderedDraft:
        """Linearize exact currentness through completed rendering in this instance.

        Uses only the fixed existing builder/renderer, never a caller callback.
        CAS cannot commit between validation and rendering completion. The lock
        ends before later disclosure: the result may already be stale when used.
        Labels/context are comparison data, not authenticated identity/authority.
        No repository state changes, including when rendering fails.
        """
        with self._lock:
            key, entry = self._current(tenant, owner, mailbox_id, draft_id, version)
            if type(snapshot) is not DraftSnapshot or snapshot is not entry.snapshot:
                raise DraftRepositoryError("DRAFT_REPOSITORY_SNAPSHOT_INVALID")
            if type(context) is not PreviewContext:
                raise DraftRepositoryError("DRAFT_REPOSITORY_CONTEXT_INVALID")
            values = (
                context.action_id, context.actor, context.agent,
                context.tenant, context.policy_version,
            )
            if any(type(value) is not str for value in values):
                raise DraftRepositoryError("DRAFT_REPOSITORY_CONTEXT_INVALID")
            if context.tenant != tenant:
                raise DraftRepositoryError("DRAFT_REPOSITORY_MISMATCH")
            # Detached builtin-only copies avoid rendering caller-owned objects.
            # Original preview validation still checks every context field.
            checked_context = PreviewContext(*values)
            draft = _snapshot(key, entry.owner, entry.version, entry.data).draft
            try:
                preview = build_offline_preview(draft, checked_context)
                document = render_offline_preview(
                    preview, draft=draft, context=checked_context,
                )
                if type(document) is not str or len(document.encode("utf-8")) > MAX_RENDERED_HTML_BYTES:
                    raise ValueError
                return RenderedDraft(
                    DraftRenderBinding(
                        tenant, owner, mailbox_id, draft_id, version,
                        preview.continuity_digest,
                    ),
                    document,
                )
            except Exception:
                # Suppress renderer/parser inputs and exception chains in diagnostics.
                raise DraftRepositoryError("DRAFT_REPOSITORY_RENDER_FAILED") from None

    def compare_and_swap(
        self, snapshot: DraftSnapshot, *, tenant: str, owner: str, mailbox_id: str,
        draft_id: str, version: str, draft: MailDraft,
    ) -> DraftSnapshot:
        with self._lock:
            key, entry = self._current(tenant, owner, mailbox_id, draft_id, version)
            if type(snapshot) is not DraftSnapshot or snapshot is not entry.snapshot:
                raise DraftRepositoryError("DRAFT_REPOSITORY_SNAPSHOT_INVALID")
            data, size = _freeze(draft, self._max_message_bytes)
            if data[0] != mailbox_id:
                raise DraftRepositoryError("DRAFT_REPOSITORY_MISMATCH")
            if entry.version >= MAX_VERSION:
                raise DraftRepositoryError("DRAFT_REPOSITORY_VERSION_LIMIT")
            if self._total_bytes - entry.size + size > self._max_total_bytes:
                raise DraftRepositoryError("DRAFT_REPOSITORY_CAPACITY")
            version_number = entry.version + 1
            result = _snapshot(key, entry.owner, version_number, data)
            self._entries[key] = _Entry(entry.owner, version_number, data, size, result)
            self._total_bytes += size - entry.size
            return result
