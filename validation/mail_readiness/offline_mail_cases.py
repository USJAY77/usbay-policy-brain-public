"""Fixed stdlib-only synthetic cases. Import only after native isolation gates."""
from dataclasses import replace
import queue
import threading
import unittest

from governance.mail_draft_preview import (
    MailPreviewError, PreviewContext, build_offline_preview, render_offline_preview,
)
from governance.mail_draft_repository import DraftRepositoryError, InMemoryDraftRepository
from governance.mail_draft_review import MailAttachment, MailDraft
from governance.mail_preview_access_proposal import (
    HypotheticalSourceRecord, SOURCE_KINDS, analyze_hypothetical_sources, propose_binding,
)
from offline_mail_contract import CASE_NAMES, SCHEMA


class OfflineMailCases(unittest.TestCase):
    def setUp(self):
        self.context = PreviewContext('synthetic-action', 'synthetic-owner', 'synthetic-agent', 'synthetic-tenant', 'synthetic-policy')
        self.draft = MailDraft('synthetic-mailbox', 'synthetic-message', '1',
                               'sender@example.invalid', ('recipient@example.invalid',), (),
                               ('private-copy@example.invalid',), 'Synthetic subject',
                               b'Synthetic message', (MailAttachment('synthetic.txt', b'synthetic attachment'),))
        self.repository = InMemoryDraftRepository()
        self.labels = dict(tenant=self.context.tenant, owner=self.context.actor,
                           mailbox_id=self.draft.mailbox_id, draft_id='synthetic-draft')
        self.snapshot = self.repository.create(**self.labels, draft=self.draft)
        self.current = self.labels | {'version': '1'}

    def preview(self):
        return build_offline_preview(self.draft, self.context)

    def render(self, preview=None, draft=None, context=None):
        return render_offline_preview(preview or self.preview(), draft=draft or self.draft,
                                      context=context or self.context)

    def records(self):
        expected = propose_binding(self.preview(), draft=self.draft, context=self.context,
                                   draft_id='synthetic-draft', draft_version='1')
        records = tuple(HypotheticalSourceRecord(kind, expected, 'synthetic-issuer',
                        'synthetic-evidence', 'synthetic-generation', 100, 200) for kind in SOURCE_KINDS)
        return expected, records

    def test_preview_is_not_authority(self):
        preview = self.preview()
        self.assertIs(preview.send_available, False)
        self.assertIs(preview.execution_authorized, False)

    def test_no_constructor_authority_override(self):
        with self.assertRaises(ValueError):
            replace(self.preview(), execution_authorized=True)

    def test_bcc_not_disclosed(self):
        preview = self.preview()
        self.assertNotIn(b'private-copy@example.invalid', preview.mime_bytes)
        self.assertNotIn('private-copy@example.invalid', self.render(preview))

    def test_html_escapes_content(self):
        draft = replace(self.draft, body=b'<script>synthetic()</script>')
        document = self.render(build_offline_preview(draft, self.context), draft=draft)
        self.assertNotIn('<script>', document)
        self.assertIn('&lt;script&gt;', document)

    def test_forged_preview_rejected(self):
        with self.assertRaises(MailPreviewError):
            self.render(replace(self.preview(), continuity_digest='0' * 64))

    def test_changed_content_rejected(self):
        with self.assertRaises(MailPreviewError):
            self.render(self.preview(), draft=replace(self.draft, body=b'changed synthetic message'))

    def test_changed_tenant_rejected(self):
        with self.assertRaises(MailPreviewError):
            self.render(self.preview(), context=replace(self.context, tenant='different-tenant'))

    def test_duplicate_recipient_rejected(self):
        with self.assertRaises(MailPreviewError):
            build_offline_preview(replace(self.draft, cc=self.draft.to), self.context)

    def test_header_injection_rejected(self):
        with self.assertRaises(MailPreviewError):
            build_offline_preview(replace(self.draft, subject='Synthetic\r\nX-Injected: denied'), self.context)

    def test_repository_cross_tenant_rejected(self):
        with self.assertRaises(DraftRepositoryError):
            self.repository.resolve(**(self.current | {'tenant': 'different-tenant'}))

    def test_repository_cross_owner_rejected(self):
        with self.assertRaises(DraftRepositoryError):
            self.repository.resolve(**(self.current | {'owner': 'different-owner'}))

    def test_stale_snapshot_rejected(self):
        self.repository.compare_and_swap(self.snapshot, **self.current, draft=replace(self.draft, subject='Next synthetic version'))
        with self.assertRaises(DraftRepositoryError):
            self.repository.require_current(self.snapshot, **self.current)

    def test_copied_snapshot_rejected(self):
        with self.assertRaises(DraftRepositoryError):
            self.repository.require_current(replace(self.snapshot), **self.current)

    def test_tampered_snapshot_rejected(self):
        object.__setattr__(self.snapshot, 'draft', replace(self.draft, body=b'changed synthetic message'))
        with self.assertRaises(DraftRepositoryError):
            self.repository.resolve(**self.current)

    def test_render_tenant_mismatch_rejected(self):
        with self.assertRaises(DraftRepositoryError):
            self.repository.render_current(self.snapshot, **self.current,
                                           context=replace(self.context, tenant='different-tenant'))

    def test_concurrent_cas_has_one_winner(self):
        barrier = threading.Barrier(2, timeout=2)
        results = queue.SimpleQueue()

        def consume():
            try:
                barrier.wait()
                self.repository.compare_and_swap(self.snapshot, **self.current, draft=self.draft)
                results.put('won')
            except DraftRepositoryError:
                results.put('rejected')
            except BaseException:
                results.put('error')

        workers = [threading.Thread(target=consume, daemon=True) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=3)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(sorted(results.get_nowait() for _ in range(2)), ['rejected', 'won'])

    def test_complete_hypothesis_never_grants(self):
        expected, records = self.records()
        result = analyze_hypothetical_sources(expected, records, now=110, max_age_seconds=20)
        self.assertIs(result.access_authorized, False)
        self.assertIs(result.execution_authorized, False)
        self.assertIn('INDEPENDENT_VERIFIERS_NOT_CONNECTED', result.blockers)

    def test_stale_hypothesis_stays_blocked(self):
        expected, records = self.records()
        result = analyze_hypothetical_sources(expected, records, now=150, max_age_seconds=20)
        self.assertIs(result.access_authorized, False)
        self.assertIn('IDENTITY_STALE_OR_EXPIRED', result.blockers)

    def test_missing_source_stays_blocked(self):
        expected, records = self.records()
        result = analyze_hypothetical_sources(expected, records[1:], now=110, max_age_seconds=20)
        self.assertIn('IDENTITY_SOURCE_MISSING', result.blockers)

    def test_mime_is_deterministic(self):
        self.assertEqual(self.preview().mime_bytes, self.preview().mime_bytes)


class BoundedResult(unittest.TestResult):
    """Retain only fixed case names and outcomes; never format exception data."""
    def __init__(self):
        super().__init__()
        self.reports = {}

    def record(self, test, value):
        name = test._testMethodName
        if name not in CASE_NAMES or name in self.reports:
            raise RuntimeError('OFFLINE_MAIL_RESULT_INVALID')
        self.reports[name] = value

    def addSuccess(self, test):
        self.record(test, 'passed')

    def addError(self, test, error):
        self.record(test, 'error')

    def addFailure(self, test, error):
        self.record(test, 'failed')

    def addSkip(self, test, reason):
        self.record(test, 'skipped')

    def addExpectedFailure(self, test, error):
        self.record(test, 'failed')

    def addUnexpectedSuccess(self, test):
        self.record(test, 'failed')


def run(source_binding):
    suite = unittest.TestSuite(OfflineMailCases(name) for name in CASE_NAMES)
    result = BoundedResult()
    suite.run(result)
    return {'schema': SCHEMA, 'source_binding': source_binding,
            'reports': result.reports, 'tests_run': result.testsRun,
            'execution_authorized': False}
