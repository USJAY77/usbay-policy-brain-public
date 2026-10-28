"""Synthetic envelope cases: no real messages, providers, addresses or sends."""
from dataclasses import replace, asdict
import json
import unittest
import pytest

from governance.mail_draft_review import MailAttachment, MailDraft, bind_mail_draft
from governance.product_dry_run import DryRunGrant, ProductDryRun

pytestmark = pytest.mark.governance


class MailDraftReviewTests(unittest.TestCase):
    def setUp(self):
        self.context = dict(action_id="mail-fixture", actor="synthetic-actor",
                            agent="Governance Agent", tenant="tenant-a",
                            policy_version="synthetic-policy-v1")
        self.draft = MailDraft("synthetic-mailbox", "source-1", "modseq-1",
            "sender@example.invalid", ("to@example.invalid",),
            ("cc@example.invalid",), ("bcc@example.invalid",),
            "Synthetic subject", b"Synthetic body\r\n", (
                MailAttachment("one.txt", b"one"), MailAttachment("two.txt", b"two")))

    def bind(self, draft=None, **changes):
        return bind_mail_draft(draft or self.draft, **{**self.context, **changes})

    def test_offline_request_has_no_raw_mail_or_execution_capability(self):
        request = self.bind()
        self.assertEqual(request.capability, "governance_review")
        self.assertTrue(request.dry_run)
        serialized = json.dumps(asdict(request))
        for raw in (self.draft.subject, self.draft.mailbox_id, "example.invalid", "one.txt", "Synthetic body"):
            self.assertNotIn(raw, serialized)
        self.assertNotIn("Synthetic", repr(self.draft))

    def test_content_and_target_mutations_change_binding(self):
        changes = {
            "mailbox_id": "other-mailbox", "source_message_id": "other-source",
            "source_message_version": "modseq-2", "from_identity": "other@example.invalid",
            "to": ("other@example.invalid",), "cc": (), "bcc": (),
            "subject": self.draft.subject + " ", "body": b"Synthetic body\n",
            "attachments": (MailAttachment("one.txt", b"ONE"), self.draft.attachments[1]),
        }
        original = self.bind().binding
        for key, value in changes.items():
            with self.subTest(field=key):
                self.assertNotEqual(original, self.bind(replace(self.draft, **{key: value})).binding)

    def test_filename_order_and_attachment_count_are_bound(self):
        for attachments in (
            (MailAttachment("renamed.txt", b"one"), self.draft.attachments[1]),
            tuple(reversed(self.draft.attachments)), self.draft.attachments[:1], (),
        ):
            with self.subTest(attachments=repr(attachments)):
                self.assertNotEqual(self.bind().binding, self.bind(replace(self.draft, attachments=attachments)).binding)

    def test_to_cc_bcc_are_separate_roles(self):
        changed = replace(self.draft, to=self.draft.bcc, bcc=self.draft.to)
        self.assertNotEqual(self.bind().binding, self.bind(changed).binding)

    def test_contract_v1_address_case_space_and_order_normalization(self):
        left = replace(self.draft, to=(" Z@EXAMPLE.INVALID ", "a@example.invalid"))
        right = replace(self.draft, to=("a@example.invalid", "z@example.invalid"))
        self.assertEqual(self.bind(left).binding, self.bind(right).binding)

    def test_ambiguous_or_header_injected_addresses_block(self):
        for address in ("Name <to@example.invalid>", "to@example.invalid\r\nBcc:x@y.invalid",
                        "a@@b.invalid", "é@example.invalid", "a..b@example.invalid", "a@localhost", "a@-bad.invalid"):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    self.bind(replace(self.draft, to=(address,)))

    def test_duplicate_recipients_across_or_within_roles_block(self):
        for draft in (replace(self.draft, to=("to@example.invalid", "TO@example.invalid")),
                      replace(self.draft, bcc=self.draft.to)):
            with self.assertRaises(ValueError):
                self.bind(draft)

    def test_required_source_and_context_are_not_inferred(self):
        for field in ("mailbox_id", "source_message_id", "source_message_version"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.bind(replace(self.draft, **{field: ""}))
        for field in self.context:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.bind(**{field: ""})

    def test_whitespace_only_required_identifiers_are_rejected(self):
        fields = {
            "mailbox_id": "MAILBOX_REQUIRED",
            "source_message_id": "SOURCE_MESSAGE_REQUIRED",
            "source_message_version": "SOURCE_VERSION_REQUIRED",
        }
        for field, code in fields.items():
            for value in (" ", "\t", " \t ", "\u00a0", "\u2003"):
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaisesRegex(ValueError, f"^{code}$"):
                        self.bind(replace(self.draft, **{field: value}))

    def test_required_identifier_whitespace_is_preserved_in_binding(self):
        original = self.bind()
        for field in ("mailbox_id", "source_message_id", "source_message_version"):
            value = getattr(self.draft, field)
            for padded in (f" {value}", f"{value}\t", f"\u2003{value}\u00a0"):
                with self.subTest(field=field, value=repr(padded)):
                    request = self.bind(replace(self.draft, **{field: padded}))
                    self.assertNotEqual(original.target_hash, request.target_hash)
                    self.assertNotEqual(original.binding, request.binding)

    def test_subject_and_filename_whitespace_is_bound_exactly(self):
        draft = replace(self.draft, subject=" ",
                        attachments=(MailAttachment(" ", b"one"),))
        original = self.bind(draft)
        changes = {
            "subject": "  ",
            "attachments": (MailAttachment("  ", b"one"),),
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                request = self.bind(replace(draft, **{field: value}))
                self.assertEqual(original.target_hash, request.target_hash)
                self.assertNotEqual(original.payload_hash, request.payload_hash)

    def test_live_or_other_atomic_actions_are_rejected(self):
        for action in ("send", "move", "delete", "flag", "send_then_move"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.bind(replace(self.draft, action_type=action))

    def test_mutable_content_and_recipient_lists_are_rejected(self):
        for draft in (replace(self.draft, body=bytearray(b"mutable")),
                      replace(self.draft, to=["to@example.invalid"]),
                      replace(self.draft, attachments=[self.draft.attachments[0]]),
                      replace(self.draft, attachments=(MailAttachment("one.txt", bytearray(b"mutable")),))):
            with self.assertRaises(ValueError):
                self.bind(draft)

    def test_header_injection_in_subject_and_filename_blocks(self):
        for draft in (replace(self.draft, subject="x\r\nBcc:other@example.invalid"),
                      replace(self.draft, attachments=(MailAttachment("x\r\ny", b"a"),))):
            with self.assertRaises(ValueError):
                self.bind(draft)

    def test_b1_review_cannot_be_reused_after_mail_mutation(self):
        from tests.test_product_dry_run import ProductDryRunTests
        fixture = ProductDryRunTests(); fixture.setUp()
        request = self.bind()
        grant = replace(fixture.grant, request_binding=request.binding)
        events = []
        def audit(event):
            from governance.connector_framework import sha256_payload
            events.append(event)
            return {"decision": "PASS", "audit_hash": sha256_payload(event)}
        boundary = ProductDryRun(registry=fixture.registry,
            tenant_bindings={request.actor: (request.tenant,), request.agent: (request.tenant,)},
            policy_version=request.policy_version, grants={request.binding: grant},
            audit=audit, clock=lambda: fixture.now)
        result = boundary.prepare(request)
        self.assertEqual(result["decision"], "PREPARED_DRY_RUN")
        self.assertFalse(result["execution_authorized"])
        changed = self.bind(replace(self.draft, bcc=("changed@example.invalid",)))
        rejected = boundary.prepare(changed)
        self.assertEqual(rejected["decision"], "BLOCKED")
        self.assertIn("SCOPED_REVIEW_MISSING_OR_INVALID", rejected["blockers"])
        self.assertNotIn("example.invalid", json.dumps(events))


if __name__ == "__main__":
    unittest.main()
