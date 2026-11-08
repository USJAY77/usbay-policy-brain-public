"""Synthetic role keys live in memory only; no authority adoption or writer.

Run directly with unittest; pytest can also collect these unittest cases.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.release_owner_contract import (
    DOMAIN, PROFILE, ReleaseIdentity, ReleaseTrustContext,
    inspect_release_owner_contract,
)
from security.runtime_artifact_provenance import canonical_bytes, public_key_id
from security.runtime_artifact_provenance import ProducerTrust, RuntimeArtifactError

NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)
START = "2026-11-07T11:59:00Z"
END = "2026-11-07T12:01:00Z"


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def mark(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class ReleaseOwnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Only synthetic private keys; never serialize or persist them.
        cls.private = {role: Ed25519PrivateKey.generate() for role in ("root", "issuer", "owner", "status")}
        cls.identities = {}
        for role, private in cls.private.items():
            public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            cls.identities[role] = ReleaseIdentity(
                "synthetic-" + role, public_key_id(public), public, role, "synthetic-tenant",
                "synthetic-target", "2026-11-07T11:00:00Z", "2026-11-07T13:00:00Z", mark(role))

    def chain(self, mutate=None):
        records, payloads, envelopes = {}, {}, {}
        scope = dict(tenant_id="synthetic-tenant", actor_id="synthetic-actor", purpose="release_provenance",
            environment="non-production", target_id="synthetic-target", tool_id="synthetic-tool",
            resource_type="GOVERNANCE_RELEASE", resource_id="synthetic-release",
            source_commit="1" * 40, source_tree="2" * 40,
            policy_bundle_hash=mark("bundle"), release_core_hash=mark("core"), predecessor_hash=mark("previous"))

        def add(kind, role, extra):
            payload = dict(schema="usbay.release_owner." + kind + ".v1", domain=DOMAIN,
                record_id="synthetic-" + kind, issued_at=START, valid_from=START, valid_until=END, **extra)
            if kind == "status":
                payload["issued_at"] = "2026-11-07T11:59:59Z"
            if mutate:
                mutate(kind, payload)
            signature = self.private[role].sign(canonical_bytes(payload))
            envelope = dict(payload=payload, key_id=self.identities[role].key_id,
                            signature=base64.b64encode(signature).decode("ascii"))
            envelopes[kind] = envelope
            payloads[kind] = payload
            records[kind] = canonical_bytes(envelope)
            return digest(envelope)

        root_hash = add("root", "root", dict(scope=dict(scope), issuer_id="synthetic-issuer",
            issuer_key_id=self.identities["issuer"].key_id, owner_id="synthetic-owner",
            owner_key_id=self.identities["owner"].key_id, status_key_id=self.identities["status"].key_id,
            review_profile=PROFILE, review_threshold=1, role_policy="DISTINCT_ROLE_KEYS_V1",
            max_issuances=1, redelegation_allowed=False))
        issuer_hash = add("issuer", "root", dict(scope=dict(scope), root_hash=root_hash,
            subject_id="synthetic-issuer", subject_key_id=self.identities["issuer"].key_id,
            max_issuances=1, redelegation_allowed=False))
        policy_hash = add("policy", "root", dict(root_hash=root_hash, owner_id="synthetic-owner",
            owner_key_id=self.identities["owner"].key_id, profile=PROFILE, threshold=1,
            role_policy="DISTINCT_ROLE_KEYS_V1"))
        request_hash = add("request", "issuer", dict(scope=dict(scope), root_hash=root_hash,
            issuer_grant_hash=issuer_hash, review_policy_hash=policy_hash, issuer_id="synthetic-issuer",
            action="ISSUE_RELEASE_MANIFEST", nonce="synthetic-once-only-request"))
        review_hash = add("review", "owner", dict(request_hash=request_hash,
            review_policy_hash=policy_hash, owner_id="synthetic-owner", decision="APPROVE"))
        status_hash = add("status", "status", dict(root_hash=root_hash, issuer_grant_hash=issuer_hash,
            review_policy_hash=policy_hash, request_hash=request_hash, review_hash=review_hash,
            challenge="synthetic-challenge", epoch="synthetic-epoch", sequence=7, head_hash=mark("head"),
            revocation_reference=mark("revocation"), root_state="ACTIVE", issuer_state="ACTIVE",
            policy_state="ACTIVE", owner_state="ACTIVE", issuance_state="AVAILABLE"))
        trust = ReleaseTrustContext(tuple(self.identities.values()), self.identities["root"].key_id,
            root_hash, issuer_hash, policy_hash, "synthetic-tenant", "synthetic-target", status_hash,
            "synthetic-challenge", "synthetic-epoch", 7, mark("head"), mark("revocation"), 30)
        return records, trust

    def inspect(self, records, trust, now=NOW):
        result = inspect_release_owner_contract(records, trust=trust, now=now)
        self.assertEqual(result.decision, "DENY")
        self.assertFalse(result.issuance_authorized)
        self.assertFalse(result.consumption_confirmed)
        return result

    def test_complete_chain_has_evidence_but_no_writer_authority(self):
        result = self.inspect(*self.chain())
        self.assertTrue(result.bindings_valid)
        self.assertEqual(result.reason, "RELEASE_WRITER_UNAVAILABLE")
        self.assertEqual(result.verification_valid_until, "2026-11-07T12:00:29Z")

    def test_no_default_trust(self):
        records, _ = self.chain()
        self.assertEqual(self.inspect(records, None).reason, "RELEASE_AUTHORITY_UNAVAILABLE")

    def test_no_default_clock(self):
        self.assertEqual(self.inspect(*self.chain(), now=None).reason, "CLOCK_INVALID")

    def test_naive_clock_denied(self):
        self.assertEqual(self.inspect(*self.chain(), now=NOW.replace(tzinfo=None)).reason, "CLOCK_INVALID")

    def test_no_clock_fallback_from_environment(self):
        with patch.dict("os.environ", {"USBAY_ENV": "test", "RUNTIME_ENVIRONMENT": "staging"}):
            self.assertEqual(self.inspect(*self.chain(), now=None).reason, "CLOCK_INVALID")

    def test_duplicate_identity_denied(self):
        records, trust = self.chain()
        result = self.inspect(records, replace(trust, identities=trust.identities + trust.identities[:1]))
        self.assertEqual(result.reason, "AMBIGUOUS_IDENTITY")

    def test_identity_provenance_required(self):
        records, trust = self.chain()
        bad = replace(trust.identities[0], provenance_reference="unknown")
        self.assertEqual(self.inspect(records, replace(trust, identities=(bad,) + trust.identities[1:])).reason,
                         "IDENTITY_INVALID")

    def test_identity_expiry(self):
        records, trust = self.chain()
        identities = tuple(replace(k, valid_until="2026-11-07T12:00:00Z") for k in trust.identities)
        self.assertEqual(self.inspect(records, replace(trust, identities=identities)).reason, "IDENTITY_EXPIRED")

    def test_artifact_key_is_not_enrolled_release_identity(self):
        records, trust = self.chain()
        public = base64.b64decode("y/SIMxivmo5i3HPmrrOrpRTwn11Bw6SZ8l90Nf+ZtAw=")
        payload = json.loads(records["request"])
        payload["key_id"] = public_key_id(public)
        records["request"] = canonical_bytes(payload)
        self.assertEqual(self.inspect(records, trust).reason, "SIGNER_INVALID")

    def test_no_io_during_inspection(self):
        records, trust = self.chain()
        with patch("builtins.open", side_effect=AssertionError("file access")), \
             patch("socket.socket", side_effect=AssertionError("network access")):
            self.assertTrue(self.inspect(records, trust).bindings_valid)

    def test_parallel_inspection_cannot_consume_or_authorize(self):
        records, trust = self.chain()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: inspect_release_owner_contract(records, trust=trust, now=NOW), range(24)))
        self.assertTrue(all(r.bindings_valid and r.decision == "DENY" and not r.issuance_authorized
                            and not r.consumption_confirmed for r in results))
        # This proves no ALLOW from this inspector, not durable writer concurrency.

    def test_status_deadline_expires_at_exact_boundary(self):
        self.assertEqual(self.inspect(*self.chain(), now=NOW + timedelta(seconds=29)).reason, "STATUS_STALE")

    def test_unsigned_signature_corruption_is_bounded(self):
        records, trust = self.chain()
        env = json.loads(records["review"])
        env["signature"] = base64.b64encode(bytes(64)).decode()
        records["review"] = canonical_bytes(env)
        result = self.inspect(records, trust)
        self.assertFalse(result.bindings_valid)
        self.assertNotIn("synthetic-owner", result.reason)
        self.assertEqual(result.reason, "SIGNATURE_INVALID")

    def test_identity_role_is_not_a_caller_label(self):
        records, trust = self.chain()
        identities = tuple(replace(k, role="owner") if k.role == "issuer" else k for k in trust.identities)
        self.assertEqual(self.inspect(records, replace(trust, identities=identities)).reason, "ROLE_MISMATCH")

    def test_test_producer_remains_denied_in_production(self):
        identity = self.identities["issuer"]
        with self.assertRaisesRegex(RuntimeArtifactError, "runtime_artifact_test_producer_denied"):
            ProducerTrust(identity.public_key, identity.key_id, "test", "production").validate()

    def test_artifact_producer_fingerprint_contract_is_unchanged(self):
        public = base64.b64decode("y/SIMxivmo5i3HPmrrOrpRTwn11Bw6SZ8l90Nf+ZtAw=")
        self.assertEqual(public_key_id(public),
            "sha256:d7ef066bfc0513e8dcb58324830d5ab0213bfbaf10e13cbe9165bbe6f442cbbf")

    def test_artifact_fingerprint_mismatch_still_denied(self):
        identity = self.identities["issuer"]
        with self.assertRaisesRegex(RuntimeArtifactError, "runtime_artifact_producer_key_id_mismatch"):
            ProducerTrust(identity.public_key, mark("wrong"), "test", "test").validate()

    def test_status_cannot_predate_the_review_it_attests(self):
        def mutate(kind, payload):
            if kind == "review":
                payload["issued_at"] = "2026-11-07T12:00:00Z"
        self.assertEqual(self.inspect(*self.chain(mutate)).reason, "VALIDITY_BROADENING")

    def test_request_cannot_predate_its_review_policy(self):
        def mutate(kind, payload):
            if kind == "policy":
                payload["issued_at"] = "2026-11-07T11:59:30Z"
        self.assertEqual(self.inspect(*self.chain(mutate)).reason, "VALIDITY_BROADENING")

    def test_request_interval_cannot_outlive_its_review_policy(self):
        def mutate(kind, payload):
            if kind == "policy":
                payload["valid_until"] = "2026-11-07T12:00:30Z"
        self.assertEqual(self.inspect(*self.chain(mutate)).reason, "VALIDITY_BROADENING")

    def test_status_interval_cannot_outlive_its_owner_review(self):
        def mutate(kind, payload):
            if kind == "review":
                payload["valid_until"] = "2026-11-07T12:00:30Z"
        self.assertEqual(self.inspect(*self.chain(mutate)).reason, "VALIDITY_BROADENING")


def mutation_case(kind, field, value, reason):
    def case(self):
        def mutate(record_kind, payload):
            if record_kind == kind:
                payload[field] = value
        result = self.inspect(*self.chain(mutate))
        self.assertFalse(result.bindings_valid)
        self.assertEqual(result.reason, reason)
    return case


CASES = [
    ("root", "review_threshold", 2, "ROOT_REVIEW_POLICY_DENIED"),
    ("root", "review_threshold", True, "ROOT_REVIEW_POLICY_DENIED"),
    ("root", "review_profile", "production", "ROOT_REVIEW_POLICY_DENIED"),
    ("root", "role_policy", "IMPLICIT_ROLE_REUSE", "ROOT_REVIEW_POLICY_DENIED"),
    ("root", "max_issuances", 2, "ROOT_SCOPE_DENIED"),
    ("root", "redelegation_allowed", True, "ROOT_SCOPE_DENIED"),
    ("issuer", "max_issuances", True, "ISSUER_SCOPE_DENIED"),
    ("issuer", "redelegation_allowed", True, "ISSUER_SCOPE_DENIED"),
    ("issuer", "root_hash", mark("wrong-parent"), "PARENT_BINDING_INVALID"),
    ("issuer", "subject_id", "other", "ISSUER_BINDING_INVALID"),
    ("policy", "threshold", 2, "REVIEW_POLICY_DOWNGRADE"),
    ("policy", "threshold", True, "REVIEW_POLICY_DOWNGRADE"),
    ("policy", "profile", "v1-fallback", "REVIEW_POLICY_DOWNGRADE"),
    ("policy", "owner_id", "other", "OWNER_BINDING_INVALID"),
    ("request", "action", "DEPLOY", "REQUEST_ACTION_INVALID"),
    ("request", "issuer_id", "other", "REQUEST_ACTION_INVALID"),
    ("request", "nonce", "*", "REQUEST_ACTION_INVALID"),
    ("request", "root_hash", mark("other"), "REQUEST_CHAIN_MISMATCH"),
    ("request", "issuer_grant_hash", mark("other"), "REQUEST_CHAIN_MISMATCH"),
    ("request", "review_policy_hash", mark("other"), "REQUEST_CHAIN_MISMATCH"),
    ("review", "decision", "DENY", "OWNER_REVIEW_INVALID"),
    ("review", "request_hash", mark("other"), "OWNER_REVIEW_INVALID"),
    ("review", "owner_id", "other", "OWNER_REVIEW_INVALID"),
    ("status", "challenge", "other", "CURRENTNESS_BINDING_INVALID"),
    ("status", "epoch", "previous", "CURRENTNESS_BINDING_INVALID"),
    ("status", "sequence", 6, "CURRENTNESS_BINDING_INVALID"),
    ("status", "sequence", True, "CURRENTNESS_BINDING_INVALID"),
    ("status", "head_hash", mark("old-head"), "CURRENTNESS_BINDING_INVALID"),
    ("status", "revocation_reference", mark("old-revocations"), "CURRENTNESS_BINDING_INVALID"),
    ("status", "request_hash", mark("other-request"), "CURRENTNESS_BINDING_INVALID"),
    ("status", "review_hash", mark("other-review"), "CURRENTNESS_BINDING_INVALID"),
    ("status", "issuance_state", "CONSUMED", "ISSUANCE_REPLAY"),
    ("status", "issuance_state", "UNKNOWN", "ISSUANCE_REPLAY"),
    ("status", "root_state", "REVOKED", "AUTHORITY_REVOKED"),
    ("status", "issuer_state", "REVOKED", "AUTHORITY_REVOKED"),
    ("status", "policy_state", "REVOKED", "AUTHORITY_REVOKED"),
    ("status", "owner_state", "REVOKED", "AUTHORITY_REVOKED"),
    ("status", "issued_at", "2026-11-07T11:59:29Z", "STATUS_STALE"),
    ("status", "issued_at", "2026-11-07T12:00:01Z", "RECORD_EXPIRED"),
    ("request", "valid_until", "2026-11-07T12:00:00Z", "RECORD_EXPIRED"),
    ("issuer", "valid_until", "2026-11-07T12:02:00Z", "VALIDITY_BROADENING"),
    ("request", "valid_from", "2026-11-07T11:58:00Z", "VALIDITY_BROADENING"),
]
for index, args in enumerate(CASES):
    setattr(ReleaseOwnerContractTests, "test_signed_mutation_%02d_%s_%s" % (index, args[0], args[1]), mutation_case(*args))


def scope_case(kind, field, value, reason):
    def case(self):
        def mutate(k, payload):
            if k == kind:
                if value is None:
                    del payload["scope"][field]
                else:
                    payload["scope"][field] = value
        self.assertEqual(self.inspect(*self.chain(mutate)).reason, reason)
    return case


for field in ("tenant_id", "actor_id", "target_id", "tool_id", "resource_id", "source_commit", "source_tree",
              "policy_bundle_hash", "release_core_hash", "predecessor_hash"):
    value = "f" * 40 if field in ("source_commit", "source_tree") else mark("substitution") if field.endswith("hash") else "other"
    setattr(ReleaseOwnerContractTests, "test_request_scope_" + field,
            scope_case("request", field, value, "REQUEST_SCOPE_MISMATCH"))
    setattr(ReleaseOwnerContractTests, "test_missing_scope_" + field,
            scope_case("request", field, None, "SCOPE_INVALID"))
for env in ("production", "staging", "test"):
    setattr(ReleaseOwnerContractTests, "test_caller_environment_" + env,
            scope_case("request", "environment", env, "ENVIRONMENT_DENIED"))


def raw_case(kind, transform, reason):
    def case(self):
        records, trust = self.chain()
        records[kind] = transform(records[kind])
        result = self.inspect(records, trust)
        self.assertFalse(result.bindings_valid)
        self.assertEqual(result.reason, reason)
    return case


for kind in ("root", "issuer", "policy", "request", "review", "status"):
    def extra(raw):
        obj = json.loads(raw)
        obj["payload"]["unexpected"] = True
        return canonical_bytes(obj)
    setattr(ReleaseOwnerContractTests, "test_unknown_field_" + kind, raw_case(kind, extra, "SCHEMA_INVALID"))
    setattr(ReleaseOwnerContractTests, "test_empty_" + kind, raw_case(kind, lambda _: b"", "ENVELOPE_INVALID"))
    setattr(ReleaseOwnerContractTests, "test_oversized_" + kind,
            raw_case(kind, lambda _: b" " * (65536 + 1), "ENVELOPE_INVALID"))
    setattr(ReleaseOwnerContractTests, "test_duplicate_" + kind,
            raw_case(kind, lambda raw: b'{"key_id":"ignored",' + raw[1:], "DUPLICATE_JSON_KEY"))
    setattr(ReleaseOwnerContractTests, "test_nonfinite_" + kind,
            raw_case(kind, lambda _: b'{"x":NaN}', "NONFINITE_JSON"))
    setattr(ReleaseOwnerContractTests, "test_domain_" + kind,
            mutation_case(kind, "domain", "USBAY_ENROLLMENT_GOVERNANCE_MUTATION", "DOMAIN_SCHEMA_MISMATCH"))


def missing_record_case(kind):
    def case(self):
        records, trust = self.chain()
        del records[kind]
        self.assertEqual(self.inspect(records, trust).reason, "CHAIN_INCOMPLETE")
    return case


for kind in ("root", "issuer", "policy", "request", "review", "status"):
    setattr(ReleaseOwnerContractTests, "test_missing_record_" + kind, missing_record_case(kind))


def pin_case(field, reason):
    def case(self):
        records, trust = self.chain()
        self.assertEqual(self.inspect(records, replace(trust, **{field: mark("wrong-pin")})).reason, reason)
    return case


for field, reason in (("root_hash", "ROOT_PIN_MISMATCH"),
                      ("issuer_grant_hash", "GRANT_POLICY_PIN_MISMATCH"),
                      ("review_policy_hash", "GRANT_POLICY_PIN_MISMATCH"),
                      ("status_hash", "STATUS_PIN_MISMATCH")):
    setattr(ReleaseOwnerContractTests, "test_independent_pin_" + field, pin_case(field, reason))


ReleaseOwnerContractTests.test_issuer_scope_broadening = scope_case(
    "issuer", "resource_id", "other-resource", "CHILD_SCOPE_BROADENING")
ReleaseOwnerContractTests.test_genesis_is_not_an_implicit_predecessor = scope_case(
    "request", "predecessor_hash", "GENESIS", "RELEASE_BINDING_INVALID")


def shared_role_key_case(self):
    def mutate(kind, payload):
        if kind == "root":
            payload["owner_key_id"] = self.identities["issuer"].key_id
    self.assertEqual(self.inspect(*self.chain(mutate)).reason, "ROLE_KEY_SEPARATION_REQUIRED")


ReleaseOwnerContractTests.test_shared_role_key_denied = shared_role_key_case


if __name__ == "__main__":
    unittest.main()
